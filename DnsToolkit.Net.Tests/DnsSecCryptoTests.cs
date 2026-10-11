#region Copyright and License
// Copyright 2026 Matheis1992
// 
// This file is part of DnsToolkit.Net - C# DNS client/server and SPF Library (https://github.com/Matheis1992/DnsToolkit.Net)
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//   http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#endregion

using System.Net;
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

/// <summary>
///   Tests the signatures and keys of the DNSSEC algorithms and the hashed owner names of NSEC3 records
/// </summary>
public class DnsSecCryptoTests
{
	private static readonly DomainName _zone = DomainName.Parse("example.test");

	/// <summary>
	///   The values of ECDSA keys and signatures have a fixed length (RFC 6605). About one of 128 values starts with a zero
	///   byte, which used to be left out, so the value was shifted and the key or the signature was invalid.
	/// </summary>
	[Theory]
	[InlineData(DnsSecAlgorithm.EcDsaP256Sha256, 32)]
	[InlineData(DnsSecAlgorithm.EcDsaP384Sha384, 48)]
	public void EcDsa_ValuesStartingWithAZeroByte_AreValid(DnsSecAlgorithm algorithm, int valueLength)
	{
		// One of 64 keys has an X or Y starting with a zero byte, so one is found after a few attempts. Without the padding
		// such a value never starts with a zero byte, as it is shifted instead.
		var key = Generate(() => DnsKeyRecord.CreateSigningKey(_zone, RecordClass.INet, 3600, DnsKeyFlags.Zone, 3, algorithm),
			k => (k.PublicKey[0] == 0) || (k.PublicKey[valueLength] == 0));
		Assert.True(key != null, "No key with a value starting with a zero byte was generated, so the values are not padded");
		Assert.True(SignAndVerify(key!), "The signature with the key, whose value starts with a zero byte, is invalid");

		// the same for r and s of the signature
		var signingKey = DnsKeyRecord.CreateSigningKey(_zone, RecordClass.INet, 3600, DnsKeyFlags.Zone, 3, algorithm);
		var records = new List<DnsRecordBase> { new ARecord(DomainName.Parse("host.example.test"), 3600, IPAddress.Parse("192.0.2.1")) };
		var signature = Generate(() => new RrSigRecord(records, signingKey, DateTime.Now.AddDays(-1), DateTime.Now.AddDays(1)),
			s => (s.Signature[0] == 0) || (s.Signature[valueLength] == 0));
		Assert.True(signature != null, "No signature with a value starting with a zero byte was generated, so the values are not padded");
		Assert.True(signature!.Verify(records, new[] { signingKey }), "The signature, whose value starts with a zero byte, is invalid");
	}

	/// <summary>
	///   Generates values until one has the given property, with the padding it fails to find one in about 1 of 10^17 runs
	/// </summary>
	private static T? Generate<T>(Func<T> generate, Func<T, bool> isWanted)
		where T : class
	{
		for (var attempt = 0; attempt < 5000; attempt++)
		{
			var value = generate();
			if (isWanted(value))
				return value;
		}

		return null;
	}

	[Theory]
	[InlineData(DnsSecAlgorithm.Ed25519)]
	[InlineData(DnsSecAlgorithm.Ed448)]
	[InlineData(DnsSecAlgorithm.RsaSha256)]
	public void Signature_IsValid(DnsSecAlgorithm algorithm)
	{
		var key = DnsKeyRecord.CreateSigningKey(_zone, RecordClass.INet, 3600, DnsKeyFlags.Zone, 3, algorithm);

		Assert.True(SignAndVerify(key));
	}

	[Fact]
	public void NSec3_CoversTheHashedNamesBetweenItsOwnerAndTheNextHashedOwner()
	{
		// The hashed names are base32hex (RFC 5155), whose order is the one of the hashes.
		// In the normal base32 alphabet, letters come before digits, so the order differs.
		var nsec3 = NSec3(owner: Hash(0x10), nextHashedOwner: Hash(0x90));

		Assert.True(nsec3.IsCovering(HashedName(Hash(0x50))));
		Assert.False(nsec3.IsCovering(HashedName(Hash(0xA0))));
		Assert.False(nsec3.IsCovering(HashedName(Hash(0x08))));
	}

	[Fact]
	public void NSec3_LastRecordOfTheZone_CoversTheNamesAfterItAndBeforeTheFirst()
	{
		var nsec3 = NSec3(owner: Hash(0xC0), nextHashedOwner: Hash(0x20));

		Assert.True(nsec3.IsCovering(HashedName(Hash(0xE0))));
		Assert.True(nsec3.IsCovering(HashedName(Hash(0x10))));
		Assert.False(nsec3.IsCovering(HashedName(Hash(0x50))));
	}

	[Fact]
	public void NSec3_TextRepresentation_CanBeParsedAgain()
	{
		var nsec3 = NSec3(owner: Hash(0x10), nextHashedOwner: Hash(0x90));

		var parsed = new NSec3Record(nsec3.Name, RecordType.NSec3, RecordClass.INet, 3600, _zone, nsec3.RecordDataToString().Split(' '));

		Assert.Equal(nsec3.NextHashedOwner, parsed.NextHashedOwner);
		Assert.Equal(nsec3.Types, parsed.Types);
	}

	private static bool SignAndVerify(DnsKeyRecord key)
	{
		var records = new List<DnsRecordBase> { new ARecord(DomainName.Parse("host.example.test"), 3600, IPAddress.Parse("192.0.2.1")) };
		var signature = new RrSigRecord(records, key, DateTime.Now.AddDays(-1), DateTime.Now.AddDays(1));

		return signature.Verify(records, new[] { key });
	}

	/// <summary>
	///   A SHA-1 hash, which starts with the given byte
	/// </summary>
	private static byte[] Hash(byte first)
	{
		var hash = new byte[20];
		hash[0] = first;
		return hash;
	}

	private static DomainName HashedName(byte[] hash) => new(hash.ToBase32HexString(), _zone);

	private static NSec3Record NSec3(byte[] owner, byte[] nextHashedOwner)
	{
		return new NSec3Record(HashedName(owner), RecordClass.INet, 3600, NSec3HashAlgorithm.Sha1, NSec3Flags.None, 1, Array.Empty<byte>(), nextHashedOwner, new List<RecordType> { RecordType.A, RecordType.RrSig });
	}
}
