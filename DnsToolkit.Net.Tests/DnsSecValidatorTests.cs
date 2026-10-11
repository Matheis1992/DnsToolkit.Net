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
///   Tests the limits of the DNSSEC validation against the zone data of an attacker (KeyTrap, CVE-2023-50387, and the
///   NSEC3 closest encloser proof, CVE-2023-50868) with real signatures and a resolver, which returns the keys of the zone
/// </summary>
public class DnsSecValidatorTests
{
	private static readonly DomainName _zone = DomainName.Parse("example.test");
	private static readonly DomainName _host = DomainName.Parse("host.example.test");
	private static readonly DomainName _missing = DomainName.Parse("missing.example.test");
	private static readonly DomainName _wildcard = DomainName.Parse("*.example.test");
	private static readonly DomainName _child = DomainName.Parse("child.example.test");
	private static readonly DomainName _childHost = DomainName.Parse("host.child.example.test");
	private static readonly byte[] _salt = { 0xAB, 0xCD };
	private static readonly DnsKeyRecord _key = DnsKeyRecord.CreateSigningKey(_zone, RecordClass.INet, 3600, DnsKeyFlags.Zone, 3, DnsSecAlgorithm.RsaSha256);

	[Fact]
	public async Task ValidSignature_IsSigned()
	{
		var (message, records) = SignedAnswer();

		Assert.Equal(DnsSecValidationResult.Signed, await ValidateAnswerAsync(new[] { _key }, message, records));
	}

	[Fact]
	public async Task KeyWithTheSameKeyTag_WhichIsMalformed_DoesNotPreventTheValidationWithTheRightKey()
	{
		var (message, records) = SignedAnswer();

		// before, the exception of the malformed key aborted the validation
		Assert.Equal(DnsSecValidationResult.Signed, await ValidateAnswerAsync(new[] { MalformedKey(), _key }, message, records));
	}

	[Fact]
	public async Task OnlyTwoKeysWithTheSameKeyTag_AreTried()
	{
		var (message, records) = SignedAnswer();

		// many keys with the same key tag would otherwise each be tried for every signature (KeyTrap)
		Assert.Equal(DnsSecValidationResult.Bogus, await ValidateAnswerAsync(new[] { CollidingKey(0), CollidingKey(1), _key }, message, records));
	}

	[Fact]
	public async Task MoreSignatureVerificationsThanTheLimit_AreBogus()
	{
		var limit = DnsSecValidationLimits.Default.MaxSignatureValidations;

		// every invalid signature is verified, before the valid one is found
		var (withinLimit, withinLimitRecords) = SignedAnswer(invalidSignaturesBefore: limit - 1);
		var (aboveLimit, aboveLimitRecords) = SignedAnswer(invalidSignaturesBefore: limit);

		var validator = CreateValidator(new[] { _key });
		Assert.Equal(DnsSecValidationResult.Signed, await validator.ValidateAsync(_host, RecordType.A, RecordClass.INet, withinLimit, withinLimitRecords, null, default));
		Assert.Equal(DnsSecValidationResult.Bogus, await validator.ValidateAsync(_host, RecordType.A, RecordClass.INet, aboveLimit, aboveLimitRecords, null, default));

		// the limit applies to every validation separately
		Assert.Equal(DnsSecValidationResult.Signed, await validator.ValidateAsync(_host, RecordType.A, RecordClass.INet, withinLimit, withinLimitRecords, null, default));
	}

	[Fact]
	public async Task NSec3WithMoreIterationsThanTheLimit_IsInsecure()
	{
		var limit = DnsSecValidationLimits.Default.MaxNSec3Iterations;

		Assert.Equal(DnsSecValidationResult.Unsigned, await ValidateNonExistenceAsync(NSec3Denial(_zone, iterations: (ushort) (limit + 1))));

		// up to the limit, the proof of non-existence is checked
		Assert.NotEqual(DnsSecValidationResult.Unsigned, await ValidateNonExistenceAsync(NSec3Denial(_zone, iterations: (ushort) limit)));
	}

	[Fact]
	public async Task NSec3WithMoreIterationsThanTheLimit_ButAnInvalidSignature_IsBogus()
	{
		// RFC 9276: the signature of the NSEC3 records is validated, before the response is treated as insecure
		var message = NSec3Denial(_zone, iterations: (ushort) (DnsSecValidationLimits.Default.MaxNSec3Iterations + 1), invalidSignature: true);

		Assert.Equal(DnsSecValidationResult.Bogus, await ValidateNonExistenceAsync(message));
	}

	[Fact]
	public async Task MoreNSec3HashComputationsThanTheLimit_AreBogus()
	{
		// the NSEC3 record matches the hash of the missing name directly, so its proof needs exactly one hash
		var message = NSec3Denial(_missing, iterations: 1);

		Assert.Equal(DnsSecValidationResult.Signed, await ValidateNonExistenceAsync(message, new DnsSecValidationLimits { MaxNSec3HashComputations = 1 }));
		Assert.Equal(DnsSecValidationResult.Bogus, await ValidateNonExistenceAsync(message, new DnsSecValidationLimits { MaxNSec3HashComputations = 0 }));
	}

	[Fact]
	public async Task AnswerWithoutSignatures_InsideOfASignedZone_IsBogus()
	{
		// the proof, that the name has no DS record, proves no delegation, so it must not make the stripped answer insecure
		var dsResponses = new Dictionary<DomainName, DnsMessage> { [_host] = NSecDenial(_host, RecordType.A, RecordType.RrSig, RecordType.NSec) };

		Assert.Equal(DnsSecValidationResult.Bogus, await ValidateUnsignedAnswerAsync(_host, dsResponses));
	}

	[Fact]
	public async Task AnswerWithoutSignatures_InsideOfASignedZoneWithNSec3_IsBogus()
	{
		var dsResponses = new Dictionary<DomainName, DnsMessage> { [_host] = NSec3DsDenial(_host, RecordType.A, RecordType.RrSig) };

		Assert.Equal(DnsSecValidationResult.Bogus, await ValidateUnsignedAnswerAsync(_host, dsResponses));
	}

	[Fact]
	public async Task AnswerWithoutSignatures_BelowADelegationWithoutDs_IsUnsigned()
	{
		var dsResponses = new Dictionary<DomainName, DnsMessage> { [_child] = NSecDenial(_child, RecordType.Ns, RecordType.RrSig, RecordType.NSec) };

		Assert.Equal(DnsSecValidationResult.Unsigned, await ValidateUnsignedAnswerAsync(_childHost, dsResponses));
	}

	[Fact]
	public async Task AnswerWithoutSignatures_BelowADelegationWithoutDsWithNSec3_IsUnsigned()
	{
		var dsResponses = new Dictionary<DomainName, DnsMessage> { [_child] = NSec3DsDenial(_child, RecordType.Ns) };

		Assert.Equal(DnsSecValidationResult.Unsigned, await ValidateUnsignedAnswerAsync(_childHost, dsResponses));
	}

	[Fact]
	public async Task AnswerWithoutSignatures_BelowTheApexOfTheChildZone_IsBogus()
	{
		// the NSEC record of the apex of the child zone has the SOA bit, so it proves no delegation in the parent zone
		var dsResponses = new Dictionary<DomainName, DnsMessage> { [_child] = NSecDenial(_child, RecordType.Ns, RecordType.Soa, RecordType.RrSig, RecordType.NSec) };

		Assert.Equal(DnsSecValidationResult.Bogus, await ValidateUnsignedAnswerAsync(_childHost, dsResponses));
	}

	[Fact]
	public async Task WildcardExpansion_WithoutProof_IsBogus()
	{
		var (message, records) = WildcardAnswer(_host);

		Assert.Equal(DnsSecValidationResult.Bogus, await ValidateAsync(_host, message, records));
	}

	[Fact]
	public async Task WildcardExpansion_WithNSecCoveringTheName_IsSigned()
	{
		var (message, records) = WildcardAnswer(_host);
		AddSigned(message, new NSecRecord(_wildcard, RecordClass.INet, 3600, DomainName.Parse("zz.example.test"), new List<RecordType> { RecordType.A, RecordType.RrSig, RecordType.NSec }));

		Assert.Equal(DnsSecValidationResult.Signed, await ValidateAsync(_host, message, records));
	}

	[Fact]
	public async Task WildcardExpansion_ForANameWhichExists_IsBogus()
	{
		// the name has an own NSEC record without the A bit, but the wildcard must not be used for a name, which exists
		var (message, records) = WildcardAnswer(_host);
		AddSigned(message, new NSecRecord(_host, RecordClass.INet, 3600, DomainName.Parse("zz.example.test"), new List<RecordType> { RecordType.Aaaa, RecordType.RrSig, RecordType.NSec }));

		Assert.Equal(DnsSecValidationResult.Bogus, await ValidateAsync(_host, message, records));
	}

	[Fact]
	public async Task WildcardExpansion_BelowACloserNameWhichExists_IsBogus()
	{
		// sub.example.test exists, so the wildcard of example.test must not be used for a name below it
		var name = DomainName.Parse("host.sub.example.test");
		var (message, records) = WildcardAnswer(name);
		AddSigned(message, new NSecRecord(DomainName.Parse("sub.example.test"), RecordClass.INet, 3600, DomainName.Parse("zz.example.test"), new List<RecordType> { RecordType.A, RecordType.RrSig, RecordType.NSec }));

		Assert.Equal(DnsSecValidationResult.Bogus, await ValidateAsync(name, message, records));
	}

	[Fact]
	public async Task WildcardExpansion_WithNSec3CoveringTheNextCloserName_IsSigned()
	{
		var (message, records) = WildcardAnswer(_host);
		AddSigned(message, NSec3(new byte[20], Enumerable.Repeat((byte) 0xFF, 20).ToArray(), RecordType.A, RecordType.RrSig));

		Assert.Equal(DnsSecValidationResult.Signed, await ValidateAsync(_host, message, records));
	}

	[Fact]
	public async Task WildcardExpansion_WithNSec3MatchingTheNextCloserName_IsBogus()
	{
		var (message, records) = WildcardAnswer(_host);
		AddSigned(message, NSec3(_host.GetNSec3Hash(NSec3HashAlgorithm.Sha1, 1, _salt), Enumerable.Repeat((byte) 0xFF, 20).ToArray(), RecordType.Aaaa, RecordType.RrSig));

		Assert.Equal(DnsSecValidationResult.Bogus, await ValidateAsync(_host, message, records));
	}

	private static Task<DnsSecValidationResult> ValidateAsync(DomainName name, DnsMessage message, List<ARecord> records)
	{
		return CreateValidator(new[] { _key }).ValidateAsync(name, RecordType.A, RecordClass.INet, message, records, null, default);
	}

	/// <summary>
	///   Validates an A record without signatures, like one whose signatures were stripped by an attacker. The resolver
	///   returns the given responses to the queries for DS records, and an empty response to the other ones.
	/// </summary>
	private static Task<DnsSecValidationResult> ValidateUnsignedAnswerAsync(DomainName name, Dictionary<DomainName, DnsMessage> dsResponses)
	{
		var record = new ARecord(name, 3600, IPAddress.Parse("192.0.2.1"));

		var message = new DnsMessage();
		message.AnswerRecords.Add(record);

		return new DnsSecValidator<object?>(new KeyResolver(new[] { _key }, dsResponses), new EmptyHintStore())
			.ValidateAsync(name, RecordType.A, RecordClass.INet, message, new List<ARecord> { record }, null, default);
	}

	private static Task<DnsSecValidationResult> ValidateAnswerAsync(IReadOnlyList<DnsKeyRecord> keys, DnsMessage message, List<ARecord> records)
	{
		return CreateValidator(keys).ValidateAsync(_host, RecordType.A, RecordClass.INet, message, records, null, default);
	}

	private static Task<DnsSecValidationResult> ValidateNonExistenceAsync(DnsMessage message, DnsSecValidationLimits? limits = null)
	{
		return CreateValidator(new[] { _key }, limits).ValidateAsync(_missing, RecordType.A, RecordClass.INet, message, new List<ARecord>(), null, default);
	}

	private static DnsSecValidator<object?> CreateValidator(IReadOnlyList<DnsKeyRecord> keys, DnsSecValidationLimits? limits = null)
	{
		return new DnsSecValidator<object?>(new KeyResolver(keys), new EmptyHintStore(), limits);
	}

	/// <summary>
	///   An A record signed by the key of the zone, optionally preceded by signatures with the same key tag, which are invalid
	/// </summary>
	private static (DnsMessage Message, List<ARecord> Records) SignedAnswer(int invalidSignaturesBefore = 0)
	{
		var record = new ARecord(_host, 3600, IPAddress.Parse("192.0.2.1"));
		var signature = Sign(record);

		var message = new DnsMessage();
		message.AnswerRecords.Add(record);

		for (var i = 0; i < invalidSignaturesBefore; i++)
			message.AnswerRecords.Add(Corrupt(signature, i));

		message.AnswerRecords.Add(signature);

		return (message, new List<ARecord> { record });
	}

	/// <summary>
	///   A response without records, whose non-existence is proven by a signed NSEC3 record for the hash of the given name
	/// </summary>
	private static DnsMessage NSec3Denial(DomainName hashedName, ushort iterations, bool invalidSignature = false)
	{
		var hash = hashedName.GetNSec3Hash(NSec3HashAlgorithm.Sha1, iterations, _salt);
		var nsec3 = new NSec3Record(
			hashedName.GetNSec3HashName(NSec3HashAlgorithm.Sha1, iterations, _salt, _zone), RecordClass.INet, 3600,
			NSec3HashAlgorithm.Sha1, NSec3Flags.None, iterations, _salt, hash,
			new List<RecordType> { RecordType.Ns, RecordType.Soa, RecordType.RrSig, RecordType.DnsKey, RecordType.NSec3Param });

		var signature = Sign(nsec3);

		var message = new DnsMessage { ReturnCode = ReturnCode.NxDomain };
		message.AuthorityRecords.Add(nsec3);
		message.AuthorityRecords.Add(invalidSignature ? Corrupt(signature, 0) : signature);
		return message;
	}

	/// <summary>
	///   An A record expanded from the wildcard of the zone, with the signature of the wildcard
	/// </summary>
	private static (DnsMessage Message, List<ARecord> Records) WildcardAnswer(DomainName name)
	{
		var signature = Sign(new ARecord(_wildcard, 3600, IPAddress.Parse("192.0.2.1")));
		var record = new ARecord(name, 3600, IPAddress.Parse("192.0.2.1"));

		var message = new DnsMessage();
		message.AnswerRecords.Add(record);
		message.AnswerRecords.Add(new RrSigRecord(name, signature.RecordClass, signature.TimeToLive, signature.TypeCovered, signature.Algorithm, signature.Labels,
			signature.OriginalTimeToLive, signature.SignatureExpiration, signature.SignatureInception, signature.KeyTag, signature.SignersName, signature.Signature));

		return (message, new List<ARecord> { record });
	}

	/// <summary>
	///   A response to the query for the DS record of the name, which proves with a signed NSEC record of the name, that
	///   there is no DS record
	/// </summary>
	private static DnsMessage NSecDenial(DomainName name, params RecordType[] types)
	{
		var message = new DnsMessage();
		AddSigned(message, new NSecRecord(name, RecordClass.INet, 3600, DomainName.Parse("zz.example.test"), types.ToList()));
		return message;
	}

	/// <summary>
	///   A response to the query for the DS record of the name, which proves with a signed NSEC3 record of the hash of the
	///   name, that there is no DS record
	/// </summary>
	private static DnsMessage NSec3DsDenial(DomainName name, params RecordType[] types)
	{
		var message = new DnsMessage();
		AddSigned(message, NSec3(name.GetNSec3Hash(NSec3HashAlgorithm.Sha1, 1, _salt), Enumerable.Repeat((byte) 0xFF, 20).ToArray(), types));
		return message;
	}

	private static NSec3Record NSec3(byte[] ownerHash, byte[] nextHash, params RecordType[] types)
	{
		return new NSec3Record(new DomainName(ownerHash.ToBase32HexString(), _zone), RecordClass.INet, 3600, NSec3HashAlgorithm.Sha1, NSec3Flags.None, 1, _salt, nextHash, types.ToList());
	}

	private static void AddSigned(DnsMessage message, DnsRecordBase record)
	{
		message.AuthorityRecords.Add(record);
		message.AuthorityRecords.Add(Sign(record));
	}

	private static RrSigRecord Sign(DnsRecordBase record)
	{
		return new RrSigRecord(new List<DnsRecordBase> { record }, _key, DateTime.Now.AddDays(-1), DateTime.Now.AddDays(1));
	}

	/// <summary>
	///   A copy of the signature with the same key tag, whose signature data is invalid
	/// </summary>
	private static RrSigRecord Corrupt(RrSigRecord signature, int variant)
	{
		var data = (byte[]) signature.Signature.Clone();
		data[variant % data.Length] ^= (byte) (1 + variant / data.Length);

		return new RrSigRecord(signature.Name, signature.RecordClass, signature.TimeToLive, signature.TypeCovered, signature.Algorithm, signature.Labels,
			signature.OriginalTimeToLive, signature.SignatureExpiration, signature.SignatureInception, signature.KeyTag, signature.SignersName, data);
	}

	/// <summary>
	///   A different key with the same algorithm and key tag as the key of the zone. The key tag is a checksum, in which
	///   bytes at an even distance are added up, so increasing one byte and decreasing the byte two positions later keeps it.
	/// </summary>
	private static DnsKeyRecord CollidingKey(int variant)
	{
		var publicKey = (byte[]) _key.PublicKey.Clone();

		var found = 0;
		for (var i = 0; i + 2 < publicKey.Length; i++)
		{
			if ((publicKey[i] == 255) || (publicKey[i + 2] == 0))
				continue;

			if (found++ < variant)
				continue;

			publicKey[i]++;
			publicKey[i + 2]--;
			break;
		}

		var key = new DnsKeyRecord(_zone, RecordClass.INet, 3600, _key.Flags, _key.Protocol, _key.Algorithm, publicKey);
		Assert.Equal(_key.CalculateKeyTag(), key.CalculateKeyTag());
		Assert.NotEqual(_key.PublicKey, key.PublicKey);
		return key;
	}

	/// <summary>
	///   A key with the same algorithm and key tag as the key of the zone, whose public key of two bytes is no valid RSA
	///   key, so its use throws. The two bytes are chosen to give the same key tag.
	/// </summary>
	private static DnsKeyRecord MalformedKey()
	{
		for (var value = 0; value <= UInt16.MaxValue; value++)
		{
			var publicKey = new[] { (byte) (value >> 8), (byte) value };
			var key = new DnsKeyRecord(_zone, RecordClass.INet, 3600, _key.Flags, _key.Protocol, _key.Algorithm, publicKey);

			if (key.CalculateKeyTag() == _key.CalculateKeyTag())
			{
				Assert.ThrowsAny<Exception>(() => key.Verify(new byte[16], 16, new byte[128]));
				return key;
			}
		}

		throw new InvalidOperationException("No public key with the same key tag found");
	}

	/// <summary>
	///   Returns the given keys as the validated keys of the zone, and the given responses to the queries for DS records
	/// </summary>
	private sealed class KeyResolver : IInternalDnsSecResolver<object?>
	{
		private readonly IReadOnlyList<DnsKeyRecord> _keys;
		private readonly Dictionary<DomainName, DnsMessage>? _dsResponses;

		public KeyResolver(IReadOnlyList<DnsKeyRecord> keys, Dictionary<DomainName, DnsMessage>? dsResponses = null)
		{
			_keys = keys;
			_dsResponses = dsResponses;
		}

		public Task<DnsMessage?> ResolveMessageAsync(DomainName name, RecordType recordType, RecordClass recordClass, object? state, CancellationToken token)
		{
			if ((recordType != RecordType.Ds) || (_dsResponses == null))
				throw new NotSupportedException();

			return Task.FromResult<DnsMessage?>(_dsResponses.TryGetValue(name, out var response) ? response : new DnsMessage());
		}

		public Task<DnsSecResult<TRecord>> ResolveSecureAsync<TRecord>(DomainName name, RecordType recordType, RecordClass recordClass, object? state, CancellationToken token)
			where TRecord : DnsRecordBase
		{
			if ((recordType != RecordType.DnsKey) || !name.Equals(_zone))
				throw new NotSupportedException();

			return Task.FromResult(new DnsSecResult<TRecord>(_keys.Cast<TRecord>().ToList(), DnsSecValidationResult.Signed));
		}
	}

	private sealed class EmptyHintStore : IResolverHintStore
	{
		public IReadOnlyList<IPAddress> RootServers { get; } = Array.Empty<IPAddress>();

		public IReadOnlyList<DsRecord> RootKeys { get; } = Array.Empty<DsRecord>();
	}
}
