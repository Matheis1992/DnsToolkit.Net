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

using System.Text;
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

/// <summary>
///   Tests the HMAC algorithms of TSIG against the published test vectors, so they agree with other implementations and not
///   only with themselves
/// </summary>
public class TSigAlgorithmTests
{
	/// <summary>
	///   The second test case of RFC 2202 (MD5, SHA-1) and RFC 4231 (SHA-2): the key "Jefe" and the data
	///   "what do ya want for nothing?". The truncated algorithms use the same HMAC, only the MAC sent is shorter.
	/// </summary>
	[Theory]
	[InlineData(TSigAlgorithm.Md5, "750c783e6ab0b503eaa86e310a5db738")]
	[InlineData(TSigAlgorithm.Sha1, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")]
	[InlineData(TSigAlgorithm.Sha224, "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44")]
	[InlineData(TSigAlgorithm.Sha256, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")]
	[InlineData(TSigAlgorithm.Sha256_128, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")]
	[InlineData(TSigAlgorithm.Sha384, "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649")]
	[InlineData(TSigAlgorithm.Sha384_192, "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649")]
	[InlineData(TSigAlgorithm.Sha512, "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737")]
	[InlineData(TSigAlgorithm.Sha512_256, "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737")]
	public void Hmac_MatchesThePublishedTestVector(TSigAlgorithm algorithm, string expectedMac)
	{
		// before, hmac-sha384 was computed with SHA-256
		var hmac = TSigAlgorithmHelper.GetHashAlgorithm(algorithm)!;
		var key = Encoding.ASCII.GetBytes("Jefe");
		var data = Encoding.ASCII.GetBytes("what do ya want for nothing?");

		hmac.Init(new Org.BouncyCastle.Crypto.Parameters.KeyParameter(key));
		hmac.BlockUpdate(data, 0, data.Length);
		var mac = new byte[hmac.GetMacSize()];
		hmac.DoFinal(mac, 0);

		Assert.Equal(expectedMac, mac.ToBase16String().ToLowerInvariant());
	}
}
