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

namespace DnsToolkit.Net.Dns;

/// <summary>
///   <para>Info code of an <see cref="ExtendedDnsErrorOption" /></para>
///   <para>
///     Defined in
///     <a href="https://www.rfc-editor.org/rfc/rfc8914.html">RFC 8914</a>
///     unless stated otherwise. Codes, which are not listed, keep their numeric value.
///   </para>
/// </summary>
public enum ExtendedDnsErrorCode : ushort
{
	/// <summary>
	///   An error, which none of the other codes matches. The extra text should describe it.
	/// </summary>
	Other = 0,

	/// <summary>
	///   The answer is unsigned for DNSSEC, as the zone is only signed with unsupported DNSKEY algorithms
	/// </summary>
	UnsupportedDnsKeyAlgorithm = 1,

	/// <summary>
	///   The answer is unsigned for DNSSEC, as the DS records only use unsupported digest types
	/// </summary>
	UnsupportedDsDigestType = 2,

	/// <summary>
	///   The answer is stale data from the cache, as the authority was not reachable
	/// </summary>
	StaleAnswer = 3,

	/// <summary>
	///   The answer was forged by a policy of the resolver
	/// </summary>
	ForgedAnswer = 4,

	/// <summary>
	///   The DNSSEC validation ended indeterminate
	/// </summary>
	DnsSecIndeterminate = 5,

	/// <summary>
	///   The DNSSEC validation failed
	/// </summary>
	DnsSecBogus = 6,

	/// <summary>
	///   The DNSSEC validation failed, as the signatures are expired
	/// </summary>
	SignatureExpired = 7,

	/// <summary>
	///   The DNSSEC validation failed, as the signatures are not valid yet
	/// </summary>
	SignatureNotYetValid = 8,

	/// <summary>
	///   The DNSSEC validation failed, as no matching DNSKEY to the DS records exists
	/// </summary>
	DnsKeyMissing = 9,

	/// <summary>
	///   The DNSSEC validation failed, as the signatures are missing
	/// </summary>
	RrSigsMissing = 10,

	/// <summary>
	///   The DNSSEC validation failed, as no DNSKEY has the zone key bit set
	/// </summary>
	NoZoneKeyBitSet = 11,

	/// <summary>
	///   The DNSSEC validation failed, as the NSEC or NSEC3 records are missing
	/// </summary>
	NSecMissing = 12,

	/// <summary>
	///   The resolver answered with a cached error
	/// </summary>
	CachedError = 13,

	/// <summary>
	///   The server is not ready to answer, e.g. as it is starting
	/// </summary>
	NotReady = 14,

	/// <summary>
	///   The name is blocked by the operator of the server
	/// </summary>
	Blocked = 15,

	/// <summary>
	///   The name is blocked, as an external requirement demands it
	/// </summary>
	Censored = 16,

	/// <summary>
	///   The name is blocked, as the client requested it, e.g. by a filtering service
	/// </summary>
	Filtered = 17,

	/// <summary>
	///   The client is not allowed to query the server
	/// </summary>
	Prohibited = 18,

	/// <summary>
	///   The NXDOMAIN answer is stale data from the cache
	/// </summary>
	StaleNxDomainAnswer = 19,

	/// <summary>
	///   The server is not authoritative for the name and does not resolve recursively
	/// </summary>
	NotAuthoritative = 20,

	/// <summary>
	///   The requested operation or query is not supported
	/// </summary>
	NotSupported = 21,

	/// <summary>
	///   The resolver could not reach any of the authoritative name servers
	/// </summary>
	NoReachableAuthority = 22,

	/// <summary>
	///   An unrecoverable network error occurred
	/// </summary>
	NetworkError = 23,

	/// <summary>
	///   The data of the authoritative server for the zone is invalid
	/// </summary>
	InvalidData = 24,

	/// <summary>
	///   <para>The DNSSEC validation failed, as a signature expired before it became valid</para>
	///   <para>Registered at IANA after RFC 8914.</para>
	/// </summary>
	SignatureExpiredBeforeValid = 25,

	/// <summary>
	///   <para>The query arrived as 0-RTT data, which the server does not accept for it</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc9250.html">RFC 9250</a>.
	///   </para>
	/// </summary>
	TooEarly = 26,

	/// <summary>
	///   <para>The answer is unsigned for DNSSEC, as the NSEC3 records use too many iterations</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc9276.html">RFC 9276</a>.
	///   </para>
	/// </summary>
	UnsupportedNSec3IterationsValue = 27,

	/// <summary>
	///   <para>The query type is not allowed in queries, e.g. a meta type like NXNAME</para>
	///   <para>
	///     Defined in
	///     <a href="https://www.rfc-editor.org/rfc/rfc9824.html">RFC 9824</a>.
	///   </para>
	/// </summary>
	InvalidQueryType = 30,
}
