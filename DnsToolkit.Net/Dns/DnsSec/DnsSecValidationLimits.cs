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
///   Limits of the work for validating a response, as the zone data of an attacker could otherwise make the validation
///   take very long (KeyTrap, CVE-2023-50387, and the NSEC3 closest encloser proof, CVE-2023-50868). The defaults are
///   the ones of the PowerDNS Recursor.
/// </summary>
internal sealed class DnsSecValidationLimits
{
	public static DnsSecValidationLimits Default { get; } = new();

	/// <summary>
	///   NSEC3 records with more hash iterations are treated as insecure, like recommended in RFC 9276
	/// </summary>
	public int MaxNSec3Iterations { get; init; } = 50;

	/// <summary>
	///   The number of DNSKEYs with the same algorithm and key tag, which are tried for a signature
	/// </summary>
	public int MaxDnsKeysPerKeyTag { get; init; } = 2;

	/// <summary>
	///   The number of signature verifications for validating a response. If more are needed, the response is bogus.
	/// </summary>
	public int MaxSignatureValidations { get; init; } = 30;

	/// <summary>
	///   The number of NSEC3 hashes of names for validating a response. If more are needed, the response is bogus.
	/// </summary>
	public int MaxNSec3HashComputations { get; init; } = 600;
}

/// <summary>
///   The work, which is left for validating a response
/// </summary>
internal sealed class DnsSecValidationBudget
{
	private readonly DnsSecValidationLimits _limits;
	private int _signatureValidations;
	private int _nsec3HashComputations;

	public DnsSecValidationBudget(DnsSecValidationLimits limits)
	{
		_limits = limits;
	}

	public int MaxDnsKeysPerKeyTag => _limits.MaxDnsKeysPerKeyTag;

	/// <exception cref="DnsSecValidationLimitExceededException">The limit of signature verifications is exceeded</exception>
	public void ConsumeSignatureValidation()
	{
		if (++_signatureValidations > _limits.MaxSignatureValidations)
			throw new DnsSecValidationLimitExceededException();
	}

	/// <exception cref="DnsSecValidationLimitExceededException">The limit of NSEC3 hash computations is exceeded</exception>
	public void ConsumeNSec3HashComputation()
	{
		if (++_nsec3HashComputations > _limits.MaxNSec3HashComputations)
			throw new DnsSecValidationLimitExceededException();
	}
}

/// <summary>
///   The validation of a response needs more work than allowed, so the response is bogus
/// </summary>
internal sealed class DnsSecValidationLimitExceededException : Exception { }
