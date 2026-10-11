#region Copyright and License
// Copyright 2010..2024 Alexander Reinert
// Modifications Copyright 2026 Matheis1992
// 
// This file is part of the ARSoft.Tools.Net - C# DNS client/server and SPF Library (https://github.com/alexreinert/ARSoft.Tools.Net)
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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DnsToolkit.Net.Dns
{
	internal class DnsSecValidator<TState>
	{
		private readonly IInternalDnsSecResolver<TState> _resolver;
		private readonly IResolverHintStore _resolverHintStore;
		private readonly DnsSecValidationLimits _limits;

		public DnsSecValidator(IInternalDnsSecResolver<TState> resolver, IResolverHintStore resolverHintStore, DnsSecValidationLimits? limits = null)
		{
			_resolver = resolver;
			_resolverHintStore = resolverHintStore;
			_limits = limits ?? DnsSecValidationLimits.Default;
		}

		public async Task<DnsSecValidationResult> ValidateAsync<TRecord>(DomainName name, RecordType recordType, RecordClass recordClass, DnsMessage msg, List<TRecord> resultRecords, TState state, CancellationToken token)
			where TRecord : DnsRecordBase
		{
			// The zone data of an attacker could otherwise make the validation take very long (KeyTrap, CVE-2023-50387,
			// and the NSEC3 closest encloser proof, CVE-2023-50868). The keys and DS records of the signers are validated
			// separately, each with an own budget.
			var budget = new DnsSecValidationBudget(_limits);

			try
			{
				return await ValidateAsync(name, recordType, recordClass, msg, resultRecords, state, budget, token).ConfigureAwait(false);
			}
			catch (DnsSecValidationLimitExceededException)
			{
				return DnsSecValidationResult.Bogus;
			}
		}

		private async Task<DnsSecValidationResult> ValidateAsync<TRecord>(DomainName name, RecordType recordType, RecordClass recordClass, DnsMessage msg, List<TRecord> resultRecords, TState state, DnsSecValidationBudget budget, CancellationToken token)
			where TRecord : DnsRecordBase
		{
			List<RrSigRecord> rrSigRecords = msg
				.AnswerRecords.OfType<RrSigRecord>()
				.Union(msg.AuthorityRecords.OfType<RrSigRecord>())
				.Where(x => name.IsEqualOrSubDomainOf(x.SignersName) && (x.SignatureInception <= DateTime.Now) && (x.SignatureExpiration >= DateTime.Now)).ToList();

			if (rrSigRecords.Count == 0)
			{
				return await ValidateOptOut(name, recordClass, state, budget, token).ConfigureAwait(false) ? DnsSecValidationResult.Unsigned : DnsSecValidationResult.Bogus;
			}

			DomainName zoneApex = rrSigRecords.OrderByDescending(x => x.Labels).First().SignersName;

			if (resultRecords.Count != 0)
				return await ValidateRrSigAsync(name, recordType, recordClass, resultRecords, rrSigRecords, zoneApex, msg, state, budget, token).ConfigureAwait(false);

			return await ValidateNonExistenceAsync(name, recordType, recordClass, rrSigRecords, DomainName.Asterisk + zoneApex, zoneApex, msg, state, budget, token).ConfigureAwait(false);
		}

		private async Task<bool> ValidateOptOut(DomainName name, RecordClass recordClass, TState state, DnsSecValidationBudget budget, CancellationToken token)
		{
			while (!name.IsRoot)
			{
				DnsMessage? msg = await _resolver.ResolveMessageAsync(name, RecordType.Ds, recordClass, state, token).ConfigureAwait(false);

				if ((msg == null) || ((msg.ReturnCode != ReturnCode.NoError) && (msg.ReturnCode != ReturnCode.NxDomain)))
				{
					throw new Exception("DNS request failed");
				}

				List<RrSigRecord> rrSigRecords = msg
					.AnswerRecords.OfType<RrSigRecord>()
					.Union(msg.AuthorityRecords.OfType<RrSigRecord>())
					.Where(x => name.IsEqualOrSubDomainOf(x.SignersName) && (x.SignatureInception <= DateTime.Now) && (x.SignatureExpiration >= DateTime.Now)).ToList();

				if (rrSigRecords.Count != 0)
				{
					DomainName zoneApex = rrSigRecords.OrderByDescending(x => x.Labels).First().SignersName;

					// No name inside of a signed zone has a DS record, so only the proof of a delegation without DS records
					// makes the name insecure. Otherwise, an answer of a signed zone, whose signatures were stripped, would be
					// insecure instead of bogus.
					if (await ValidateInsecureDelegationAsync(name, recordClass, rrSigRecords, zoneApex, msg, state, budget, token).ConfigureAwait(false))
						return true;
				}

				name = name.GetParentName();
			}

			return false;
		}

		/// <summary>
		///   Validates the proof, that the name is a delegation without DS records (RFC 4035, section 5.2, and RFC 5155,
		///   section 8.6): the NSEC or NSEC3 record of the name has the NS bit, but neither the DS nor the SOA bit, or an
		///   NSEC3 record with the opt-out flag covers the hash of the name
		/// </summary>
		private async Task<bool> ValidateInsecureDelegationAsync(DomainName name, RecordClass recordClass, List<RrSigRecord> rrSigRecords, DomainName zoneApex, DnsMessage msg, TState state, DnsSecValidationBudget budget, CancellationToken token)
		{
			static bool IsInsecureDelegation(List<RecordType> types) => types.Contains(RecordType.Ns) && !types.Contains(RecordType.Ds) && !types.Contains(RecordType.Soa);

			List<NSecRecord> nsecRecords = msg.AuthorityRecords.OfType<NSecRecord>().ToList();

			if (nsecRecords.Count != 0)
			{
				if (await ValidateRrSigsPerOwnerAsync(nsecRecords, RecordType.NSec, recordClass, rrSigRecords, zoneApex, msg, state, budget, token).ConfigureAwait(false) != DnsSecValidationResult.Signed)
					return false;

				NSecRecord? nsecRecord = nsecRecords.FirstOrDefault(x => x.Name.Equals(name));
				return (nsecRecord != null) && IsInsecureDelegation(nsecRecord.Types);
			}

			List<NSec3Record> nsec3Records = msg.AuthorityRecords.OfType<NSec3Record>().Where(x => ((x.Flags == NSec3Flags.None) || (x.Flags == NSec3Flags.OptOut)) && x.Name.GetParentName().Equals(zoneApex)).ToList();

			NSec3Record? nsec3Parameter = GetNSec3Parameter(nsec3Records);
			if (nsec3Parameter == null)
				return false;

			if (await ValidateRrSigsPerOwnerAsync(nsec3Records, RecordType.NSec3, recordClass, rrSigRecords, zoneApex, msg, state, budget, token).ConfigureAwait(false) != DnsSecValidationResult.Signed)
				return false;

			// Treated as insecure like recommended in RFC 9276, but only after the signatures of the NSEC3 records were validated above
			if (nsec3Parameter.Iterations > _limits.MaxNSec3Iterations)
				return true;

			budget.ConsumeNSec3HashComputation();
			DomainName hashedName = name.GetNSec3HashName(nsec3Parameter.HashAlgorithm, nsec3Parameter.Iterations, nsec3Parameter.Salt, zoneApex);

			NSec3Record? directMatch = nsec3Records.FirstOrDefault(x => x.Name.Equals(hashedName));
			if (directMatch != null)
				return IsInsecureDelegation(directMatch.Types);

			return nsec3Records.Any(x => x.Flags.HasFlag(NSec3Flags.OptOut) && x.IsCovering(hashedName));
		}

		private async Task<DnsSecValidationResult> ValidateNonExistenceAsync(DomainName name, RecordType recordType, RecordClass recordClass, List<RrSigRecord> rrSigRecords, DomainName stop, DomainName zoneApex, DnsMessage msg, TState state, DnsSecValidationBudget budget, CancellationToken token)
		{
			var nsecRes = await ValidateNSecAsync(name, recordType, recordClass, rrSigRecords, stop, zoneApex, msg, state, budget, token).ConfigureAwait(false);
			if (nsecRes == DnsSecValidationResult.Signed)
				return nsecRes;

			var nsec3Res = await ValidateNSec3Async(name, recordType, recordClass, rrSigRecords, stop.Equals(DomainName.Asterisk + zoneApex), zoneApex, msg, state, budget, token).ConfigureAwait(false);
			if (nsec3Res == DnsSecValidationResult.Signed)
				return nsec3Res;

			if ((nsecRes == DnsSecValidationResult.Unsigned) || (nsec3Res == DnsSecValidationResult.Unsigned))
				return DnsSecValidationResult.Unsigned;

			if ((nsecRes == DnsSecValidationResult.Bogus) || (nsec3Res == DnsSecValidationResult.Bogus))
				return DnsSecValidationResult.Bogus;

			return DnsSecValidationResult.Indeterminate;
		}

		private async Task<DnsSecValidationResult> ValidateNSecAsync(DomainName name, RecordType recordType, RecordClass recordClass, List<RrSigRecord> rrSigRecords, DomainName stop, DomainName zoneApex, DnsMessage msg, TState state, DnsSecValidationBudget budget, CancellationToken token)
		{
			List<NSecRecord> nsecRecords = msg.AuthorityRecords.OfType<NSecRecord>().ToList();

			if (nsecRecords.Count == 0)
				return DnsSecValidationResult.Indeterminate;

			DnsSecValidationResult validationResult = await ValidateRrSigsPerOwnerAsync(nsecRecords, RecordType.NSec, recordClass, rrSigRecords, zoneApex, msg, state, budget, token).ConfigureAwait(false);
			if (validationResult != DnsSecValidationResult.Signed)
				return validationResult;

			DomainName current = name;

			while (true)
			{
				if (current.Equals(stop))
				{
					return DnsSecValidationResult.Signed;
				}

				NSecRecord? nsecRecord = nsecRecords.FirstOrDefault(x => x.Name.Equals(current));
				if (nsecRecord != null)
				{
					return nsecRecord.Types.Contains(recordType) ? DnsSecValidationResult.Bogus : DnsSecValidationResult.Signed;
				}
				else
				{
					nsecRecord = nsecRecords.FirstOrDefault(x => x.IsCovering(current, zoneApex));
					if (nsecRecord == null)
						return DnsSecValidationResult.Bogus;
				}

				current = current.Labels[0] == "*" ? current.GetParentName() : DomainName.Asterisk + current.GetParentName();
			}
		}

		private async Task<DnsSecValidationResult> ValidateNSec3Async(DomainName name, RecordType recordType, RecordClass recordClass, List<RrSigRecord> rrSigRecords, bool checkWildcard, DomainName zoneApex, DnsMessage msg, TState state, DnsSecValidationBudget budget, CancellationToken token)
		{
			List<NSec3Record> nsecRecords = msg.AuthorityRecords.OfType<NSec3Record>().Where(r => r.Flags == NSec3Flags.None || r.Flags == NSec3Flags.OptOut).ToList();

			if (nsecRecords.Count == 0)
				return DnsSecValidationResult.Indeterminate;

			DnsSecValidationResult validationResult = await ValidateRrSigsPerOwnerAsync(nsecRecords, RecordType.NSec3, recordClass, rrSigRecords, zoneApex, msg, state, budget, token).ConfigureAwait(false);
			if (validationResult != DnsSecValidationResult.Signed)
				return validationResult;

			var nsec3Parameter = nsecRecords.Where(x => x.Name.GetParentName().Equals(zoneApex)).Where(x => x.HashAlgorithm.IsSupported()).Select(x => new { x.HashAlgorithm, x.Iterations, x.Salt }).OrderBy(x => x.HashAlgorithm.GetPriority()).FirstOrDefault();

			// NSEC3 records with an unknown hash algorithm are ignored, so they prove nothing (RFC 5155, section 8.1)
			if (nsec3Parameter == null)
				return DnsSecValidationResult.Bogus;

			// An NSEC3 record of a delegation point, which has the NS bit, but not the SOA bit, belongs to the parent zone. Except
			// the missing DS record, it proves nothing about the child zone (RFC 5155, section 8.3, and RFC 6840, section 4.1).
			static bool IsDelegationPoint(NSec3Record record) => record.Types.Contains(RecordType.Ns) && !record.Types.Contains(RecordType.Soa);

			// Treated as insecure like recommended in RFC 9276, but only after the signatures of the NSEC3 records were validated above
			if (nsec3Parameter.Iterations > _limits.MaxNSec3Iterations)
				return DnsSecValidationResult.Unsigned;

			DomainName GetNSec3HashName(DomainName domainName)
			{
				budget.ConsumeNSec3HashComputation();
				return domainName.GetNSec3HashName(nsec3Parameter.HashAlgorithm, nsec3Parameter.Iterations, nsec3Parameter.Salt, zoneApex);
			}

			DomainName hashedName = GetNSec3HashName(name);

			if (recordType == RecordType.Ds && nsecRecords.Any(x => x.IsCovering(hashedName) && x.Flags.HasFlag(NSec3Flags.OptOut)))
				return DnsSecValidationResult.Unsigned;

			var directMatch = nsecRecords.FirstOrDefault(x => x.Name.Equals(hashedName));
			if (directMatch != null)
			{
				if ((recordType != RecordType.Ds) && IsDelegationPoint(directMatch))
					return DnsSecValidationResult.Bogus;

				return directMatch.Types.Contains(recordType) ? DnsSecValidationResult.Bogus : DnsSecValidationResult.Signed;
			}

			// find closest encloser
			DomainName current = name;
			DomainName previousHashedName = hashedName;

			while (true)
			{
				var closestEncloserMatch = nsecRecords.FirstOrDefault(x => x.Name.Equals(hashedName, true));
				if (closestEncloserMatch != null)
				{
					// names below a delegation or a DNAME record are not in the zone, so the zone cannot deny them (RFC 5155, section 8.3)
					if (IsDelegationPoint(closestEncloserMatch) || closestEncloserMatch.Types.Contains(RecordType.DName))
						return DnsSecValidationResult.Bogus;

					break;
				}

				if (current.Equals(zoneApex))
					return DnsSecValidationResult.Bogus; // closest encloser could not be found, but at least the zone apex must be found as

				current = current.GetParentName();
				previousHashedName = hashedName;
				hashedName = GetNSec3HashName(current);
			}

			if (!nsecRecords.Any(x => x.IsCovering(previousHashedName)))
				return DnsSecValidationResult.Bogus;

			if (checkWildcard)
			{
				DomainName wildcardHashName = GetNSec3HashName(DomainName.Asterisk + current);

				var wildcardDirectMatch = nsecRecords.FirstOrDefault(x => x.Name.Equals(wildcardHashName));
				if ((wildcardDirectMatch != null) && (!wildcardDirectMatch.Types.Contains(recordType)))
					return wildcardDirectMatch.Types.Contains(recordType) ? DnsSecValidationResult.Bogus : DnsSecValidationResult.Signed;

				var wildcardCoveringMatch = nsecRecords.FirstOrDefault(x => x.IsCovering(wildcardHashName));
				return (wildcardCoveringMatch != null) ? DnsSecValidationResult.Signed : DnsSecValidationResult.Bogus;
			}
			else
			{
				return DnsSecValidationResult.Signed;
			}
		}

		private async Task<DnsSecValidationResult> ValidateRrSigAsync<TRecord>(DomainName name, RecordType recordType, RecordClass recordClass, List<TRecord> resultRecords, List<RrSigRecord> rrSigRecords, DomainName zoneApex, DnsMessage msg, TState state, DnsSecValidationBudget budget, CancellationToken token)
			where TRecord : DnsRecordBase
		{
			DnsSecValidationResult res = DnsSecValidationResult.Bogus;

			foreach (var record in rrSigRecords.Where(x => x.Name.Equals(name) && (x.TypeCovered == recordType)))
			{
				res = await ValidateRrSigAsync(record, resultRecords, recordClass, state, budget, token).ConfigureAwait(false);
				if (res == DnsSecValidationResult.Signed)
				{
					if ((record.Labels == name.LabelCount)
					    || ((name.Labels[0] == "*") && (record.Labels == name.LabelCount - 1)))
						return DnsSecValidationResult.Signed;

					// an answer expanded from a wildcard is only valid with the proof, that no closer name exists
					res = await ValidateWildcardExpansionAsync(name, record.Labels, recordClass, rrSigRecords, record.SignersName, msg, state, budget, token).ConfigureAwait(false);
					if (res == DnsSecValidationResult.Signed)
						return DnsSecValidationResult.Signed;
				}
			}

			return res;
		}

		/// <summary>
		///   Validates the proof, that the answer for the name was expanded from the wildcard of the closest encloser given by
		///   the labels of the signature (RFC 4035, section 5.3.4, and RFC 5155, section 8.8): neither the name nor the next
		///   closer name, which is the closest encloser plus the next label of the name, exists
		/// </summary>
		private async Task<DnsSecValidationResult> ValidateWildcardExpansionAsync(DomainName name, int signatureLabels, RecordClass recordClass, List<RrSigRecord> rrSigRecords, DomainName zoneApex, DnsMessage msg, TState state, DnsSecValidationBudget budget, CancellationToken token)
		{
			DomainName closestEncloser = name.GetParentName(name.LabelCount - signatureLabels);
			DomainName nextCloser = name.GetParentName(name.LabelCount - signatureLabels - 1);

			if (!closestEncloser.IsEqualOrSubDomainOf(zoneApex))
				return DnsSecValidationResult.Bogus;

			List<NSecRecord> nsecRecords = msg.AuthorityRecords.OfType<NSecRecord>().ToList();

			if (nsecRecords.Count != 0)
			{
				if (await ValidateRrSigsPerOwnerAsync(nsecRecords, RecordType.NSec, recordClass, rrSigRecords, zoneApex, msg, state, budget, token).ConfigureAwait(false) != DnsSecValidationResult.Signed)
					return DnsSecValidationResult.Bogus;

				// A closer name, which exists, is the owner or the next name of every NSEC record covering the name, or a
				// parent of them. So they share no more labels with the name than the closest encloser.
				return nsecRecords.Any(x => x.IsCovering(name, zoneApex)
				                            && (Math.Max(GetCommonLabelCount(name, x.Name), GetCommonLabelCount(name, x.NextDomainName)) == closestEncloser.LabelCount))
					? DnsSecValidationResult.Signed
					: DnsSecValidationResult.Bogus;
			}

			List<NSec3Record> nsec3Records = msg.AuthorityRecords.OfType<NSec3Record>().Where(x => ((x.Flags == NSec3Flags.None) || (x.Flags == NSec3Flags.OptOut)) && x.Name.GetParentName().Equals(zoneApex)).ToList();

			NSec3Record? nsec3Parameter = GetNSec3Parameter(nsec3Records);
			if (nsec3Parameter == null)
				return DnsSecValidationResult.Bogus;

			if (await ValidateRrSigsPerOwnerAsync(nsec3Records, RecordType.NSec3, recordClass, rrSigRecords, zoneApex, msg, state, budget, token).ConfigureAwait(false) != DnsSecValidationResult.Signed)
				return DnsSecValidationResult.Bogus;

			// Treated as insecure like recommended in RFC 9276, but only after the signatures of the NSEC3 records were validated above
			if (nsec3Parameter.Iterations > _limits.MaxNSec3Iterations)
				return DnsSecValidationResult.Unsigned;

			budget.ConsumeNSec3HashComputation();
			DomainName hashedNextCloser = nextCloser.GetNSec3HashName(nsec3Parameter.HashAlgorithm, nsec3Parameter.Iterations, nsec3Parameter.Salt, zoneApex);

			return nsec3Records.Any(x => x.IsCovering(hashedNextCloser)) ? DnsSecValidationResult.Signed : DnsSecValidationResult.Bogus;
		}

		private async Task<DnsSecValidationResult> ValidateRrSigsPerOwnerAsync<TRecord>(List<TRecord> records, RecordType recordType, RecordClass recordClass, List<RrSigRecord> rrSigRecords, DomainName zoneApex, DnsMessage msg, TState state, DnsSecValidationBudget budget, CancellationToken token)
			where TRecord : DnsRecordBase
		{
			foreach (var recordGroup in records.GroupBy(x => x.Name))
			{
				DnsSecValidationResult validationResult = await ValidateRrSigAsync(recordGroup.Key, recordType, recordClass, recordGroup.ToList(), rrSigRecords, zoneApex, msg, state, budget, token).ConfigureAwait(false);

				if (validationResult != DnsSecValidationResult.Signed)
					return validationResult;
			}

			return DnsSecValidationResult.Signed;
		}

		private static NSec3Record? GetNSec3Parameter(List<NSec3Record> nsec3Records)
		{
			return nsec3Records.Where(x => x.HashAlgorithm.IsSupported()).OrderBy(x => x.HashAlgorithm.GetPriority()).FirstOrDefault();
		}

		private static int GetCommonLabelCount(DomainName name1, DomainName name2)
		{
			int count = 0;

			while ((count < name1.LabelCount) && (count < name2.LabelCount)
			       && String.Equals(name1.Labels[name1.LabelCount - 1 - count], name2.Labels[name2.LabelCount - 1 - count], StringComparison.OrdinalIgnoreCase))
			{
				count++;
			}

			return count;
		}

		private async Task<DnsSecValidationResult> ValidateRrSigAsync<TRecord>(RrSigRecord rrSigRecord, List<TRecord> coveredRecords, RecordClass recordClass, TState state, DnsSecValidationBudget budget, CancellationToken token)
			where TRecord : DnsRecordBase
		{
			if (rrSigRecord.TypeCovered == RecordType.DnsKey)
			{
				IReadOnlyList<DsRecord> dsRecords;

				if (rrSigRecord.SignersName.Equals(DomainName.Root))
				{
					dsRecords = _resolverHintStore.RootKeys;
				}
				else
				{
					var dsRecordResults = await _resolver.ResolveSecureAsync<DsRecord>(rrSigRecord.SignersName, RecordType.Ds, recordClass, state, token).ConfigureAwait(false);

					if ((dsRecordResults.ValidationResult == DnsSecValidationResult.Bogus) || (dsRecordResults.ValidationResult == DnsSecValidationResult.Indeterminate))
						throw new DnsSecValidationException("DS records could not be retrieved");

					if (dsRecordResults.ValidationResult == DnsSecValidationResult.Unsigned)
						return DnsSecValidationResult.Unsigned;

					dsRecords = dsRecordResults.Records;
				}

				if (!dsRecords.Any())
					return DnsSecValidationResult.Unsigned;

				if (dsRecords.Any() && !dsRecords.Any(r => r.Algorithm.IsSupported()))
					return DnsSecValidationResult.Indeterminate;

				return dsRecords.Any(dsRecord => rrSigRecord.Verify(coveredRecords, coveredRecords.Cast<DnsKeyRecord>().Where(dsRecord.IsCovering).ToList(), budget)) ? DnsSecValidationResult.Signed : DnsSecValidationResult.Bogus;
			}
			else
			{
				var dnsKeyRecordResults = await _resolver.ResolveSecureAsync<DnsKeyRecord>(rrSigRecord.SignersName, RecordType.DnsKey, recordClass, state, token).ConfigureAwait(false);

				if ((dnsKeyRecordResults.ValidationResult == DnsSecValidationResult.Bogus) || (dnsKeyRecordResults.ValidationResult == DnsSecValidationResult.Indeterminate))
					throw new DnsSecValidationException("DNSKEY records could not be retrieved");

				if (!rrSigRecord.Verify(coveredRecords, dnsKeyRecordResults.Records, budget))
					return DnsSecValidationResult.Bogus;

				if (dnsKeyRecordResults.ValidationResult == DnsSecValidationResult.Unsigned)
					return DnsSecValidationResult.Indeterminate;

				return DnsSecValidationResult.Signed;
			}
		}
	}
}