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
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Spf
{
	/// <summary>
	///   Base implementation of a validator for SPF and SenderID records
	/// </summary>
	/// <typeparam name="T"> Type of the record </typeparam>
	public abstract class ValidatorBase<T>
		where T : SpfRecordBase
	{
		protected class State
		{
			public int DnsLookupCount { get; set; }
			internal int VoidLookupCount { get; set; }

			// the number of include and redirect terms, which led to the current record
			internal int NestingDepth { get; set; }

			// the validated names of the client for the %{p} macro, null until they are needed
			internal List<DomainName>? ValidatedNames { get; set; }
		}

		// what macros are expanded for
		private enum MacroTarget
		{
			TermName,
			ExplanationName,
			ExplanationText,
		}

		private const int _maximumNameLength = 253;

		// limits the number of queries with any DnsLookupLimit
		private const int _maximumDnsLookupLimit = 100;

		// limits the recursion with any DnsLookupLimit, so it does not exceed a stack of 256 KB
		private const int _maximumNestingDepth = 20;

		// ReSharper disable once StaticMemberInGenericType
		private static readonly Regex _parseMacroRegex = new Regex(@"(%%|%_|%-|%\{(?<letter>[slodiphcrtvSLODIPHCRTV])(?<count>[0-9]*)(?<reverse>[rR]?)(?<delimiter>[\.\-+,/_=]*)})", RegexOptions.Compiled);

		// the macros %{c}, %{r} and %{t} are only allowed in explanations (RFC 7208, section 7.2)
		// ReSharper disable once StaticMemberInGenericType
		private static readonly Regex _termNameRegex = new Regex(@"^(?>(?:[^%]|%[%_\-]|%\{[slodiphvSLODIPHV](?:0*[1-9][0-9]*)?[rR]?[\.\-+,/_=]*\})*)\z", RegexOptions.Compiled);

		// ReSharper disable once StaticMemberInGenericType
		private static readonly Regex _ip4Regex = new Regex(@"^(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}\z", RegexOptions.Compiled);

		// without brackets and scope, which IPAddress accepts
		// ReSharper disable once StaticMemberInGenericType
		private static readonly Regex _ip6Regex = new Regex(@"^[0-9a-fA-F:\.]+\z", RegexOptions.Compiled);

		/// <summary>
		///   DnsResolver which is used for DNS lookups
		///   <para>Default is a Stub DNS resolver using the local configured upstream servers</para>
		/// </summary>
		public IDnsResolver DnsResolver { get; set; } = new DnsStubResolver();

		/// <summary>
		///   Domain name which was used in HELO/EHLO
		/// </summary>
		public DomainName? HeloDomain { get; set; }

		/// <summary>
		///   IP address of the computer validating the record
		///   <para>Has no effect anymore, as the macro %{c} is the address of the client (RFC 7208, section 7.2)</para>
		/// </summary>
		[Obsolete("Has no effect anymore, as the macro %{c} is the address of the client.")]
		public IPAddress? LocalIP { get; set; }

		/// <summary>
		///   Name of the computer validating the record
		///   <para>Default is the computer name</para>
		/// </summary>
		public DomainName? LocalDomain { get; set; }

		/// <summary>
		///   The maximum number of terms, which cause DNS lookups (RFC 7208, section 4.6.4). Exceeding it results in PermError.
		///   <para>Default is 10. Values above 100 are treated as 100, and more than 20 nested records result in PermError.</para>
		/// </summary>
		public int DnsLookupLimit { get; set; } = 10;

		private int EffectiveDnsLookupLimit => Math.Min(DnsLookupLimit, _maximumDnsLookupLimit);

		/// <summary>
		///   The maximum number of terms, whose DNS lookup has no answer (RFC 7208, section 4.6.4). Exceeding it results in PermError.
		///   <para>
		///     Default is null, no limit. The RFC recommends 2, but this fails also valid mails, as a host, which only has addresses
		///     of the other IP version than the client, has no answer, too.
		///   </para>
		/// </summary>
		public int? VoidLookupLimit { get; set; }

		protected abstract Task<LoadRecordResult> LoadRecordsAsync(DomainName domain, CancellationToken token);

		/// <summary>
		///   Validates the record(s)
		/// </summary>
		/// <param name="ip"> The IP address of the SMTP client that is emitting the mail </param>
		/// <param name="domain"> The domain portion of the "MAIL FROM" or "HELO" identity </param>
		/// <param name="sender"> The "MAIL FROM" or "HELO" identity </param>
		/// <param name="expandExplanation"> A value indicating if the explanation should be retrieved in case of Fail</param>
		/// <returns> The result of the evaluation </returns>
		[Obsolete("Blocks the calling thread while waiting for the DNS responses. Use CheckHostAsync instead.")]
		public ValidationResult CheckHost(IPAddress ip, DomainName domain, string sender, bool expandExplanation = false)
		{
			return CheckHostRootAsync(ip, domain, sender, expandExplanation, default).GetAwaiter().GetResult();
		}

		/// <summary>
		///   Validates the record(s)
		/// </summary>
		/// <param name="ip"> The IP address of the SMTP client that is emitting the mail </param>
		/// <param name="domain"> The domain portion of the "MAIL FROM" or "HELO" identity </param>
		/// <param name="sender"> The "MAIL FROM" or "HELO" identity </param>
		/// <param name="expandExplanation"> A value indicating if the explanation should be retrieved in case of Fail</param>
		/// <returns> The result of the evaluation </returns>
		[Obsolete("Blocks the calling thread while waiting for the DNS responses. Use CheckHostAsync instead.")]
		public ValidationResult CheckHost(IPAddress ip, string domain, string sender, bool expandExplanation = false)
		{
			// a malformed domain results in None (RFC 7208, section 4.3)
			DomainName.TryParse(domain, out DomainName? name);
			return CheckHostRootAsync(ip, name, sender, expandExplanation, default).GetAwaiter().GetResult();
		}

		/// <summary>
		///   Validates the record(s)
		/// </summary>
		/// <param name="ip"> The IP address of the SMTP client that is emitting the mail </param>
		/// <param name="domain"> The domain portion of the "MAIL FROM" or "HELO" identity </param>
		/// <param name="sender"> The "MAIL FROM" or "HELO" identity </param>
		/// <param name="expandExplanation"> A value indicating if the explanation should be retrieved in case of Fail</param>
		/// <param name="token"> The token to monitor cancellation requests. A cancelled evaluation results in TempError. </param>
		/// <returns> The result of the evaluation </returns>
		public Task<ValidationResult> CheckHostAsync(IPAddress ip, DomainName domain, string sender, bool expandExplanation = false, CancellationToken token = default(CancellationToken))
		{
			return CheckHostRootAsync(ip, domain, sender, expandExplanation, token);
		}

		/// <summary>
		///   Validates the record(s)
		/// </summary>
		/// <param name="ip"> The IP address of the SMTP client that is emitting the mail </param>
		/// <param name="domain"> The domain portion of the "MAIL FROM" or "HELO" identity </param>
		/// <param name="sender"> The "MAIL FROM" or "HELO" identity </param>
		/// <param name="expandExplanation"> A value indicating if the explanation should be retrieved in case of Fail</param>
		/// <param name="token"> The token to monitor cancellation requests. A cancelled evaluation results in TempError. </param>
		/// <returns> The result of the evaluation </returns>
		public Task<ValidationResult> CheckHostAsync(IPAddress ip, string domain, string sender, bool expandExplanation = false, CancellationToken token = default(CancellationToken))
		{
			// a malformed domain results in None (RFC 7208, section 4.3)
			DomainName.TryParse(domain, out DomainName? name);
			return CheckHostRootAsync(ip, name, sender, expandExplanation, token);
		}

		protected class LoadRecordResult
		{
			public bool CouldBeLoaded { get; internal set; }
			public T? Record { get; internal set; }
			public SpfQualifier ErrorResult { get; internal set; }
		}

		private async Task<ValidationResult> CheckHostRootAsync(IPAddress ip, DomainName? domain, string sender, bool expandExplanation, CancellationToken token)
		{
			try
			{
				return await CheckHostInternalAsync(ip, domain, sender, expandExplanation, new State(), token).ConfigureAwait(false);
			}
			catch (OperationCanceledException) when (token.IsCancellationRequested)
			{
				// not evaluated completely, so the result of the remaining terms must not be used
				return new ValidationResult() { Result = SpfQualifier.TempError, Explanation = String.Empty };
			}
		}

		private async Task<ValidationResult> CheckHostInternalAsync(IPAddress ip, DomainName? domain, string sender, bool expandExplanation, State state, CancellationToken token)
		{
			// IPv4 clients of dual mode sockets are treated as IPv4 (RFC 7208, section 5)
			if (ip is { IsIPv4MappedToIPv6: true })
				ip = ip.MapToIPv4();

			if ((domain == null) || (domain.IsRoot))
			{
				return new ValidationResult() { Result = SpfQualifier.None, Explanation = String.Empty };
			}

			if (String.IsNullOrEmpty(sender))
			{
				sender = "postmaster@unknown";
			}
			else if (!sender.Contains('@'))
			{
				sender = "postmaster@" + sender;
			}
			else if (sender[0] == '@')
			{
				sender = "postmaster" + sender;
			}

			LoadRecordResult loadResult = await LoadRecordsAsync(domain, token).ConfigureAwait(false);

			if (!loadResult.CouldBeLoaded)
			{
				return new ValidationResult() { Result = loadResult.ErrorResult, Explanation = String.Empty };
			}

			T record = loadResult.Record!;

			if ((record.Terms == null) || (record.Terms.Count == 0))
				return new ValidationResult() { Result = SpfQualifier.Neutral, Explanation = String.Empty };

			if (record.Terms.OfType<SpfModifier>().GroupBy(m => m.Type).Where(g => (g.Key == SpfModifierType.Exp) || (g.Key == SpfModifierType.Redirect)).Any(g => g.Count() > 1))
				return new ValidationResult() { Result = SpfQualifier.PermError, Explanation = String.Empty };

			// a syntax error anywhere in the record, also after a matching mechanism (RFC 7208, section 4.6)
			if (!record.Terms.All(IsValidTerm))
				return new ValidationResult() { Result = SpfQualifier.PermError, Explanation = String.Empty };

			ValidationResult result = new ValidationResult() { Result = loadResult.ErrorResult };

			#region Evaluate mechanism
			foreach (SpfMechanism mechanism in record.Terms.OfType<SpfMechanism>())
			{
				SpfQualifier qualifier = await CheckMechanismAsync(mechanism, ip, domain, sender, state, token).ConfigureAwait(false);

				if (qualifier != SpfQualifier.None)
				{
					result.Result = qualifier;
					break;
				}
			}
			#endregion

			#region Evaluate modifiers
			if (result.Result == SpfQualifier.None)
			{
				SpfModifier? redirectModifier = record.Terms.OfType<SpfModifier>().FirstOrDefault(m => m.Type == SpfModifierType.Redirect);
				if (redirectModifier != null)
				{
					if (++state.DnsLookupCount > EffectiveDnsLookupLimit)
						return new ValidationResult() { Result = SpfQualifier.PermError, Explanation = String.Empty };

					DomainName? redirectDomain = (await ExpandDomainAsync(redirectModifier.Domain ?? string.Empty, ip, domain, sender, state, token).ConfigureAwait(false)).Name;

					if ((redirectDomain == null) || (redirectDomain.IsRoot) || (redirectDomain.Equals(domain)) || (state.NestingDepth >= _maximumNestingDepth))
					{
						result.Result = SpfQualifier.PermError;
					}
					else
					{
						state.NestingDepth++;
						result = await CheckHostInternalAsync(ip, redirectDomain, sender, expandExplanation, state, token).ConfigureAwait(false);
						state.NestingDepth--;

						if (result.Result == SpfQualifier.None)
							result.Result = SpfQualifier.PermError;
					}
				}
			}
			else if ((result.Result == SpfQualifier.Fail) && expandExplanation)
			{
				SpfModifier? expModifier = record?.Terms?.OfType<SpfModifier>().FirstOrDefault(m => m.Type == SpfModifierType.Exp);
				if (expModifier != null)
				{
					try
					{
						DomainName? target = (await ExpandDomainAsync(expModifier.Domain, ip, domain, sender, state, token, MacroTarget.ExplanationName).ConfigureAwait(false)).Name;

						if ((target == null) || target.IsRoot)
						{
							result.Explanation = String.Empty;
						}
						else
						{
							DnsResolveResult<TxtRecord> dnsResult = await ResolveDnsAsync<TxtRecord>(target, RecordType.Txt, token).ConfigureAwait(false);
							if ((dnsResult != null) && (dnsResult.ReturnCode == ReturnCode.NoError))
							{
								// more than one record or a text, which is not ASCII or has a syntax error, gives no explanation (RFC 7208, section 6.2)
								if (dnsResult.Records?.Count == 1)
								{
									string? explanation = (await ExpandMacroAsync(dnsResult.Records[0].TextData, ip, domain, sender, state, MacroTarget.ExplanationText, token).ConfigureAwait(false)).Text;
									result.Explanation = (explanation != null) && explanation.All(c => c <= 127) ? explanation : String.Empty;
								}
								else
								{
									result.Explanation = String.Empty;
								}
							}
						}
					}
					catch (OperationCanceledException) when (token.IsCancellationRequested)
					{
						// the result is already known, only its explanation is missing
					}
				}
			}
			#endregion

			if (result.Result == SpfQualifier.None)
				result.Result = SpfQualifier.Neutral;

			return result;
		}

		// the modifier exp and unknown modifiers do not affect the result, so errors in their value are ignored
		private static bool IsValidTerm(SpfTerm term)
		{
			switch (term)
			{
				case SpfModifier modifier:
					return (modifier.Type != SpfModifierType.Redirect) || IsValidTermName(modifier.Domain);

				case SpfMechanism mechanism:
					switch (mechanism.Type)
					{
						case SpfMechanismType.All:
							return String.IsNullOrEmpty(mechanism.Domain);

						case SpfMechanismType.A:
						case SpfMechanismType.Mx:
						case SpfMechanismType.Ptr:
							return String.IsNullOrEmpty(mechanism.Domain) || IsValidTermName(mechanism.Domain);

						case SpfMechanismType.Exists:
						case SpfMechanismType.Include:
							return IsValidTermName(mechanism.Domain);

						case SpfMechanismType.Ip4:
						case SpfMechanismType.Ip6:
							return TryParseAddress(mechanism, out _);

						default:
							return false;
					}

				default:
					return true;
			}
		}

		private static bool IsValidTermName(string? name)
		{
			return !String.IsNullOrEmpty(name) && _termNameRegex.IsMatch(name!);
		}

		// parses the address of the mechanisms ip4 and ip6 and checks its prefix length (RFC 7208, section 5.6)
		private static bool TryParseAddress(SpfMechanism mechanism, out IPAddress? address)
		{
			bool isIp6 = (mechanism.Type == SpfMechanismType.Ip6);
			string text = mechanism.Domain ?? String.Empty;

			if (!(isIp6 ? _ip6Regex : _ip4Regex).IsMatch(text)
			    || !IPAddress.TryParse(text, out address)
			    || (address.AddressFamily != (isIp6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork)))
			{
				address = null;
				return false;
			}

			return !mechanism.Prefix.HasValue || ((mechanism.Prefix.Value >= 0) && (mechanism.Prefix.Value <= (isIp6 ? 128 : 32)));
		}

		private async Task<SpfQualifier> CheckMechanismAsync(SpfMechanism mechanism, IPAddress ip, DomainName domain, string sender, State state, CancellationToken token)
		{
			switch (mechanism.Type)
			{
				case SpfMechanismType.All:
					return mechanism.Qualifier;

				case SpfMechanismType.A:
					if (++state.DnsLookupCount > EffectiveDnsLookupLimit)
						return SpfQualifier.PermError;

					(DomainName? aMechanismDomain, SpfQualifier aError) = await ExpandMechanismDomainAsync(mechanism, ip, domain, sender, state, token).ConfigureAwait(false);
					if (aMechanismDomain == null)
						return aError;

					bool? isAMatch = await IsIpMatchAsync(aMechanismDomain, ip, mechanism.Prefix, mechanism.Prefix6, token, state).ConfigureAwait(false);
					if (!isAMatch.HasValue)
						return SpfQualifier.TempError;

					if (state.VoidLookupCount > VoidLookupLimit)
						return SpfQualifier.PermError;

					if (isAMatch.Value)
					{
						return mechanism.Qualifier;
					}

					break;

				case SpfMechanismType.Mx:
					if (++state.DnsLookupCount > EffectiveDnsLookupLimit)
						return SpfQualifier.PermError;

					(DomainName? mxMechanismDomain, SpfQualifier mxError) = await ExpandMechanismDomainAsync(mechanism, ip, domain, sender, state, token).ConfigureAwait(false);
					if (mxMechanismDomain == null)
						return mxError;

					DnsResolveResult<MxRecord> dnsMxResult = await ResolveDnsAsync<MxRecord>(mxMechanismDomain, RecordType.Mx, token).ConfigureAwait(false);
					if ((dnsMxResult == null) || ((dnsMxResult.ReturnCode != ReturnCode.NoError) && (dnsMxResult.ReturnCode != ReturnCode.NxDomain)))
						return SpfQualifier.TempError;

					if (dnsMxResult.Records!.Count == 0 && ++state.VoidLookupCount > VoidLookupLimit)
						return SpfQualifier.PermError;

					int mxCheckedCount = 0;

					foreach (MxRecord mxRecord in dnsMxResult.Records)
					{
						// one address query for each mail exchanger, more than 10 are an error
						if (++mxCheckedCount > 10)
							return SpfQualifier.PermError;

						// the void lookup limit is for the terms, so only for the MX query
						bool? isMxMatch = await IsIpMatchAsync(mxRecord.ExchangeDomainName, ip, mechanism.Prefix, mechanism.Prefix6, token).ConfigureAwait(false);
						if (!isMxMatch.HasValue)
							return SpfQualifier.TempError;

						if (isMxMatch.Value)
						{
							return mechanism.Qualifier;
						}
					}

					break;

				case SpfMechanismType.Ip4:
				case SpfMechanismType.Ip6:
					if (TryParseAddress(mechanism, out IPAddress? compareAddress))
					{
						if (ip.AddressFamily != compareAddress!.AddressFamily)
							return SpfQualifier.None;

						if (mechanism.Prefix.HasValue)
						{
							if (ip.GetNetworkAddress(mechanism.Prefix.Value).Equals(compareAddress.GetNetworkAddress(mechanism.Prefix.Value)))
							{
								return mechanism.Qualifier;
							}
						}
						else if (ip.Equals(compareAddress))
						{
							return mechanism.Qualifier;
						}
					}
					else
					{
						return SpfQualifier.PermError;
					}

					break;

				case SpfMechanismType.Ptr:
					if (++state.DnsLookupCount > EffectiveDnsLookupLimit)
						return SpfQualifier.PermError;

					(DomainName? ptrMechanismDomain, SpfQualifier ptrError) = await ExpandMechanismDomainAsync(mechanism, ip, domain, sender, state, token).ConfigureAwait(false);
					if (ptrMechanismDomain == null)
						return ptrError;

					DnsResolveResult<PtrRecord> dnsPtrResult = await ResolveDnsAsync<PtrRecord>(ip.GetReverseLookupDomain(), RecordType.Ptr, token).ConfigureAwait(false);
					// the mechanism does not match, if the lookup fails (RFC 7208, section 5.5)
					if ((dnsPtrResult == null) || ((dnsPtrResult.ReturnCode != ReturnCode.NoError) && (dnsPtrResult.ReturnCode != ReturnCode.NxDomain)))
						return SpfQualifier.None;

					if (dnsPtrResult.Records!.Count == 0 && ++state.VoidLookupCount > VoidLookupLimit)
						return SpfQualifier.PermError;

					int ptrCheckedCount = 0;
					foreach (PtrRecord ptrRecord in dnsPtrResult.Records)
					{
						// the names after the tenth are ignored, as they are controlled by the owner of the address
						if (++ptrCheckedCount > 10)
							break;

						bool? isPtrMatch = await IsIpMatchAsync(ptrRecord.PointerDomainName, ip, null, null, token).ConfigureAwait(false);
						if (isPtrMatch.HasValue && isPtrMatch.Value)
						{
							if (ptrRecord.PointerDomainName.Equals(ptrMechanismDomain) || (ptrRecord.PointerDomainName.IsSubDomainOf(ptrMechanismDomain)))
								return mechanism.Qualifier;
						}
					}

					break;

				case SpfMechanismType.Exists:
					if (++state.DnsLookupCount > EffectiveDnsLookupLimit)
						return SpfQualifier.PermError;

					if (String.IsNullOrEmpty(mechanism.Domain))
						return SpfQualifier.PermError;

					(DomainName? existsMechanismDomain, SpfQualifier existsError) = await ExpandMechanismDomainAsync(mechanism, ip, domain, sender, state, token).ConfigureAwait(false);
					if (existsMechanismDomain == null)
						return existsError;

					DnsResolveResult<ARecord> dnsAResult = await ResolveDnsAsync<ARecord>(existsMechanismDomain, RecordType.A, token).ConfigureAwait(false);
					if ((dnsAResult == null) || ((dnsAResult.ReturnCode != ReturnCode.NoError) && (dnsAResult.ReturnCode != ReturnCode.NxDomain)))
						return SpfQualifier.TempError;

					if ((dnsAResult.Records?.Count ?? 0) == 0 && ++state.VoidLookupCount > VoidLookupLimit)
						return SpfQualifier.PermError;

					if (dnsAResult.Records?.Count(record => (record.RecordType == RecordType.A)) > 0)
					{
						return mechanism.Qualifier;
					}

					break;

				case SpfMechanismType.Include:
					if (++state.DnsLookupCount > EffectiveDnsLookupLimit)
						return SpfQualifier.PermError;

					if (String.IsNullOrEmpty(mechanism.Domain))
						return SpfQualifier.PermError;

					(DomainName? includeMechanismDomain, SpfQualifier includeError) = await ExpandMechanismDomainAsync(mechanism, ip, domain, sender, state, token).ConfigureAwait(false);
					if (includeMechanismDomain == null)
						return includeError;

					if (includeMechanismDomain.Equals(domain) || (state.NestingDepth >= _maximumNestingDepth))
						return SpfQualifier.PermError;

					state.NestingDepth++;
					var includeResult = await CheckHostInternalAsync(ip, includeMechanismDomain, sender, false, state, token).ConfigureAwait(false);
					state.NestingDepth--;

					switch (includeResult.Result)
					{
						case SpfQualifier.Pass:
							return mechanism.Qualifier;

						case SpfQualifier.Fail:
						case SpfQualifier.SoftFail:
						case SpfQualifier.Neutral:
							return SpfQualifier.None;

						case SpfQualifier.TempError:
							return SpfQualifier.TempError;

						case SpfQualifier.PermError:
						case SpfQualifier.None:
							return SpfQualifier.PermError;
					}

					break;

				default:
					return SpfQualifier.PermError;
			}

			return SpfQualifier.None;
		}

		// counts a void lookup, if a state is passed
		private Task<bool?> IsIpMatchAsync(DomainName domain, IPAddress ipAddress, int? prefix4, int? prefix6, CancellationToken token, State? state = null)
		{
			if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
			{
				if (prefix6.HasValue)
					ipAddress = ipAddress.GetNetworkAddress(prefix6.Value);

				return IsIpMatchAsync<AaaaRecord>(domain, ipAddress, prefix6, RecordType.Aaaa, token, state);
			}
			else
			{
				if (prefix4.HasValue)
					ipAddress = ipAddress.GetNetworkAddress(prefix4.Value);

				return IsIpMatchAsync<ARecord>(domain, ipAddress, prefix4, RecordType.A, token, state);
			}
		}

		private async Task<bool?> IsIpMatchAsync<TRecord>(DomainName domain, IPAddress ipAddress, int? prefix, RecordType recordType, CancellationToken token, State? state)
			where TRecord : DnsRecordBase, IAddressRecord
		{
			DnsResolveResult<TRecord> dnsResult = await ResolveDnsAsync<TRecord>(domain, recordType, token).ConfigureAwait(false);
			if ((dnsResult == null) || ((dnsResult.ReturnCode != ReturnCode.NoError) && (dnsResult.ReturnCode != ReturnCode.NxDomain)))
				return null;

			if (state != null && dnsResult.Records!.Count == 0)
				state.VoidLookupCount++;

			foreach (var dnsRecord in dnsResult.Records!)
			{
				if (prefix.HasValue)
				{
					if (ipAddress.Equals(dnsRecord.Address.GetNetworkAddress(prefix.Value)))
						return true;
				}
				else
				{
					if (ipAddress.Equals(dnsRecord.Address))
						return true;
				}
			}

			return false;
		}

		protected class DnsResolveResult<TRecord>
			where TRecord : DnsRecordBase
		{
			public ReturnCode ReturnCode { get; }
			public List<TRecord>? Records { get; }

			public DnsResolveResult(ReturnCode returnCode, List<TRecord>? records)
			{
				ReturnCode = returnCode;
				Records = records;
			}
		}

		protected async Task<DnsResolveResult<TRecord>> ResolveDnsAsync<TRecord>(DomainName domain, RecordType recordType, CancellationToken token)
			where TRecord : DnsRecordBase
		{
			try
			{
				var records = await DnsResolver.ResolveAsync<TRecord>(domain, recordType, token: token).ConfigureAwait(false);
				return new DnsResolveResult<TRecord>(ReturnCode.NoError, records);
			}
			catch
			{
				// a cancelled query says nothing about the name, unlike a failed one
				token.ThrowIfCancellationRequested();

				return new DnsResolveResult<TRecord>(ReturnCode.ServerFailure, null);
			}
		}

		// the methods for the expansion return null and the result of the term, if the expansion is not possible:
		// None, if the term does not match, as the sender controls the name, or PermError
		private async Task<(DomainName? Name, SpfQualifier Error)> ExpandMechanismDomainAsync(SpfMechanism mechanism, IPAddress ip, DomainName domain, string sender, State state, CancellationToken token)
		{
			if (String.IsNullOrEmpty(mechanism.Domain))
				return (domain, SpfQualifier.None);

			return await ExpandDomainAsync(mechanism.Domain!, ip, domain, sender, state, token).ConfigureAwait(false);
		}

		private async Task<(DomainName? Name, SpfQualifier Error)> ExpandDomainAsync(string pattern, IPAddress ip, DomainName domain, string sender, State state, CancellationToken token, MacroTarget target = MacroTarget.TermName)
		{
			(string? expanded, SpfQualifier error) = await ExpandMacroAsync(pattern, ip, domain, sender, state, target, token).ConfigureAwait(false);

			if (expanded == null)
				return (null, error);

			if (expanded.Length == 0)
				return (DomainName.Root, SpfQualifier.None);

			// names, which are too long, are shortened from the left (RFC 7208, section 7.3)
			int maximumLength = expanded.EndsWith(".", StringComparison.Ordinal) ? _maximumNameLength + 1 : _maximumNameLength;
			while (expanded.Length > maximumLength)
			{
				int firstDot = expanded.IndexOf('.');
				if (firstDot < 0)
					return (null, SpfQualifier.None);

				expanded = expanded.Substring(firstDot + 1);
			}

			return DomainName.TryParse(expanded, out DomainName? name) ? (name, SpfQualifier.None) : (null, SpfQualifier.None);
		}

		private async Task<(string? Text, SpfQualifier Error)> ExpandMacroAsync(string pattern, IPAddress ip, DomainName domain, string sender, State state, MacroTarget target, CancellationToken token)
		{
			if (String.IsNullOrEmpty(pattern))
				return (String.Empty, SpfQualifier.None);

			Match match = _parseMacroRegex.Match(pattern);
			if (!match.Success)
			{
				return (pattern.IndexOf('%') < 0) ? (pattern, SpfQualifier.None) : (null, SpfQualifier.PermError);
			}

			StringBuilder sb = new StringBuilder();
			int pos = 0;
			do
			{
				if (match.Index != pos)
				{
					// a percent sign, which is not part of a macro, is a syntax error (RFC 7208, section 7.3)
					if (pattern.IndexOf('%', pos, match.Index - pos) >= 0)
						return (null, SpfQualifier.PermError);

					sb.Append(pattern, pos, match.Index - pos);
				}

				pos = match.Index + match.Length;

				(string? expanded, SpfQualifier error) = await ExpandMacroAsync(match, ip, domain, sender, state, target, token).ConfigureAwait(false);
				if (expanded == null)
					return (null, error);

				sb.Append(expanded);
				match = match.NextMatch();
			} while (match.Success);

			if (pos < pattern.Length)
			{
				if (pattern.IndexOf('%', pos) >= 0)
					return (null, SpfQualifier.PermError);

				sb.Append(pattern, pos, pattern.Length - pos);
			}

			return (sb.ToString(), SpfQualifier.None);
		}

		private async Task<(string? Text, SpfQualifier Error)> ExpandMacroAsync(Match pattern, IPAddress ip, DomainName domain, string sender, State state, MacroTarget target, CancellationToken token)
		{
			switch (pattern.Value)
			{
				case "%%":
					return ("%", SpfQualifier.None);
				case "%_":
					return (" ", SpfQualifier.None);
				case "%-":
					return ("%20", SpfQualifier.None);

				default:
					string letter;
					string macro = pattern.Groups["letter"].Value;
					switch (macro.ToLowerInvariant())
					{
						case "s":
							if ((target != MacroTarget.ExplanationText) && !IsLocalPartAscii(sender))
								return (null, SpfQualifier.None);

							letter = (target == MacroTarget.ExplanationText) ? sender : ToALabels(sender);
							break;
						case "l":
							if ((target != MacroTarget.ExplanationText) && !IsLocalPartAscii(sender))
								return (null, SpfQualifier.None);

							// no boundary check needed, sender is validated on start of CheckHost
							letter = sender.Substring(0, sender.LastIndexOf('@'));
							break;
						case "o":
							// no boundary check needed, sender is validated on start of CheckHost
							string convertedSender = (target == MacroTarget.ExplanationText) ? sender : ToALabels(sender);
							letter = convertedSender.Substring(convertedSender.LastIndexOf('@') + 1);
							break;
						case "d":
							letter = domain.ToString(false);
							break;
						case "i":
							letter = (ip.AddressFamily == AddressFamily.InterNetworkV6)
								// the hexadecimal digits separated by dots
								? String.Join(".", ip.GetAddressBytes().SelectMany(b => b.ToString("x2")))
								: String.Join(".", ip.GetAddressBytes().Select(b => b.ToString()));
							break;
						case "p":
							// the lookup is counted like a term (RFC 7208, section 4.6.4), but not for an explanation, as the result is already known
							if ((target == MacroTarget.TermName) && (state.ValidatedNames == null) && (++state.DnsLookupCount > EffectiveDnsLookupLimit))
								return (null, SpfQualifier.PermError);

							state.ValidatedNames ??= await GetValidatedNamesAsync(ip, token).ConfigureAwait(false);

							// the domain itself, otherwise a subdomain, otherwise any name (RFC 7208, section 7.3)
							DomainName? ptrName = state.ValidatedNames.FirstOrDefault(n => n.Equals(domain))
							                      ?? state.ValidatedNames.FirstOrDefault(n => n.IsSubDomainOf(domain))
							                      ?? state.ValidatedNames.FirstOrDefault();

							letter = ptrName?.ToString(false) ?? "unknown";
							break;
						case "v":
							letter = (ip.AddressFamily == AddressFamily.InterNetworkV6) ? "ip6" : "in-addr";
							break;
						case "h":
							letter = HeloDomain?.ToString(false) ?? "unknown";
							break;
						case "c":
							letter = ip.ToString();
							break;
						case "r":
							letter = LocalDomain?.ToString(false) ?? System.Net.Dns.GetHostName();
							break;
						case "t":
							letter = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
							break;
						default:
							return (null, SpfQualifier.PermError);
					}

					bool isEscaped = Char.IsUpper(macro[0]);

					// only letter
					if (pattern.Value.Length == 4)
						return (isEscaped ? EscapeUrl(letter) : letter, SpfQualifier.None);

					char[] delimiters = pattern.Groups["delimiter"].Value.ToCharArray();
					if (delimiters.Length == 0)
						delimiters = new[] { '.' };

					string[] parts = letter.Split(delimiters);

					if (pattern.Groups["reverse"].Length > 0)
						parts = Enumerable.Reverse(parts).ToArray();

					int count = Int32.MaxValue;
					if (!String.IsNullOrEmpty(pattern.Groups["count"].Value) && Int32.TryParse(pattern.Groups["count"].Value, out int parsedCount))
					{
						// a larger count uses all parts
						count = parsedCount;
					}

					if (count < 1)
						return (null, SpfQualifier.PermError);

					count = Math.Min(count, parts.Length);

					string joined = String.Join(".", parts, (parts.Length - count), count);
					return (isEscaped ? EscapeUrl(joined) : joined, SpfQualifier.None);
			}
		}

		// the names of the PTR records, which have the address of the client (RFC 7208, section 5.5)
		private async Task<List<DomainName>> GetValidatedNamesAsync(IPAddress ip, CancellationToken token)
		{
			var names = new List<DomainName>();

			DnsResolveResult<PtrRecord> dnsResult = await ResolveDnsAsync<PtrRecord>(ip.GetReverseLookupDomain(), RecordType.Ptr, token).ConfigureAwait(false);
			if ((dnsResult == null) || ((dnsResult.ReturnCode != ReturnCode.NoError) && (dnsResult.ReturnCode != ReturnCode.NxDomain)))
				return names;

			foreach (PtrRecord ptrRecord in dnsResult.Records!.Take(10))
			{
				if (await IsIpMatchAsync(ptrRecord.PointerDomainName, ip, null, null, token).ConfigureAwait(false) == true)
					names.Add(ptrRecord.PointerDomainName);
			}

			return names;
		}

		// escapes all characters, which are not unreserved (RFC 7208, section 7.3)
		private static string EscapeUrl(string s)
		{
			var sb = new StringBuilder();

			foreach (byte b in Encoding.UTF8.GetBytes(s))
			{
				char c = (char) b;

				if (((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z')) || ((c >= '0') && (c <= '9')) || (c == '-') || (c == '.') || (c == '_') || (c == '~'))
					sb.Append(c);
				else
					sb.Append('%').Append(b.ToString("X2"));
			}

			return sb.ToString();
		}

		// terms with a local part, which is not ASCII, do not match (RFC 8616, section 4)
		private static bool IsLocalPartAscii(string sender)
		{
			return sender.Substring(0, sender.LastIndexOf('@')).All(c => c <= 127);
		}

		// converts the domain of the sender (RFC 8616, section 4)
		private static string ToALabels(string sender)
		{
			int domainOffset = sender.LastIndexOf('@') + 1;
			string senderDomain = sender.Substring(domainOffset);

			if (senderDomain.All(c => c <= 127) || !DomainName.TryParse(senderDomain, out DomainName? name))
				return sender;

			return sender.Substring(0, domainOffset) + name!.ToString(false);
		}
	}
}