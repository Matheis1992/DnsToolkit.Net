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
using System.Text;
using System.Text.RegularExpressions;

namespace DnsToolkit.Net.Spf
{
	/// <summary>
	///   Represents a single term of a SPF record
	/// </summary>
	public abstract class SpfTerm
	{
		// a slash within a macro is a delimiter and not the start of a prefix length
		private static readonly Regex _parseMechanismRegex = new Regex(@"^(\s)*(?<qualifier>[~+?-]?)(?<type>[a-z0-9]+)(:(?<domain>(?>(%%|%\{[a-z][0-9]*r?[\.\-+,/_=]*\}|[^/])+)))?(/(?<prefix>[0-9]+))?(//(?<prefix6>[0-9]+))?(\s)*$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
		private static readonly Regex _parseModifierRegex = new Regex(@"^(\s)*(?<type>[a-z][a-z0-9\-_\.]*)=(?<domain>[^\s]*)(\s)*$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

		internal static bool TryParse(string s, out SpfTerm? value)
		{
			if (String.IsNullOrEmpty(s))
			{
				value = null;
				return false;
			}

			#region Parse Mechanism
			Match match = _parseMechanismRegex.Match(s);
			if (match.Success)
			{
				SpfQualifier qualifier;
				switch (match.Groups["qualifier"].Value)
				{
					case "+":
						qualifier = SpfQualifier.Pass;
						break;
					case "-":
						qualifier = SpfQualifier.Fail;
						break;
					case "~":
						qualifier = SpfQualifier.SoftFail;
						break;
					case "?":
						qualifier = SpfQualifier.Neutral;
						break;

					default:
						qualifier = SpfQualifier.Pass;
						break;
				}

				SpfMechanismType type = EnumHelper<SpfMechanismType>.TryParse(match.Groups["type"].Value, true, out SpfMechanismType t) ? t : SpfMechanismType.Unknown;
				string? domain = match.Groups["domain"].Value;

				// null, if the mechanism has no such prefix length
				int? maximumPrefix = null;
				int? maximumPrefix6 = null;

				switch (type)
				{
					case SpfMechanismType.A:
					case SpfMechanismType.Mx:
						maximumPrefix = 32;
						maximumPrefix6 = 128;
						break;

					case SpfMechanismType.Ip4:
					case SpfMechanismType.Ip6:
						// the range depends on the address and is checked at the evaluation
						maximumPrefix = Int32.MaxValue;
						break;
				}

				if (!TryParsePrefix(match.Groups["prefix"], maximumPrefix, out int? prefix)
				    || !TryParsePrefix(match.Groups["prefix6"], maximumPrefix6, out int? prefix6))
				{
					value = null;
					return false;
				}

				value = new SpfMechanism(qualifier, type, domain, prefix, prefix6);
				return true;
			}
			#endregion

			#region Parse Modifier
			match = _parseModifierRegex.Match(s);
			if (match.Success)
			{
				SpfModifierType type = EnumHelper<SpfModifierType>.TryParse(match.Groups["type"].Value, true, out SpfModifierType t) ? t : SpfModifierType.Unknown;
				string domain = match.Groups["domain"].Value;

				// only unknown modifiers may be empty
				if ((type != SpfModifierType.Unknown) && String.IsNullOrEmpty(domain))
				{
					value = null;
					return false;
				}

				value = new SpfModifier(type, domain);
				return true;
			}
			#endregion

			value = null;
			return false;
		}

		private static bool TryParsePrefix(Group group, int? maximum, out int? prefix)
		{
			prefix = null;

			if (!group.Success)
				return true;

			if (!maximum.HasValue || !Int32.TryParse(group.Value, out int parsed) || (parsed > maximum.Value))
				return false;

			prefix = parsed;
			return true;
		}
	}
}