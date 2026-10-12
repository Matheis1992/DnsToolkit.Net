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
///   <para>
///     Chooses the names of the queries, which follow the referrals to a name, so every server only gets the name up to one
///     label below its zone instead of the full name
///   </para>
///   <para>
///     Defined in
///     <a href="https://www.rfc-editor.org/rfc/rfc9156.html">RFC 9156</a>.
///   </para>
/// </summary>
internal sealed class QNameMinimiser
{
	/// <summary>
	///   The limit of minimised queries for a name (MAX_MINIMISE_COUNT of RFC 9156), so a name with many labels does not
	///   cause a query for every label
	/// </summary>
	internal const int MAX_MINIMISED_QUERIES = 10;

	private readonly DomainName _name;
	private readonly RecordType _recordType;
	private bool _isEnabled;
	private int _minimisedQueries;
	private int _answeredLabelCount;

	public QNameMinimiser(DomainName name, RecordType recordType, bool isEnabled)
	{
		_name = name;
		_recordType = recordType;
		// a DS record is queried at the parent zone, which already is the server of the name
		_isEnabled = isEnabled && (recordType != RecordType.Ds);
	}

	/// <summary>
	///   The name and type of the next query to the servers of the zone
	/// </summary>
	public (DomainName Name, RecordType RecordType) GetQuery(DomainName zone)
	{
		if (_isEnabled && (_minimisedQueries < MAX_MINIMISED_QUERIES))
		{
			// one label below the zone, or below the last name, which the servers of the zone answered without a referral
			var labelCount = Math.Max(zone.LabelCount, _answeredLabelCount) + 1;
			if (labelCount < _name.LabelCount)
			{
				_minimisedQueries++;
				// the type A, as some servers answer queries of the type NS wrongly (RFC 9156, section 3)
				return (_name.GetParentName(_name.LabelCount - labelCount), RecordType.A);
			}
		}

		return (_name, _recordType);
	}

	/// <summary>
	///   Handles an authoritative answer to a minimised query. The servers of the zone are responsible for the name as well,
	///   so the next query to them gets one label more.
	/// </summary>
	public void OnAuthoritativeAnswer(DomainName queryName, DnsMessage message)
	{
		// Some servers answer an empty non-terminal with NXDOMAIN, and an alias redirects the names below of it only with
		// DNAME, so the full name is sent instead of guessing (the relaxed mode of RFC 9156, section 2.3)
		if ((message.ReturnCode != ReturnCode.NoError) || message.AnswerRecords.Any(x => x.Name.Equals(queryName) && ((x.RecordType == RecordType.CName) || (x.RecordType == RecordType.DName))))
		{
			Stop();
			return;
		}

		_answeredLabelCount = queryName.LabelCount;
	}

	/// <summary>
	///   Sends the full name in all further queries, e.g. as a server answered a minimised query with an error
	/// </summary>
	public void Stop()
	{
		_isEnabled = false;
	}
}
