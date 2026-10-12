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
	///   The limit of iterations for a name, including the query of the full name (MAX_MINIMISE_COUNT of RFC 9156), so a name
	///   with many labels does not cause a query for every label
	/// </summary>
	internal const int MAX_MINIMISE_COUNT = 10;

	/// <summary>
	///   The number of the first iterations, which add one label each (MINIMISE_ONE_LAB of RFC 9156). The later ones add
	///   several labels, so the full name is reached within <see cref="MAX_MINIMISE_COUNT" /> iterations.
	/// </summary>
	internal const int MINIMISE_ONE_LAB = 4;

	private readonly DomainName _name;
	private readonly RecordType _recordType;
	private bool _isEnabled;
	private int _iterations;
	private int _answeredLabelCount;

	public QNameMinimiser(DomainName name, RecordType recordType, bool isEnabled)
	{
		_name = name;
		_recordType = recordType;
		// a DS record is queried at the parent zone, the queries up to it are minimised like the others (RFC 9156, section 3)
		_isEnabled = isEnabled;
	}

	/// <summary>
	///   The name and type of the next query to the servers of the zone. For a DS record, the zone is the one of the parent.
	/// </summary>
	public (DomainName Name, RecordType RecordType) GetQuery(DomainName zone)
	{
		if (_isEnabled)
		{
			// below the zone, or below the last name, which the servers of the zone answered without a referral
			var exposedLabelCount = Math.Max(zone.LabelCount, _answeredLabelCount);
			var labelCount = exposedLabelCount + GetLabelsToAdd(_name.LabelCount - exposedLabelCount);
			_iterations++;

			if (labelCount < _name.LabelCount)
			{
				// the type A, as it causes the least problems with servers and middleboxes (RFC 9156, section 2.1)
				return (_name.GetParentName(_name.LabelCount - labelCount), RecordType.A);
			}
		}

		return (_name, _recordType);
	}

	/// <summary>
	///   The number of labels to add in the next iteration (RFC 9156, section 2.3): one in the first iterations, later the
	///   hidden labels divided by the remaining iterations, so the remainder is added in the last ones. For 18 labels, these
	///   are 1, 1, 1, 1, 2, 2, 2, 2, 3, 3.
	/// </summary>
	private int GetLabelsToAdd(int hiddenLabelCount)
	{
		var iteration = _iterations + 1;
		if (iteration <= MINIMISE_ONE_LAB)
			return 1;

		var remainingIterations = MAX_MINIMISE_COUNT - iteration + 1;
		if (remainingIterations <= 1)
			return hiddenLabelCount;

		return Math.Max(1, hiddenLabelCount / remainingIterations);
	}

	/// <summary>
	///   Handles an authoritative answer to a minimised query (RFC 9156, section 3, step 6)
	/// </summary>
	/// <returns> Whether the answer also denies the full name, so it is the answer to the original query </returns>
	public bool OnAuthoritativeAnswer(DomainName queryName, DnsMessage message)
	{
		// the names below of a nonexistent name do not exist either (RFC 8020)
		if (message.ReturnCode == ReturnCode.NxDomain)
			return true;

		// A DNAME redirects the names below of its owner, so the full name has to be resolved from the start. Its query to
		// the servers of the zone returns the CNAME, which they synthesize for it. A CNAME only redirects its own name, the
		// names below of it still exist on the servers of the zone.
		if (message.AnswerRecords.Any(x => (x.RecordType == RecordType.DName) && _name.IsSubDomainOf(x.Name)))
		{
			_isEnabled = false;
			return false;
		}

		// the name exists without a zone cut, so the servers of the zone get the next query with more labels
		_answeredLabelCount = queryName.LabelCount;
		return false;
	}

	/// <summary>
	///   Lets the next query be the same as the last one, e.g. to another server of the zone after a timeout or an error
	///   (RFC 9156, section 3, step 6)
	/// </summary>
	public void RepeatLastQuery()
	{
		if (_iterations > 0)
			_iterations--;
	}
}
