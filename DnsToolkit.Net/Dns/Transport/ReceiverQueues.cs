#region Copyright and License
// Copyright 2010..2024 Alexander Reinert
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

namespace DnsToolkit.Net.Dns;

/// <summary>
///   The receivers of responses on a pipelined connection, grouped by the identification of the query.
///   Queries with the same identification (transaction id and question) are interchangeable, so their receivers
///   are kept in the order of registration. Not thread safe, the caller has to lock.
/// </summary>
internal sealed class ReceiverQueues<TReceiver>
	where TReceiver : class
{
	private readonly Dictionary<DnsMessageIdentification, List<TReceiver>> _queues = new();

	/// <summary>
	///   The number of receivers of all identifications
	/// </summary>
	public int Count { get; private set; }

	public void Add(DnsMessageIdentification identification, TReceiver receiver)
	{
		if (!_queues.TryGetValue(identification, out var queue))
		{
			queue = new List<TReceiver>(1);
			_queues.Add(identification, queue);
		}

		queue.Add(receiver);
		Count++;
	}

	/// <summary>
	///   Returns the receivers of the identification in the order of registration
	/// </summary>
	/// <returns>The receivers, or an empty list if no receiver is registered for the identification</returns>
	public IReadOnlyList<TReceiver> Get(DnsMessageIdentification identification)
	{
		return _queues.TryGetValue(identification, out var queue) ? queue : Array.Empty<TReceiver>();
	}

	/// <summary>
	///   Removes the given receiver
	/// </summary>
	/// <returns>True, if the receiver was registered</returns>
	public bool Remove(DnsMessageIdentification identification, TReceiver receiver)
	{
		if (!_queues.TryGetValue(identification, out var queue))
			return false;

		var index = queue.IndexOf(receiver);
		if (index < 0)
			return false;

		queue.RemoveAt(index);
		Count--;

		if (queue.Count == 0)
			_queues.Remove(identification);

		return true;
	}

	/// <summary>
	///   Removes and returns all receivers
	/// </summary>
	public List<TReceiver> RemoveAll()
	{
		var receivers = _queues.Values.SelectMany(x => x).ToList();
		_queues.Clear();
		Count = 0;
		return receivers;
	}
}
