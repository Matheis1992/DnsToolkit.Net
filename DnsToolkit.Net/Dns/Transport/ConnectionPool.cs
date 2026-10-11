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

using System.Collections.Concurrent;
using System.Net;

namespace DnsToolkit.Net.Dns;

/// <summary>
///   A connection, which can be kept in a <see cref="ConnectionPool{TConnection}" />. It closes itself, once it cannot
///   be used anymore, the pool only removes it then.
/// </summary>
internal interface IPooledConnection
{
	/// <summary>
	///   True, if further queries can use the connection
	/// </summary>
	bool IsAlive { get; }

	/// <summary>
	///   Closes the connection
	/// </summary>
	void MarkFaulty();
}

/// <summary>
///   One shared connection per server. The connection is established only once, all queries which need it meanwhile
///   wait for the same connect.
/// </summary>
internal sealed class ConnectionPool<TConnection>
	where TConnection : class, IPooledConnection
{
	// GetOrAdd may create an entry, which is not added, so the connect is started lazily. Only the connect of the entry in
	// the pool is started, so concurrent queries never establish a second connection, which nobody would use or close.
	private readonly ConcurrentDictionary<IPAddress, Lazy<Task<TConnection?>>> _pool = new();

	/// <summary>
	///   The number of servers, for which a connection is established or being established
	/// </summary>
	internal int Count => _pool.Count;

	/// <summary>
	///   Returns the connection to the server and establishes it, if the pool does not contain one yet
	/// </summary>
	/// <param name="address">The address of the server</param>
	/// <param name="connect">Establishes the connection, it is called once for all queries which need it meanwhile</param>
	/// <param name="token">
	///   The token to monitor cancellation requests. It only ends the waiting of this caller, the connect is shared
	///   and is not canceled.
	/// </param>
	/// <returns>The connection, or null if no usable connection could be established</returns>
	public async Task<TConnection?> GetOrConnectAsync(IPAddress address, Func<Task<TConnection?>> connect, CancellationToken token)
	{
		while (true)
		{
			var newEntry = new Lazy<Task<TConnection?>>(() => Task.Run(connect));
			var entry = _pool.GetOrAdd(address, newEntry);
			var connectTask = entry.Value;

			TConnection? connection;
			try
			{
				connection = await connectTask.WaitAsync(token).ConfigureAwait(false);
			}
			catch when (connectTask.IsFaulted || connectTask.IsCanceled)
			{
				// otherwise every further query would get the failed connect
				Remove(address, entry);
				throw;
			}

			if ((connection != null) && connection.IsAlive)
				return connection;

			Remove(address, entry);

			// A connection of the pool, which was closed or is draining meanwhile, e.g. by its idle timeout, is replaced by a
			// new one. The own connect is not repeated, so a server, which closes every connection, is not connected endlessly.
			if (ReferenceEquals(entry, newEntry))
				return null;
		}
	}

	/// <summary>
	///   Returns the connection to the server, if the pool contains one. A connection, which is still being established,
	///   is awaited.
	/// </summary>
	/// <param name="address">The address of the server</param>
	/// <param name="token">The token to monitor cancellation requests</param>
	/// <returns>The connection, or null if the pool contains no usable connection to the server</returns>
	public async Task<TConnection?> GetPooledAsync(IPAddress address, CancellationToken token)
	{
		if (!_pool.TryGetValue(address, out var entry))
			return null;

		var connectTask = entry.Value;

		if (connectTask.IsCompleted)
		{
			var connection = connectTask.Status == TaskStatus.RanToCompletion ? connectTask.Result : null;
			if ((connection != null) && connection.IsAlive)
				return connection;

			// Only removed, not closed: a connection, which takes no further queries, may still receive the responses
			// of the queries in progress. It closes itself afterwards.
			Remove(address, entry);
			return null;
		}

		try
		{
			var connection = await connectTask.WaitAsync(token).ConfigureAwait(false);
			return (connection != null) && connection.IsAlive ? connection : null;
		}
		catch when (connectTask.IsFaulted || connectTask.IsCanceled)
		{
			// the failure of the connect is reported to the queries, which established it
			Remove(address, entry);
			return null;
		}
	}

	/// <summary>
	///   Removes the connection from the pool, e.g. because it was closed. The pool may already contain a new connection
	///   to the server, which is kept.
	/// </summary>
	public void Remove(IPAddress address, TConnection connection)
	{
		// The result is only read of a completed connect, a pending one is not awaited
		if (_pool.TryGetValue(address, out var entry)
		    && entry.IsValueCreated
		    && (entry.Value.Status == TaskStatus.RanToCompletion)
		    && ReferenceEquals(entry.Value.Result, connection))
		{
			Remove(address, entry);
		}
	}

	/// <summary>
	///   Removes the entry, but not a newer entry of the server, which replaced it meanwhile
	/// </summary>
	private void Remove(IPAddress address, Lazy<Task<TConnection?>> entry)
	{
		// removes the pair only, if the value is still the same, on all target frameworks
		((ICollection<KeyValuePair<IPAddress, Lazy<Task<TConnection?>>>>) _pool).Remove(new KeyValuePair<IPAddress, Lazy<Task<TConnection?>>>(address, entry));
	}

	/// <summary>
	///   Removes all connections and closes them, the pending ones once they are established
	/// </summary>
	public void Clear()
	{
		foreach (var address in _pool.Keys)
		{
			// The value of an entry, whose connect is not started yet, is about to be read by the query, which added it,
			// so reading it here starts no connect, which would not be started anyway.
			if (_pool.TryRemove(address, out var entry))
				entry.Value.ContinueWith(t => t.Result?.MarkFaulty(), CancellationToken.None, TaskContinuationOptions.OnlyOnRanToCompletion, TaskScheduler.Default);
		}
	}
}
