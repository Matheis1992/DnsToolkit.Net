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
	private readonly Dictionary<IPAddress, Task<TConnection?>> _pool = new();

	/// <summary>
	///   The number of servers, for which a connection is established or being established
	/// </summary>
	internal int Count
	{
		get
		{
			lock (_pool)
				return _pool.Count;
		}
	}

	/// <summary>
	///   Returns the connection to the server and establishes it, if the pool does not contain one yet
	/// </summary>
	/// <param name="address">The address of the server</param>
	/// <param name="connect">Establishes the connection, it is called once for all queries which need it meanwhile</param>
	/// <param name="token">
	///   The token to monitor cancellation requests. It only ends the waiting of this caller, the connect is shared
	///   and is not canceled.
	/// </param>
	/// <returns>The connection, or null if it could not be established</returns>
	public async Task<TConnection?> GetOrConnectAsync(IPAddress address, Func<Task<TConnection?>> connect, CancellationToken token)
	{
		Task<TConnection?>? connectTask;
		Task<Task<TConnection?>>? startConnect = null;

		lock (_pool)
		{
			if (!_pool.TryGetValue(address, out connectTask))
			{
				// Only the connect added to the pool is started, so concurrent queries never establish a second connection,
				// which nobody would use or close. It is started outside of the lock, as it may complete synchronously.
				startConnect = new Task<Task<TConnection?>>(connect);
				connectTask = startConnect.Unwrap();
				_pool.Add(address, connectTask);
			}
		}

		startConnect?.Start(TaskScheduler.Default);

		TConnection? connection;
		try
		{
			connection = await connectTask.WaitAsync(token).ConfigureAwait(false);
		}
		catch when (connectTask.IsFaulted || connectTask.IsCanceled)
		{
			// otherwise every further query would get the failed connect
			Remove(address, connectTask);
			throw;
		}

		if ((connection == null) || !connection.IsAlive)
			Remove(address, connectTask);

		return connection;
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
		Task<TConnection?>? connectTask;

		lock (_pool)
		{
			if (!_pool.TryGetValue(address, out connectTask))
				return null;

			// The result is only read of a completed connect, a pending one must not be awaited inside the lock
			if (connectTask.IsCompleted)
			{
				var connection = connectTask.Status == TaskStatus.RanToCompletion ? connectTask.Result : null;
				if ((connection != null) && connection.IsAlive)
					return connection;

				// Only removed, not closed: a connection, which takes no further queries, may still receive the responses
				// of the queries in progress. It closes itself afterwards.
				_pool.Remove(address);
				return null;
			}
		}

		try
		{
			var connection = await connectTask.WaitAsync(token).ConfigureAwait(false);
			return (connection != null) && connection.IsAlive ? connection : null;
		}
		catch when (connectTask.IsFaulted || connectTask.IsCanceled)
		{
			// the failure of the connect is reported to the queries, which established it
			Remove(address, connectTask);
			return null;
		}
	}

	/// <summary>
	///   Removes the connection from the pool, e.g. because it was closed. The pool may already contain a new connection
	///   to the server, which is kept.
	/// </summary>
	public void Remove(IPAddress address, TConnection connection)
	{
		lock (_pool)
		{
			// The result is only read of a completed connect, a pending one must not be awaited inside the lock
			if (_pool.TryGetValue(address, out var connectTask)
			    && (connectTask.Status == TaskStatus.RanToCompletion)
			    && ReferenceEquals(connectTask.Result, connection))
			{
				_pool.Remove(address);
			}
		}
	}

	private void Remove(IPAddress address, Task<TConnection?> connectTask)
	{
		lock (_pool)
		{
			if (_pool.TryGetValue(address, out var pooledTask) && (pooledTask == connectTask))
				_pool.Remove(address);
		}
	}

	/// <summary>
	///   Removes all connections and closes them, the pending ones once they are established
	/// </summary>
	public void Clear()
	{
		List<Task<TConnection?>> connectTasks;

		lock (_pool)
		{
			connectTasks = _pool.Values.ToList();
			_pool.Clear();
		}

		foreach (var connectTask in connectTasks)
		{
			connectTask.ContinueWith(t => t.Result?.MarkFaulty(), CancellationToken.None, TaskContinuationOptions.OnlyOnRanToCompletion, TaskScheduler.Default);
		}
	}
}
