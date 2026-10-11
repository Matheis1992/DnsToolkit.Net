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

using System.Threading.Channels;

namespace DnsToolkit.Net.Dns;

/// <summary>
///   A connection to a server, which is shared by all queries to it. A single receive loop reads all responses and
///   passes each to the query it belongs to. Every query has an own queue, so the messages of a multi message response
///   (e.g. a zone transfer) are kept until the query reads them, even if they arrive before it asks for them.
/// </summary>
internal sealed class SharedPipelinedConnection : IPooledConnection
{
	private readonly IPipelineableClientConnection _connection;
	private readonly Action<SharedPipelinedConnection> _onUnusable;

	// Canceled after the idle timeout, which only runs while no query is in progress, so the connection is closed then.
	// CancelAfter restarts the timer with every call, an infinite delay pauses it.
	private readonly CancellationTokenSource _idleCts = new();
	private TimeSpan _idleTimeout;

	/// <summary>
	///   The time without any query, after which the connection is closed
	/// </summary>
	internal TimeSpan IdleTimeout
	{
		get
		{
			lock (_lock)
				return _idleTimeout;
		}
	}

	// canceled when the connection is closed, so the pending read of the receive loop ends
	private readonly CancellationTokenSource _closeCts = new();

	/// <summary>
	///   The number of queries in a row, which ended without any response on the connection, after which it is closed. A server
	///   may keep the connection open, but stop answering, e.g. when it is overloaded or a middlebox dropped its state.
	/// </summary>
	internal const int MaxUnansweredQueries = 3;

	private readonly object _lock = new();
	private readonly ReceiverQueues<PendingQuery> _queries = new();
	private bool _isClosed;
	private int _unansweredQueries;

	// the server asked to close the connection, it is closed once all outstanding responses were received
	private bool _isDraining;
	private int _isUnusableReported;

	/// <summary>
	///   Creates the shared connection
	/// </summary>
	/// <param name="connection">The underlying connection</param>
	/// <param name="onUnusable">
	///   Called once, when the connection must not be used for further queries anymore, e.g. to remove it from the pool
	/// </param>
	/// <param name="idleTimeout">The time without any query, after which the connection is closed</param>
	/// <param name="initialIdleTimeout">
	///   The time, after which the connection is closed, if it is never used. It has to be long enough for the query,
	///   which established the connection, to send its query. Null, if the connection is not closed before its first query.
	/// </param>
	public SharedPipelinedConnection(IPipelineableClientConnection connection, Action<SharedPipelinedConnection> onUnusable, TimeSpan idleTimeout, TimeSpan? initialIdleTimeout = null)
	{
		_connection = connection;
		_onUnusable = onUnusable;

		_idleTimeout = idleTimeout;
		_idleCts.Token.Register(MarkFaulty);

		// e.g. all queries waiting for the connect were canceled meanwhile
		if (initialIdleTimeout.HasValue)
			_idleCts.CancelAfter(initialIdleTimeout.Value);
	}

	private void ReportUnusable()
	{
		if (Interlocked.Exchange(ref _isUnusableReported, 1) == 0)
			_onUnusable(this);
	}

	/// <summary>
	///   Started after the first query was sent and ends, when the connection is closed
	/// </summary>
	internal Task? ReceiveLoop
	{
		get
		{
			lock (_lock)
				return _receiveLoop;
		}
	}

	private Task? _receiveLoop;

	/// <summary>
	///   Starts the receive loop, which then reads until the connection is closed
	/// </summary>
	private void EnsureReceiveLoopStarted()
	{
		lock (_lock)
		{
			if ((_receiveLoop != null) || _isClosed)
				return;

			_receiveLoop = Task.Run(ReceiveLoopAsync);
		}
	}

	/// <summary>
	///   True, if further queries can be sent with the connection
	/// </summary>
	public bool IsAlive => IsUsable && _connection.IsAlive;

	public bool IsFaulty => _connection.IsFaulty;

	private bool IsUsable
	{
		get
		{
			lock (_lock)
				return !_isClosed && !_isDraining;
		}
	}

	public async Task<bool> SendAsync(DnsRawPackage package, CancellationToken token)
	{
		// concurrent sends are serialized by the connection
		var isSent = await _connection.SendAsync(package, token).ConfigureAwait(false);

		// The receive loop starts only after the first query was sent, the responses are buffered meanwhile. On .NET Framework
		// a read, which is pending already while the first query is sent over TLS, can delay the response until the query timed out.
		if (isSent)
			EnsureReceiveLoopStarted();

		return isSent;
	}

	/// <summary>
	///   Registers a query, which was not sent with <see cref="SendAsync" />, so only its responses received from now on are kept
	/// </summary>
	public PendingQuery RegisterReceiveOnly(DnsMessageIdentification identification)
	{
		var query = Register(identification);
		EnsureReceiveLoopStarted();
		return query;
	}

	/// <summary>
	///   Registers a query, so the responses with its identification are kept for it
	/// </summary>
	public PendingQuery Register(DnsMessageIdentification identification)
	{
		var query = new PendingQuery(identification);

		lock (_lock)
		{
			if (_isClosed)
			{
				// no further responses will be received
				query.Complete();
				return query;
			}

			_queries.Add(identification, query);

			if (_queries.Count == 1)
				_idleCts.CancelAfter(Timeout.InfiniteTimeSpan);
		}

		return query;
	}

	/// <summary>
	///   Unregisters a query, the responses to it, which are received later, are dropped
	/// </summary>
	public void Unregister(PendingQuery query)
	{
		var isUnresponsive = false;

		lock (_lock)
		{
			if (_queries.Remove(query.Identification, query))
			{
				// A query, which was sent, but ended without any response, e.g. by its timeout. Every response on the connection
				// resets the count, so only a server, which stopped answering on this connection, reaches the limit.
				if (query.IsSent && !query.HasMessages && (++_unansweredQueries >= MaxUnansweredQueries))
					isUnresponsive = true;

				if (_queries.Count == 0)
					_idleCts.CancelAfter(_idleTimeout);
			}
		}

		query.Complete();

		// the next queries establish a new connection
		if (isUnresponsive)
			MarkFaulty();
	}

	private async Task ReceiveLoopAsync()
	{
		try
		{
			while (true)
			{
				var package = await _connection.ReceiveAsync(_closeCts.Token).ConfigureAwait(false);

				// the server closed the connection or it failed
				if (package == null)
					return;

				PendingQuery? query;
				lock (_lock)
				{
					// the server still answers, also if the query of the response is finished already
					_unansweredQueries = 0;
					query = SelectQuery(package.MessageIdentification);
				}

				// e.g. the query timed out already
				if (query == null)
					continue;

				// dropped, if the query was finished meanwhile
				query.TryWrite(package);
			}
		}
		catch
		{
			// the connection failed or was closed
		}
		finally
		{
			// the connection cannot be used anymore, so the waiting queries are completed
			MarkFaulty();
		}
	}

	/// <summary>
	///   Queries with the same identification (transaction id and question) cannot be told apart. The first message goes
	///   to the oldest query, which has none yet. Further messages belong to a multi message response, they go to the
	///   oldest query.
	/// </summary>
	private PendingQuery? SelectQuery(DnsMessageIdentification identification)
	{
		var queries = _queries.Get(identification);
		if (queries.Count == 0)
			return null;

		var query = queries.FirstOrDefault(q => !q.HasMessages) ?? queries[0];
		query.HasMessages = true;
		return query;
	}

	/// <summary>
	///   Applies the edns-tcp-keepalive option of a response like RFC 7828: the timeout of the server replaces the idle
	///   timeout, and the connection is closed before it expires. With a timeout of 0, no further queries are sent and the
	///   connection is closed, once all outstanding responses were received.
	/// </summary>
	/// <param name="timeout">The timeout of the server, or null if the response contained no keepalive option</param>
	public void RestartIdleTimeout(TimeSpan? timeout)
	{
		// without the option, the own idle timeout is kept
		if (!timeout.HasValue)
			return;

		bool isDraining;

		lock (_lock)
		{
			if (_isClosed)
				return;

			if (timeout.Value <= TimeSpan.Zero)
			{
				_isDraining = true;
				_idleTimeout = TimeSpan.Zero;
			}
			else
			{
				// a tenth earlier, so the connection is not closed by the server, while a query is sent
				_idleTimeout = timeout.Value - TimeSpan.FromTicks(timeout.Value.Ticks / 10);
			}

			// The timer runs only while no query is in progress, so the outstanding responses are still received. Even with
			// a delay of 0, the source is canceled by its timer, so MarkFaulty does not run inside of this lock.
			if (_queries.Count == 0)
				_idleCts.CancelAfter(_idleTimeout);

			isDraining = _isDraining;
		}

		// the queries, which need a connection from now on, establish a new one
		if (isDraining)
			ReportUnusable();

		_connection.RestartIdleTimeout(timeout);
	}

	/// <summary>
	///   Closes the connection. The messages, which were received already, can still be read by the queries.
	/// </summary>
	public void MarkFaulty()
	{
		List<PendingQuery> queries;

		lock (_lock)
		{
			if (_isClosed)
				return;

			_isClosed = true;
			queries = _queries.RemoveAll();
		}

		ReportUnusable();

		_closeCts.Cancel();
		_connection.MarkFaulty();

		// Stops the idle timer. The source is not disposed, as this may run in its own callback. The callback is MarkFaulty
		// itself, which finds the connection closed already.
		_idleCts.Cancel();

		_connection.TryDispose();

		foreach (var query in queries)
		{
			query.Complete();
		}
	}
}

/// <summary>
///   The connection a query gets for a <see cref="SharedPipelinedConnection" />. Disposing it ends the queries sent
///   with it, but not the shared connection.
/// </summary>
internal sealed class PipelinedClientConnection : IClientConnection
{
	private readonly SharedPipelinedConnection _connection;
	private readonly List<PendingQuery> _queries = new(1);

	public PipelinedClientConnection(SharedPipelinedConnection connection, IClientTransport transport)
	{
		_connection = connection;
		Transport = transport;
	}

	public IClientTransport Transport { get; }

	public bool IsFaulty => _connection.IsFaulty;

	/// <summary>
	///   The queries sent with this connection, which are not finished yet
	/// </summary>
	internal IReadOnlyList<PendingQuery> PendingQueries
	{
		get
		{
			lock (_queries)
				return _queries.ToList();
		}
	}

	public async Task<bool> SendAsync(DnsRawPackage package, CancellationToken token = default)
	{
		// The query is registered before sending. Otherwise the receive loop, which may already run for other queries,
		// could read a fast response before and would drop it.
		var query = Register(package.MessageIdentification);

		var isSent = false;
		try
		{
			isSent = await _connection.SendAsync(package, token).ConfigureAwait(false);
			query.IsSent = isSent;
			return isSent;
		}
		finally
		{
			if (!isSent)
				Unregister(query);
		}
	}

	public Task<DnsReceivedRawPackage?> ReceiveAsync(DnsMessageIdentification identification, CancellationToken token = default)
	{
		PendingQuery? query;
		lock (_queries)
		{
			query = _queries.FirstOrDefault(q => q.Identification.Equals(identification));
		}

		// Without SendAsync, only the messages received from now on can be returned
		if (query == null)
		{
			query = _connection.RegisterReceiveOnly(identification);

			lock (_queries)
				_queries.Add(query);
		}

		// The query stays registered until this connection is disposed, so further messages of a multi message
		// response are kept, even if they arrive before they are requested.
		return query.ReadAsync(token);
	}

	private PendingQuery Register(DnsMessageIdentification identification)
	{
		var query = _connection.Register(identification);

		lock (_queries)
			_queries.Add(query);

		return query;
	}

	private void Unregister(PendingQuery query)
	{
		lock (_queries)
			_queries.Remove(query);

		_connection.Unregister(query);
	}

	public void RestartIdleTimeout(TimeSpan? timeout)
	{
		_connection.RestartIdleTimeout(timeout);
	}

	public void MarkFaulty()
	{
		_connection.MarkFaulty();
	}

	/// <summary>
	///   Ends the queries sent with this connection. The shared connection stays open for other queries.
	/// </summary>
	public void Dispose()
	{
		List<PendingQuery> queries;
		lock (_queries)
		{
			queries = _queries.ToList();
			_queries.Clear();
		}

		foreach (var query in queries)
		{
			_connection.Unregister(query);
		}
	}
}

/// <summary>
///   A query on a <see cref="SharedPipelinedConnection" /> with the queue of its received messages
/// </summary>
internal sealed class PendingQuery
{
	// Unbounded, as the receive loop would otherwise have to wait for a query, which is behind with reading, and the responses
	// to all other queries would be delayed meanwhile. The client reads the messages of a multi message response one after
	// another and keeps all of them anyway, so the queue holds no more than the client keeps.
	private readonly Channel<DnsReceivedRawPackage> _messages = Channel.CreateUnbounded<DnsReceivedRawPackage>(
		new UnboundedChannelOptions
		{
			SingleReader = true,
			SingleWriter = true
		});

	public PendingQuery(DnsMessageIdentification identification)
	{
		Identification = identification;
	}

	public DnsMessageIdentification Identification { get; }

	/// <summary>
	///   True, once a message was passed to the query. Only used inside of the lock of the connection.
	/// </summary>
	public bool HasMessages { get; set; }

	/// <summary>
	///   True, if the query was sent, so a response is expected. Set before the query is unregistered.
	/// </summary>
	public bool IsSent { get; set; }

	/// <summary>
	///   Adds a received message to the queue
	/// </summary>
	/// <returns>False, if the query is done already, so the message is dropped</returns>
	public bool TryWrite(DnsReceivedRawPackage package)
	{
		return _messages.Writer.TryWrite(package);
	}

	/// <summary>
	///   Returns the next message
	/// </summary>
	/// <param name="token">The token to monitor cancellation requests</param>
	/// <returns>The message, or null if no further message will be received</returns>
	public async Task<DnsReceivedRawPackage?> ReadAsync(CancellationToken token)
	{
		try
		{
			return await _messages.Reader.ReadAsync(token).ConfigureAwait(false);
		}
		catch (ChannelClosedException)
		{
			return null;
		}
	}

	/// <summary>
	///   No further messages are added, the messages added already can still be read
	/// </summary>
	public void Complete()
	{
		_messages.Writer.TryComplete();
	}
}
