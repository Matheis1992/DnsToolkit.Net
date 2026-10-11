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
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

/// <summary>
///   Tests the connection shared by all queries to a server with a simulated connection, whose responses are sent by the test
/// </summary>
public class SharedPipelinedConnectionTests
{
	private static readonly TimeSpan _idleTimeout = TimeSpan.FromMinutes(5);

	[Fact]
	public async Task FollowUpMessages_ArrivingBeforeTheyAreRequested_AreKeptForTheQuery()
	{
		var (connection, shared) = Create();
		using var query = Lease(shared);
		var sent = Query(0x1111, "zone");
		Assert.True(await query.SendAsync(sent));

		// all messages of the multi message response arrive, before the query asks for the first one
		connection.Respond(sent, "m1");
		connection.Respond(sent, "m2");
		connection.Respond(sent, "m3");
		await connection.WaitUntilAllResponsesWereReadAsync();

		Assert.Equal("m1", Marker(await ReceiveWithinAsync(query, sent.MessageIdentification)));
		Assert.Equal("m2", Marker(await ReceiveWithinAsync(query, sent.MessageIdentification)));
		Assert.Equal("m3", Marker(await ReceiveWithinAsync(query, sent.MessageIdentification)));
	}

	[Fact]
	public async Task Responses_AreDeliveredToTheirQueries()
	{
		var (connection, shared) = Create();
		using var first = Lease(shared);
		using var second = Lease(shared);
		var firstSent = Query(0x1111, "first");
		var secondSent = Query(0x2222, "second");
		await first.SendAsync(firstSent);
		await second.SendAsync(secondSent);

		connection.Respond(secondSent, "s1");
		connection.Respond(firstSent, "f1");
		connection.Respond(secondSent, "s2");

		Assert.Equal("f1", Marker(await ReceiveWithinAsync(first, firstSent.MessageIdentification)));
		Assert.Equal("s1", Marker(await ReceiveWithinAsync(second, secondSent.MessageIdentification)));
		Assert.Equal("s2", Marker(await ReceiveWithinAsync(second, secondSent.MessageIdentification)));
	}

	[Fact]
	public async Task QueriesWithTheSameIdentification_GetOneResponseEach_InTheOrderTheyWereSent()
	{
		var (connection, shared) = Create();
		using var first = Lease(shared);
		using var second = Lease(shared);
		var sent = Query(0x1111, "same");
		await first.SendAsync(sent);
		await second.SendAsync(sent);

		connection.Respond(sent, "r1");
		connection.Respond(sent, "r2");

		Assert.Equal("r1", Marker(await ReceiveWithinAsync(first, sent.MessageIdentification)));
		Assert.Equal("r2", Marker(await ReceiveWithinAsync(second, sent.MessageIdentification)));
	}

	[Fact]
	public async Task ResponsesOfAFinishedQuery_AreDropped_WithoutBlockingOtherQueries()
	{
		var (connection, shared) = Create();
		var finished = Lease(shared);
		using var other = Lease(shared);
		var finishedSent = Query(0x1111, "finished");
		var otherSent = Query(0x2222, "other");
		await finished.SendAsync(finishedSent);
		await other.SendAsync(otherSent);

		finished.Dispose();

		for (var i = 0; i < 20; i++)
			connection.Respond(finishedSent, "late" + i);
		connection.Respond(otherSent, "o1");

		var received = other.ReceiveAsync(otherSent.MessageIdentification);
		await CompletesWithinAsync(received, TimeSpan.FromSeconds(2));
		Assert.Equal("o1", Marker(await received));
	}

	[Fact]
	public async Task ResponsesToOtherQueries_AreNotDelayed_ByAQueryWhichIsBehindWithReading()
	{
		var (connection, shared) = Create();
		using var zoneTransfer = Lease(shared);
		using var other = Lease(shared);
		var zoneTransferSent = Query(0x1111, "zone");
		var otherSent = Query(0x2222, "other");
		await zoneTransfer.SendAsync(zoneTransferSent);
		await other.SendAsync(otherSent);

		// before, the receive loop waited for the zone transfer to read, once it had 16 unread messages
		for (var i = 0; i < 50; i++)
			connection.Respond(zoneTransferSent, "m" + i);
		connection.Respond(otherSent, "o1");

		var received = other.ReceiveAsync(otherSent.MessageIdentification);
		await CompletesWithinAsync(received, TimeSpan.FromSeconds(2));
		Assert.Equal("o1", Marker(await received));

		Assert.Equal("m0", Marker(await ReceiveWithinAsync(zoneTransfer, zoneTransferSent.MessageIdentification)));
	}

	[Fact]
	public async Task Connection_IsClosed_AfterQueriesInARowGotNoResponseAtAll()
	{
		// e.g. the server keeps the connection open, but stopped answering. Before, it stayed in the pool and every query
		// to the server waited for its timeout twice.
		var (connection, shared) = Create();

		for (var i = 0; i < SharedPipelinedConnection.MaxUnansweredQueries; i++)
		{
			Assert.True(shared.IsAlive, "The connection was closed before the limit of unanswered queries");

			using var query = Lease(shared);
			await query.SendAsync(Query((ushort) i, "unanswered"));
		}

		Assert.False(shared.IsAlive, "The connection, whose server stopped answering, is still used");
		Assert.True(await WaitUntilClosedAsync(connection, TimeSpan.FromSeconds(5)), "The connection was not closed");
	}

	[Fact]
	public async Task Connection_IsKept_WhileTheServerAnswersOtherQueries()
	{
		// queries, which end without a response, e.g. canceled by their caller, do not close a connection, whose server answers
		var (connection, shared) = Create();

		for (var i = 0; i < SharedPipelinedConnection.MaxUnansweredQueries * 2; i++)
		{
			using (var unanswered = Lease(shared))
				await unanswered.SendAsync(Query((ushort) (2 * i), "unanswered"));

			using var answered = Lease(shared);
			var sent = Query((ushort) (2 * i + 1), "answered");
			await answered.SendAsync(sent);
			connection.Respond(sent, "a");
			await ReceiveWithinAsync(answered, sent.MessageIdentification);
		}

		Assert.True(shared.IsAlive);
	}

	[Fact]
	public async Task ManyUnreadMessages_AreDeliveredCompletelyAndInOrder()
	{
		var (connection, shared) = Create();
		using var query = Lease(shared);
		var sent = Query(0x1111, "zone");
		await query.SendAsync(sent);

		var count = 50;
		for (var i = 0; i < count; i++)
			connection.Respond(sent, "m" + i);

		for (var i = 0; i < count; i++)
		{
			var received = query.ReceiveAsync(sent.MessageIdentification);
			await CompletesWithinAsync(received, TimeSpan.FromSeconds(2));
			Assert.Equal("m" + i, Marker(await received));
		}
	}

	[Fact]
	public async Task CanceledReceive_KeepsTheQuery_SoALaterResponseIsStillDelivered()
	{
		var (connection, shared) = Create();
		using var query = Lease(shared);
		var sent = Query(0x1111, "query");
		await query.SendAsync(sent);

		using (var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50)))
			await Assert.ThrowsAnyAsync<OperationCanceledException>(() => query.ReceiveAsync(sent.MessageIdentification, cts.Token));

		connection.Respond(sent, "late");

		Assert.Equal("late", Marker(await ReceiveWithinAsync(query, sent.MessageIdentification)));
	}

	[Fact]
	public void Receive_DoesNotKeepTheQueryRegisteredOnTheTokenOfTheCaller()
	{
		var (connection, shared) = Create();
		using var callerCts = new CancellationTokenSource();

		// e.g. the token of an application, which lives longer than the queries
		var finishedQuery = RunQueryWithToken(connection, shared, callerCts.Token);

		// Until the receive loop waits for the next message, it still holds the query, to which it passed the response. On a
		// busy build server the garbage collection could happen before, so the query seemed to be kept by a registration.
		Assert.True(SpinWait.SpinUntil(() => connection.ReceiveCalls >= 2, TimeSpan.FromSeconds(5)), "The receive loop did not wait for the next message");

		GC.Collect();
		GC.WaitForPendingFinalizers();
		GC.Collect();

		// the connection of the query and its queue, as a registration could keep either
		Assert.All(finishedQuery, reference => Assert.False(reference.IsAlive, "The finished query is still referenced, e.g. by a registration on the token of the caller"));
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static List<WeakReference> RunQueryWithToken(FakeConnection connection, SharedPipelinedConnection shared, CancellationToken token)
	{
		return Task.Run(async () =>
		{
			var query = Lease(shared);
			var sent = Query(0x1111, "query");
			await query.SendAsync(sent);

			var references = query.PendingQueries.Select(q => new WeakReference(q)).ToList();
			references.Add(new WeakReference(query));

			// the response arrives only while the query waits for it, so the wait is registered on the token
			var receiving = query.ReceiveAsync(sent.MessageIdentification, token);
			await Task.Delay(50);
			connection.Respond(sent, "r1");
			await CompletesWithinAsync(receiving, TimeSpan.FromSeconds(2));
			Assert.Equal("r1", Marker(await receiving));

			query.Dispose();
			return references;
		}).GetAwaiter().GetResult();
	}

	[Fact]
	public async Task ReceiveLoop_StartsOnlyAfterTheFirstQueryWasSent()
	{
		var (connection, shared) = Create();
		using var query = Lease(shared);

		// a read, which is pending while the first query is sent over TLS, can delay the response on .NET Framework
		Assert.Null(shared.ReceiveLoop);
		Assert.Equal(0, connection.ReceiveCalls);

		await query.SendAsync(Query(0x1111, "query"));

		Assert.NotNull(shared.ReceiveLoop);
	}

	[Fact]
	public async Task ClosedByTheServer_WaitingQueriesGetNoResponse_AndTheConnectionIsRemoved()
	{
		var closedCalls = 0;
		var (connection, shared) = Create(onUnusable: _ => Interlocked.Increment(ref closedCalls));
		using var query = Lease(shared);
		var sent = Query(0x1111, "query");
		await query.SendAsync(sent);

		var receiving = query.ReceiveAsync(sent.MessageIdentification);
		connection.CloseByServer();

		await CompletesWithinAsync(receiving, TimeSpan.FromSeconds(2));
		Assert.Null(await receiving);
		Assert.Equal(1, closedCalls);
		Assert.False(shared.IsAlive);
		Assert.True(connection.IsDisposed);

		// a query on the closed connection gets no response instead of waiting until its timeout
		using var late = Lease(shared);
		Assert.Null(await ReceiveWithinAsync(late, Query(0x2222, "late").MessageIdentification));
	}

	[Fact]
	public async Task MarkFaulty_MessagesReceivedBefore_CanStillBeRead()
	{
		var (connection, shared) = Create();
		using var query = Lease(shared);
		using var other = Lease(shared);
		var sent = Query(0x1111, "zone");
		var otherSent = Query(0x2222, "other");
		await query.SendAsync(sent);
		await other.SendAsync(otherSent);
		connection.Respond(sent, "m1");
		connection.Respond(otherSent, "o1");

		// the receive loop handles the responses in order, so the first one was passed to its query already
		Assert.Equal("o1", Marker(await ReceiveWithinAsync(other, otherSent.MessageIdentification)));

		query.MarkFaulty();

		Assert.Equal("m1", Marker(await ReceiveWithinAsync(query, sent.MessageIdentification)));
		Assert.Null(await ReceiveWithinAsync(query, sent.MessageIdentification));
	}

	[Fact]
	public async Task KeepAliveOfZero_TakesNoFurtherQueries_ButReceivesTheOutstandingResponses()
	{
		var unusableCalls = 0;
		var (connection, shared) = Create(onUnusable: _ => Interlocked.Increment(ref unusableCalls));
		var first = Lease(shared);
		var second = Lease(shared);
		var firstSent = Query(0x1111, "first");
		var secondSent = Query(0x2222, "second");
		await first.SendAsync(firstSent);
		await second.SendAsync(secondSent);

		connection.Respond(firstSent, "f1");
		Assert.Equal("f1", Marker(await ReceiveWithinAsync(first, firstSent.MessageIdentification)));

		// the server asks to close the connection (RFC 7828)
		first.RestartIdleTimeout(TimeSpan.Zero);
		first.Dispose();

		Assert.False(shared.IsAlive);
		Assert.Equal(1, unusableCalls);

		// the response to the outstanding query is still received
		await Task.Delay(200);
		Assert.False(connection.IsDisposed);
		connection.Respond(secondSent, "s1");
		Assert.Equal("s1", Marker(await ReceiveWithinAsync(second, secondSent.MessageIdentification)));

		// closed, once no query is outstanding anymore
		second.Dispose();
		Assert.True(await WaitUntilClosedAsync(connection, TimeSpan.FromSeconds(2)), "The connection was not closed after the last outstanding response");
		Assert.Equal(1, unusableCalls);
	}

	[Fact]
	public async Task KeepAliveOfTheServer_ReplacesTheIdleTimeout()
	{
		var (connection, shared) = Create(idleTimeout: TimeSpan.FromMilliseconds(50));
		var query = Lease(shared);
		var sent = Query(0x1111, "query");
		await query.SendAsync(sent);
		connection.Respond(sent, "r1");
		Assert.Equal("r1", Marker(await ReceiveWithinAsync(query, sent.MessageIdentification)));

		// the server keeps the connection open for 1.5 s, which is longer than the own idle timeout
		query.RestartIdleTimeout(TimeSpan.FromMilliseconds(1500));
		query.Dispose();

		// Measured from the start of the idle timeout. Before, the measurement started after the delay and assumed it took
		// exactly 400 ms, so a delay, which took longer on a busy build server, made the connection seem closed too early.
		var stopwatch = System.Diagnostics.Stopwatch.StartNew();

		await Task.Delay(400);
		Assert.True(shared.IsAlive, "The connection was closed before the keepalive of the server");

		// but before the server closes it
		Assert.True(await WaitUntilClosedAsync(connection, TimeSpan.FromSeconds(5)), "The connection was not closed after the keepalive of the server");
		Assert.InRange(stopwatch.Elapsed, TimeSpan.FromMilliseconds(1000), TimeSpan.FromMilliseconds(1500));
	}

	[Fact]
	public async Task KeepAliveOfTheServer_DoesNotCloseTheConnection_WhileQueriesAreInProgress()
	{
		var (connection, shared) = Create(idleTimeout: TimeSpan.FromMilliseconds(50));
		using var first = Lease(shared);
		using var second = Lease(shared);
		var firstSent = Query(0x1111, "first");
		var secondSent = Query(0x2222, "second");
		await first.SendAsync(firstSent);
		await second.SendAsync(secondSent);

		connection.Respond(firstSent, "f1");
		Assert.Equal("f1", Marker(await ReceiveWithinAsync(first, firstSent.MessageIdentification)));
		first.RestartIdleTimeout(TimeSpan.FromMilliseconds(100));

		await Task.Delay(300);
		Assert.True(shared.IsAlive, "The connection was closed, although queries are in progress");

		connection.Respond(secondSent, "s1");
		Assert.Equal("s1", Marker(await ReceiveWithinAsync(second, secondSent.MessageIdentification)));
	}

	[Fact]
	public async Task UnusedConnection_IsClosed_AfterTheInitialIdleTimeout()
	{
		var unusableCalls = 0;
		var (connection, shared) = Create(onUnusable: _ => Interlocked.Increment(ref unusableCalls), initialIdleTimeout: TimeSpan.FromMilliseconds(200));

		// e.g. all queries waiting for the connect were canceled, so nobody sends a query with it
		Assert.True(await WaitUntilClosedAsync(connection, TimeSpan.FromSeconds(5)), "The unused connection was not closed");
		Assert.False(shared.IsAlive);
		Assert.Equal(1, unusableCalls);
	}

	[Fact]
	public async Task InitialIdleTimeout_DoesNotCloseAConnectionWithAQueryInProgress()
	{
		var (connection, shared) = Create(initialIdleTimeout: TimeSpan.FromMilliseconds(200));
		using var query = Lease(shared);
		var sent = Query(0x1111, "query");
		await query.SendAsync(sent);

		await Task.Delay(500);
		Assert.True(shared.IsAlive);

		connection.Respond(sent, "r1");
		Assert.Equal("r1", Marker(await ReceiveWithinAsync(query, sent.MessageIdentification)));
	}

	[Fact]
	public async Task IdleConnection_IsClosed_OnlyAfterTheLastQueryWasFinished()
	{
		var (connection, shared) = Create(idleTimeout: TimeSpan.FromMilliseconds(100));
		var query = Lease(shared);
		var sent = Query(0x1111, "query");
		await query.SendAsync(sent);
		connection.Respond(sent, "r1");
		Assert.Equal("r1", Marker(await ReceiveWithinAsync(query, sent.MessageIdentification)));

		// the query is still in progress, e.g. as it validates the response
		await Task.Delay(300);
		Assert.True(shared.IsAlive);

		query.Dispose();

		Assert.True(await WaitUntilClosedAsync(connection, TimeSpan.FromSeconds(5)), "The idle connection was not closed");
		Assert.False(shared.IsAlive);
	}

	private static (FakeConnection Connection, SharedPipelinedConnection Shared) Create(Action<SharedPipelinedConnection>? onUnusable = null, TimeSpan? idleTimeout = null, TimeSpan? initialIdleTimeout = null)
	{
		var connection = new FakeConnection();
		var shared = new SharedPipelinedConnection(connection, onUnusable ?? (_ => { }), idleTimeout ?? _idleTimeout, initialIdleTimeout);
		return (connection, shared);
	}

	private static async Task<bool> WaitUntilClosedAsync(FakeConnection connection, TimeSpan timeout)
	{
		var stopwatch = System.Diagnostics.Stopwatch.StartNew();
		while (!connection.IsDisposed && (stopwatch.Elapsed < timeout))
			await Task.Delay(10);

		return connection.IsDisposed;
	}

	private static PipelinedClientConnection Lease(SharedPipelinedConnection shared) => new(shared, new TcpClientTransport(53));

	private static DnsRawPackage Query(ushort transactionId, string label)
	{
		var query = new DnsMessage { TransactionID = transactionId };
		query.Questions.Add(new DnsQuestion(DomainName.Parse(label + ".example.test"), RecordType.A, RecordClass.INet));
		return query.Encode();
	}

	/// <summary>
	///   The label of the record in a response, by which the test tells the responses apart
	/// </summary>
	private static string? Marker(DnsReceivedRawPackage? package)
	{
		if (package == null)
			return null;

		var response = DnsMessage.Parse(package.ToArraySegment(false));
		return response.AnswerRecords.Single().Name.Labels[0];
	}

	/// <summary>
	///   Receives with a time limit, so a broken connection fails the test instead of hanging it
	/// </summary>
	private static async Task<DnsReceivedRawPackage?> ReceiveWithinAsync(PipelinedClientConnection query, DnsMessageIdentification identification)
	{
		var receiving = query.ReceiveAsync(identification);
		await CompletesWithinAsync(receiving, TimeSpan.FromSeconds(2));
		return await receiving;
	}

	private static async Task CompletesWithinAsync(Task task, TimeSpan timeout)
	{
		Assert.True(await Task.WhenAny(task, Task.Delay(timeout)) == task, $"The task did not complete within {timeout}");
		await task;
	}

	/// <summary>
	///   A connection, whose responses are sent by the test
	/// </summary>
	private sealed class FakeConnection : IPipelineableClientConnection
	{
		private readonly Channel<DnsReceivedRawPackage> _responses = Channel.CreateUnbounded<DnsReceivedRawPackage>();
		private int _receiveCalls;

		public IClientTransport Transport => throw new NotSupportedException();

		public ConcurrentQueue<DnsRawPackage> Sent { get; } = new();

		public int ReceiveCalls => Volatile.Read(ref _receiveCalls);

		public bool IsAlive => !IsFaulty;

		public bool IsFaulty { get; private set; }

		public bool IsDisposed { get; private set; }

		public void Respond(DnsRawPackage query, string marker)
		{
			var parsed = DnsMessage.Parse(query.ToArraySegment(false));
			var response = parsed.CreateResponseInstance();
			response.AnswerRecords.Add(new ARecord(DomainName.Parse(marker + ".example.test"), 60, IPAddress.Parse("192.0.2.1")));

			var data = response.Encode().ToArraySegment(true).ToArray();
			_responses.Writer.TryWrite(new DnsReceivedRawPackage(data, new IPEndPoint(IPAddress.Loopback, 53), new IPEndPoint(IPAddress.Loopback, 50000)));
		}

		public void CloseByServer() => _responses.Writer.TryComplete();

		public async Task WaitUntilAllResponsesWereReadAsync()
		{
			var stopwatch = System.Diagnostics.Stopwatch.StartNew();
			while ((_responses.Reader.Count > 0) && (stopwatch.Elapsed < TimeSpan.FromSeconds(5)))
				await Task.Delay(10);

			Assert.Equal(0, _responses.Reader.Count);
		}

		public Task<bool> SendAsync(DnsRawPackage package, CancellationToken token = default)
		{
			Sent.Enqueue(package);
			return Task.FromResult(true);
		}

		public async Task<DnsReceivedRawPackage?> ReceiveAsync(CancellationToken token = default)
		{
			Interlocked.Increment(ref _receiveCalls);

			try
			{
				return await _responses.Reader.ReadAsync(token);
			}
			catch (ChannelClosedException)
			{
				return null;
			}
		}

		public Task<DnsReceivedRawPackage?> ReceiveAsync(DnsMessageIdentification identification, CancellationToken token = default)
			=> throw new NotSupportedException("The shared connection uses the receive loop");

		public void RestartIdleTimeout(TimeSpan? timeout) { }

		public void MarkFaulty() => IsFaulty = true;

		public void Dispose()
		{
			IsDisposed = true;
			MarkFaulty();
		}
	}
}
