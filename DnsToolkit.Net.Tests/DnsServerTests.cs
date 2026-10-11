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

using System.Net;
using System.Net.Sockets;
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

public class DnsServerTests
{
	private static readonly DomainName _name = DomainName.Parse("host.example.test");

	[Fact]
	public async Task Connection_IsDisposed_WhenClientStopsSending()
	{
		// A TCP like connection which delivers one query and then reports the end of the stream
		var connection = new FakeServerConnection(CreateQueryPackage());
		var transport = new FakeServerTransport(connection);

		using var server = new DnsServer(transport);
		server.QueryReceived += AnswerQuery;
		server.Start();

		Assert.True(await connection.WaitForDisposeAsync(TimeSpan.FromSeconds(5)), "The connection was not disposed after the client stopped sending");
		Assert.Equal(1, connection.SentPackages);
	}

	[Fact]
	public async Task Connection_IsDisposed_WhenRefused()
	{
		var connection = new FakeServerConnection(CreateQueryPackage());
		var transport = new FakeServerTransport(connection);

		using var server = new DnsServer(transport);
		server.ClientConnected += (_, e) =>
		{
			e.RefuseConnect = true;
			return Task.CompletedTask;
		};
		server.Start();

		Assert.True(await connection.WaitForDisposeAsync(TimeSpan.FromSeconds(5)), "The refused connection was not disposed");
	}

	[Fact]
	public async Task ConnectionLoop_DoesNotSpin_WhenTransportReturnsNoConnection()
	{
		var transport = new FakeServerTransport(alwaysReturnNull: true);

		var server = new DnsServer(transport);
		server.Start();
		await Task.Delay(TimeSpan.FromMilliseconds(500));
		((IDisposable) server).Dispose();

		// a busy loop calls AcceptConnectionAsync millions of times per second
		Assert.InRange(transport.AcceptCalls, 1, 1000);
	}

	[Theory]
	[InlineData(1, 0)]
	[InlineData(2, 1)]
	[InlineData(3, 2)]
	[InlineData(8, 64)]
	[InlineData(9, 100)]
	[InlineData(1000, 100)]
	public void FailedAcceptDelay_GrowsExponentiallyUpTo100Ms(int failedAccepts, int expectedMilliseconds)
	{
		Assert.Equal(TimeSpan.FromMilliseconds(expectedMilliseconds), DnsServer.GetFailedAcceptDelay(failedAccepts));
	}

	[Fact]
	public async Task Server_RecoversImmediately_AfterSomeFailedAccepts()
	{
		var connection = new FakeServerConnection(CreateQueryPackage());
		var transport = new FakeServerTransport(connection, failedAcceptsBeforeConnection: 5);

		using var server = new DnsServer(transport);
		server.QueryReceived += AnswerQuery;

		var stopwatch = System.Diagnostics.Stopwatch.StartNew();
		server.Start();

		// the delays after 5 failures add up to 15 ms
		Assert.True(await connection.WaitForDisposeAsync(TimeSpan.FromSeconds(5)), "The connection after the failed accepts was not processed");
		Assert.InRange(stopwatch.Elapsed, TimeSpan.Zero, TimeSpan.FromSeconds(1));
		Assert.Equal(1, connection.SentPackages);
	}

	[Fact]
	public async Task Server_RetriesPermanentlyFailingTransport_OnlyAboutTenTimesASecond()
	{
		var transport = new FakeServerTransport(alwaysReturnNull: true);

		var server = new DnsServer(transport);
		server.Start();
		await Task.Delay(TimeSpan.FromSeconds(1));
		((IDisposable) server).Dispose();

		// about 8 retries with growing delays up to 100 ms and then about 9 retries per remaining second
		Assert.InRange(transport.AcceptCalls, 5, 40);
	}

	[Fact]
	public async Task Stop_ReportsNoExceptions_OfTheClosedTransports()
	{
		var exceptions = new List<Exception>();
		var server = new DnsServer(
			new UdpServerTransport(new IPEndPoint(IPAddress.Loopback, 0)),
			new TcpServerTransport(new IPEndPoint(IPAddress.Loopback, 0)));
		server.ExceptionThrown += (_, e) =>
		{
			lock (exceptions)
				exceptions.Add(e.Exception);
			return Task.CompletedTask;
		};

		server.Start();
		await Task.Delay(200);
		server.Stop();
		await Task.Delay(200);

		lock (exceptions)
			Assert.Empty(exceptions);
	}

	[Fact]
	public void Dispose_WithoutStart_DoesNotThrow()
	{
		var server = new DnsServer(new FakeServerTransport());

		var exception = Record.Exception(() => ((IDisposable) server).Dispose());

		Assert.Null(exception);
	}

	[Fact]
	public async Task AcceptConnectionException_IsReportedAndServerKeepsAccepting()
	{
		var connection = new FakeServerConnection(CreateQueryPackage());
		var transport = new FakeServerTransport(connection, throwOnFirstAccept: true);
		var exceptionReported = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

		using var server = new DnsServer(transport);
		server.QueryReceived += AnswerQuery;
		server.ExceptionThrown += (_, _) =>
		{
			exceptionReported.TrySetResult(true);
			return Task.CompletedTask;
		};
		server.Start();

		Assert.True(await Task.WhenAny(exceptionReported.Task, Task.Delay(5000)) == exceptionReported.Task, "The exception of the transport was not reported");
		Assert.True(await connection.WaitForDisposeAsync(TimeSpan.FromSeconds(5)), "The server stopped accepting connections after the exception");
	}

	[Fact]
	public async Task Stop_WaitsUntilQueryInProgressIsProcessed()
	{
		await AssertStopWaitsForQueryInProgressAsync(server => Task.Run(server.Stop));
	}

	[Fact]
	public async Task StopAsync_WaitsUntilQueryInProgressIsProcessed()
	{
		await AssertStopWaitsForQueryInProgressAsync(server => server.StopAsync());
	}

	[Fact]
	public async Task DisposeAsync_WaitsUntilQueryInProgressIsProcessed()
	{
		await AssertStopWaitsForQueryInProgressAsync(server => ((IAsyncDisposable) server).DisposeAsync().AsTask());
	}

	[Fact]
	public async Task QueriesOfOneConnection_AreLimitedByMaxConcurrentQueriesPerConnection()
	{
		// e.g. queries pipelined by a client over TCP
		var connection = new FakeServerConnection(Enumerable.Range(0, 10).Select(_ => CreateQueryPackage()).ToArray());
		var transport = new FakeServerTransport(connection);
		var released = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
		var limitReached = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
		var started = 0;

		var server = new DnsServer(transport) { MaxConcurrentQueriesPerConnection = 3 };
		server.QueryReceived += async (sender, e) =>
		{
			if (Interlocked.Increment(ref started) == 3)
				limitReached.TrySetResult(true);

			await released.Task;
			await AnswerQuery(sender, e);
		};
		server.Start();

		try
		{
			Assert.True(await Task.WhenAny(limitReached.Task, Task.Delay(TimeSpan.FromSeconds(10))) == limitReached.Task, "Three queries were not started");

			// A further query would start right after the third one, so a short time shows that none does. On a slow machine
			// this can only miss an error, but not fail without one. Before, all queries were processed at the same time.
			await Task.Delay(200);
			Assert.Equal(3, Volatile.Read(ref started));

			released.TrySetResult(true);

			Assert.True(await connection.WaitForDisposeAsync(TimeSpan.FromSeconds(5)), "The connection was not disposed after all queries were answered");
			Assert.Equal(10, connection.SentPackages);
		}
		finally
		{
			released.TrySetResult(true);
			((IDisposable) server).Dispose();
		}
	}

	[Fact]
	public async Task SignedQuery_ClosesTheConnection_OnlyAfterTheOtherQueriesInProgressAreAnswered()
	{
		// e.g. queries pipelined over TCP, the unsigned one is still processed, when the signed one is answered
		var handler = new BlockingQueryHandler();
		var connection = new FakeServerConnection(CreateSignedQueryPackage(), CreateQueryPackage());
		var transport = new FakeServerTransport(connection);

		var server = new DnsServer(transport);
		server.QueryReceived += handler.HandleAsync;
		server.Start();

		try
		{
			Assert.True(await handler.WaitForQueryAsync(TimeSpan.FromSeconds(5)), "The unsigned query was not received");
			Assert.True(await WaitUntilAsync(() => connection.SentPackages == 1), "The signed query was not answered");

			// before, the response to the signed query closed the connection at once, so this response was lost
			handler.Release();

			Assert.True(await connection.WaitForDisposeAsync(TimeSpan.FromSeconds(5)), "The connection was not closed after the signed query");
			Assert.Equal(2, connection.SentPackages);
		}
		finally
		{
			handler.Release();
			((IDisposable) server).Dispose();
		}
	}

	private static async Task<bool> WaitUntilAsync(Func<bool> condition)
	{
		var stopwatch = System.Diagnostics.Stopwatch.StartNew();
		while (stopwatch.Elapsed < TimeSpan.FromSeconds(10))
		{
			if (condition())
				return true;
			await Task.Delay(20);
		}

		return condition();
	}

	[Fact]
	public async Task DisposeAsync_AbortsQueryInProgress_AfterTheStopTimeout()
	{
		var handler = new BlockingQueryHandler();
		var connection = new FakeServerConnection(CreateQueryPackage());
		var transport = new FakeServerTransport(connection);

		var server = new DnsServer(transport) { StopTimeout = TimeSpan.FromMilliseconds(300) };
		server.QueryReceived += handler.HandleAsync;
		server.Start();

		try
		{
			Assert.True(await handler.WaitForQueryAsync(TimeSpan.FromSeconds(5)), "The query was not received");

			// before, disposing waited as long as the handler, like Stop it aborts the connection after the timeout now
			await CompletesWithinAsync(((IAsyncDisposable) server).DisposeAsync().AsTask(), TimeSpan.FromSeconds(5));

			Assert.True(await connection.WaitForDisposeAsync(TimeSpan.Zero), "The connection was not aborted");
			Assert.Equal(1, transport.CloseCalls);
		}
		finally
		{
			handler.Release();
		}
	}

	private static async Task AssertStopWaitsForQueryInProgressAsync(Func<DnsServer, Task> stop)
	{
		var handler = new BlockingQueryHandler();
		var connection = new FakeServerConnection(CreateQueryPackage());
		var transport = new FakeServerTransport(connection);

		var server = new DnsServer(transport);
		server.QueryReceived += handler.HandleAsync;
		server.Start();

		try
		{
			Assert.True(await handler.WaitForQueryAsync(TimeSpan.FromSeconds(5)), "The query was not received");

			var stopping = stop(server);
			Assert.False(await Task.WhenAny(stopping, Task.Delay(300)) == stopping, "The server stopped while a query was processed");

			// the response to the query in progress has to be sent over the transport
			Assert.Equal(0, transport.CloseCalls);

			handler.Release();

			Assert.True(await Task.WhenAny(stopping, Task.Delay(TimeSpan.FromSeconds(5))) == stopping, "The server did not stop after the query was processed");
			await stopping;
			Assert.Equal(1, connection.SentPackages);
			Assert.True(await connection.WaitForDisposeAsync(TimeSpan.Zero), "The connection was not disposed when the server stopped");
			Assert.Equal(1, transport.CloseCalls);
		}
		finally
		{
			handler.Release();
		}
	}

	[Fact]
	public async Task StopAsync_AbortsConnectionsInProgress_WhenTokenIsCanceled()
	{
		var handler = new BlockingQueryHandler();
		var connection = new FakeServerConnection(CreateQueryPackage());
		var transport = new FakeServerTransport(connection);

		var server = new DnsServer(transport);
		server.QueryReceived += handler.HandleAsync;
		server.Start();

		try
		{
			Assert.True(await handler.WaitForQueryAsync(TimeSpan.FromSeconds(5)), "The query was not received");

			using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
			var stopping = server.StopAsync(cts.Token);

			Assert.True(await Task.WhenAny(stopping, Task.Delay(TimeSpan.FromSeconds(5))) == stopping, "Stopping did not end when the token was canceled");
			await Assert.ThrowsAnyAsync<OperationCanceledException>(() => stopping);

			// stopping is no longer graceful, so the connection is aborted while its query is still processed
			Assert.True(await connection.WaitForDisposeAsync(TimeSpan.Zero), "The connection was not aborted");
			Assert.Equal(1, transport.CloseCalls);
		}
		finally
		{
			handler.Release();
		}
	}

	[Fact]
	public async Task StopAsync_WithoutStart_AndTwice_Completes()
	{
		var server = new DnsServer(new FakeServerTransport());

		await CompletesWithinAsync(server.StopAsync(), TimeSpan.FromSeconds(5));

		server.Start();
		await CompletesWithinAsync(server.StopAsync(), TimeSpan.FromSeconds(5));
		await CompletesWithinAsync(server.StopAsync(), TimeSpan.FromSeconds(5));
	}

	[Fact]
	public async Task StopAsync_ClosesAsyncClosableTransportsAsynchronously()
	{
		var plain = new FakeServerTransport();
		var asyncClosable = new AsyncFakeServerTransport();
		var server = new DnsServer(plain, asyncClosable);
		server.Start();

		await CompletesWithinAsync(server.StopAsync(), TimeSpan.FromSeconds(5));

		Assert.Equal(1, plain.CloseCalls);
		Assert.Equal(1, asyncClosable.CloseAsyncCalls);
		Assert.Equal(0, asyncClosable.CloseCalls);
	}

	[Fact]
	public async Task Stop_ClosesTheOtherTransports_WhenClosingOneFails()
	{
		var failing = new FakeServerTransport(throwOnClose: true);
		var other = new FakeServerTransport();
		var server = new DnsServer(failing, other);
		var exceptions = new List<Exception>();
		server.ExceptionThrown += (_, e) =>
		{
			lock (exceptions)
				exceptions.Add(e.Exception);
			return Task.CompletedTask;
		};
		server.Start();

		// before, the exception ended the stop, so the other transport stayed bound and the server could not be started again
		await CompletesWithinAsync(server.StopAsync(), TimeSpan.FromSeconds(5));

		Assert.Equal(1, other.CloseCalls);
		lock (exceptions)
			Assert.Contains(exceptions, e => e is InvalidOperationException);

		server.Start();
		await CompletesWithinAsync(server.StopAsync(), TimeSpan.FromSeconds(5));
		Assert.Equal(2, other.CloseCalls);

		((IDisposable) server).Dispose();
	}

	[Fact]
	public void Stop_ClosesAllTransportsSynchronously()
	{
		var asyncClosable = new AsyncFakeServerTransport();
		var server = new DnsServer(asyncClosable);
		server.Start();

		server.Stop();

		Assert.Equal(1, asyncClosable.CloseCalls);
		Assert.Equal(0, asyncClosable.CloseAsyncCalls);
	}

	[Fact]
	public void Dispose_DisposesTransports()
	{
		var plain = new FakeServerTransport();
		var asyncDisposable = new AsyncFakeServerTransport();
		var server = new DnsServer(plain, asyncDisposable);
		server.Start();

		((IDisposable) server).Dispose();

		Assert.Equal(1, plain.DisposeCalls);
		Assert.Equal(1, asyncDisposable.DisposeCalls);
	}

	[Fact]
	public void Dispose_Twice_StopsAndDisposesOnlyOnce()
	{
		var transport = new FakeServerTransport();
		var server = new DnsServer(transport);
		server.Start();

		((IDisposable) server).Dispose();
		var exception = Record.Exception(() => ((IDisposable) server).Dispose());

		Assert.Null(exception);
		Assert.Equal(1, transport.CloseCalls);
		Assert.Equal(1, transport.DisposeCalls);
	}

	[Fact]
	public async Task DisposeAsync_Twice_StopsAndDisposesOnlyOnce()
	{
		var transport = new FakeServerTransport();
		var server = new DnsServer(transport);
		server.Start();

		await CompletesWithinAsync(((IAsyncDisposable) server).DisposeAsync().AsTask(), TimeSpan.FromSeconds(5));
		await CompletesWithinAsync(((IAsyncDisposable) server).DisposeAsync().AsTask(), TimeSpan.FromSeconds(5));
		((IDisposable) server).Dispose();

		Assert.Equal(1, transport.CloseCalls);
		Assert.Equal(1, transport.DisposeCalls);
	}

	[Fact]
	public async Task Stop_AfterDispose_DoesNotStopAgain()
	{
		var transport = new FakeServerTransport();
		var server = new DnsServer(transport);
		server.Start();
		((IDisposable) server).Dispose();

		var exception = Record.Exception(server.Stop);
		await CompletesWithinAsync(server.StopAsync(), TimeSpan.FromSeconds(5));

		Assert.Null(exception);
		Assert.Equal(1, transport.CloseCalls);
	}

	[Fact]
	public void Start_AfterDispose_Throws()
	{
		var transport = new FakeServerTransport();
		var server = new DnsServer(transport);
		((IDisposable) server).Dispose();

		Assert.Throws<ObjectDisposedException>(server.Start);
	}

	[Fact]
	public async Task StopAndStopAsync_Concurrently_WaitForTheSameStop()
	{
		var (server, transport, connection, handler) = await StartWithQueryInProgressAsync();

		try
		{
			var stops = new[] { server.StopAsync(), Task.Run(server.Stop), server.StopAsync() };
			Assert.False(await Task.WhenAny(Task.WhenAll(stops), Task.Delay(300)) == Task.WhenAll(stops), "A stop ended while a query was processed");

			handler.Release();

			await CompletesWithinAsync(Task.WhenAll(stops), TimeSpan.FromSeconds(5));
			Assert.Equal(1, connection.SentPackages);
			Assert.Equal(1, transport.CloseCalls);
		}
		finally
		{
			handler.Release();
		}
	}

	[Fact]
	public async Task Dispose_WhileStopping_WaitsForTheStop_BeforeDisposingTheTransports()
	{
		var (server, transport, connection, handler) = await StartWithQueryInProgressAsync();

		try
		{
			var stopping = server.StopAsync();
			var disposing = Task.Run(() => ((IDisposable) server).Dispose());

			Assert.False(await Task.WhenAny(disposing, Task.Delay(300)) == disposing, "The server was disposed while it was stopping");
			Assert.Equal(0, transport.DisposeCalls);

			handler.Release();

			await CompletesWithinAsync(Task.WhenAll(stopping, disposing), TimeSpan.FromSeconds(5));
			await stopping;
			await disposing;
			Assert.Equal(1, connection.SentPackages);
			Assert.Equal(1, transport.CloseCalls);
			Assert.Equal(1, transport.DisposeCalls);
		}
		finally
		{
			handler.Release();
		}
	}

	[Fact]
	public async Task StopAsync_TokenOfAnyCaller_AbortsTheSharedStop()
	{
		var (server, transport, connection, handler) = await StartWithQueryInProgressAsync();

		try
		{
			var graceful = server.StopAsync();

			using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
			var impatient = server.StopAsync(cts.Token);

			// only the caller, whose token was canceled, is told that the stop was not graceful
			await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CompletesWithinAsync(impatient, TimeSpan.FromSeconds(5)));
			await CompletesWithinAsync(graceful, TimeSpan.FromSeconds(5));

			Assert.True(await connection.WaitForDisposeAsync(TimeSpan.Zero), "The connection was not aborted");
			Assert.Equal(0, connection.SentPackages);
			Assert.Equal(1, transport.CloseCalls);
		}
		finally
		{
			handler.Release();
		}
	}

	[Fact]
	public async Task Start_WhileStartedOrStopping_Throws()
	{
		var (server, transport, _, handler) = await StartWithQueryInProgressAsync();

		try
		{
			Assert.Throws<InvalidOperationException>(server.Start);

			var stopping = server.StopAsync();
			Assert.Throws<InvalidOperationException>(server.Start);

			handler.Release();
			await CompletesWithinAsync(stopping, TimeSpan.FromSeconds(5));
			Assert.Equal(1, transport.BindCalls);
		}
		finally
		{
			handler.Release();
		}
	}

	[Fact]
	public async Task Start_AfterStop_StartsAgain()
	{
		var transport = new FakeServerTransport();
		var server = new DnsServer(transport);

		server.Start();
		await CompletesWithinAsync(server.StopAsync(), TimeSpan.FromSeconds(5));
		server.Start();
		await CompletesWithinAsync(server.StopAsync(), TimeSpan.FromSeconds(5));

		Assert.Equal(2, transport.BindCalls);
		Assert.Equal(2, transport.CloseCalls);
	}

	[Fact]
	public void Start_WhenATransportFailsToBind_ClosesTheTransportsBoundAlready()
	{
		var bound = new FakeServerTransport();
		var failing = new FakeServerTransport(throwOnBind: true);
		var notBound = new FakeServerTransport();
		var server = new DnsServer(bound, failing, notBound);

		var exception = Assert.Throws<SocketException>(server.Start);

		Assert.Equal(SocketError.AddressAlreadyInUse, exception.SocketErrorCode);
		Assert.Equal(1, bound.CloseCalls);
		Assert.Equal(0, failing.CloseCalls);
		Assert.Equal(0, notBound.BindCalls);

		// the server was not started, so starting is tried again instead of failing as already started
		Assert.Throws<SocketException>(server.Start);
	}

	[Fact]
	public void Start_WhenUdpPortIsInUse_ReleasesTheTcpPortAgain()
	{
		var (udpBlocker, endpoint) = BlockUdpPortWithFreeTcpPort();

		using (udpBlocker)
		{
			var server = new DnsServer(new TcpServerTransport(endpoint), new UdpServerTransport(endpoint));

			try
			{
				var exception = Assert.Throws<SocketException>(server.Start);
				Assert.Equal(SocketError.AddressAlreadyInUse, exception.SocketErrorCode);

				var listener = new TcpListener(endpoint);
				listener.Start();
				listener.Stop();
			}
			finally
			{
				((IDisposable) server).Dispose();
			}
		}
	}

	/// <summary>
	///   Binds a UDP port on loopback, whose TCP port with the same number is free
	/// </summary>
	private static (UdpClient UdpBlocker, IPEndPoint EndPoint) BlockUdpPortWithFreeTcpPort()
	{
		for (var attempt = 0; ; attempt++)
		{
			var udpBlocker = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
			var endpoint = new IPEndPoint(IPAddress.Loopback, ((IPEndPoint) udpBlocker.Client.LocalEndPoint!).Port);

			try
			{
				var probe = new TcpListener(endpoint);
				probe.Start();
				probe.Stop();
				return (udpBlocker, endpoint);
			}
			catch (SocketException) when (attempt < 10)
			{
				udpBlocker.Dispose();
			}
		}
	}

	/// <summary>
	///   Starts a server, whose transport delivers a single query, which is processed until the handler is released
	/// </summary>
	private static async Task<(DnsServer Server, FakeServerTransport Transport, FakeServerConnection Connection, BlockingQueryHandler Handler)> StartWithQueryInProgressAsync()
	{
		var handler = new BlockingQueryHandler();
		var connection = new FakeServerConnection(CreateQueryPackage());
		var transport = new FakeServerTransport(connection);

		var server = new DnsServer(transport);
		server.QueryReceived += handler.HandleAsync;
		server.Start();

		Assert.True(await handler.WaitForQueryAsync(TimeSpan.FromSeconds(5)), "The query was not received");
		return (server, transport, connection, handler);
	}

	[Fact]
	public async Task DisposeAsync_DisposesTransportsAsynchronously()
	{
		var plain = new FakeServerTransport();
		var asyncDisposable = new AsyncFakeServerTransport();
		var server = new DnsServer(plain, asyncDisposable);
		server.Start();

		await CompletesWithinAsync(((IAsyncDisposable) server).DisposeAsync().AsTask(), TimeSpan.FromSeconds(5));

		Assert.Equal(1, plain.DisposeCalls);
		Assert.Equal(1, asyncDisposable.DisposeAsyncCalls);
		Assert.Equal(0, asyncDisposable.DisposeCalls);
	}

	[Fact]
	public async Task StopAsync_ClosesIdleTcpConnections_WithoutWaitingForKeepAlive()
	{
		var (server, port) = StartServer(endpoint => new TcpServerTransport(endpoint, keepAlive: 120000), AnswerQuery);

		using var client = new TcpClient();
		await client.ConnectAsync(IPAddress.Loopback, port);
		await Task.Delay(200);

		var stopwatch = System.Diagnostics.Stopwatch.StartNew();
		await CompletesWithinAsync(server.StopAsync(), TimeSpan.FromSeconds(5));

		Assert.InRange(stopwatch.Elapsed, TimeSpan.Zero, TimeSpan.FromSeconds(2));
		Assert.True(await TransportTests.WaitForRemoteCloseAsync(client, TimeSpan.FromSeconds(5)), "The idle connection was not closed");
	}

	[Fact]
	public async Task StopAsync_AnswersTcpQueryInProgress_BeforeClosingTheConnection()
	{
		var handler = new BlockingQueryHandler();
		var (server, port) = StartServer(endpoint => new TcpServerTransport(endpoint), handler.HandleAsync);

		try
		{
			using var client = new TcpClient();
			await client.ConnectAsync(IPAddress.Loopback, port);
			var stream = client.GetStream();
			var query = EncodeQuery(0x5151, withLengthPrefix: true);
			await stream.WriteAsync(query, 0, query.Length);
			Assert.True(await handler.WaitForQueryAsync(TimeSpan.FromSeconds(5)), "The query was not received");

			var stopping = server.StopAsync();
			await Task.Delay(300);
			handler.Release();

			var response = await TcpTransportTests.ReadResponseAsync(stream);
			Assert.Equal(0x5151, response.TransactionID);

			await CompletesWithinAsync(stopping, TimeSpan.FromSeconds(5));
			Assert.True(await TransportTests.WaitForRemoteCloseAsync(client, TimeSpan.FromSeconds(5)), "The connection was not closed after the response");
		}
		finally
		{
			handler.Release();
			((IDisposable) server).Dispose();
		}
	}

	[Fact]
	public async Task StopAsync_AnswersUdpQueryInProgress_BeforeClosingTheSocket()
	{
		var handler = new BlockingQueryHandler();
		var (server, port) = StartServer(endpoint => new UdpServerTransport(endpoint), handler.HandleAsync);

		try
		{
			using var client = new UdpClient(AddressFamily.InterNetwork);
			client.Connect(IPAddress.Loopback, port);
			var query = EncodeQuery(0x6161, withLengthPrefix: false);
			await client.SendAsync(query, query.Length);
			Assert.True(await handler.WaitForQueryAsync(TimeSpan.FromSeconds(5)), "The query was not received");

			var stopping = server.StopAsync();
			await Task.Delay(300);
			handler.Release();

			var receive = client.ReceiveAsync();
			Assert.True(await Task.WhenAny(receive, Task.Delay(TimeSpan.FromSeconds(5))) == receive, "The query in progress was not answered");
			Assert.Equal(0x6161, DnsMessage.Parse(new ArraySegment<byte>((await receive).Buffer)).TransactionID);

			await CompletesWithinAsync(stopping, TimeSpan.FromSeconds(5));
		}
		finally
		{
			handler.Release();
			((IDisposable) server).Dispose();
		}
	}

	private static byte[] EncodeQuery(ushort transactionId, bool withLengthPrefix)
	{
		var query = new DnsMessage { TransactionID = transactionId };
		query.Questions.Add(new DnsQuestion(_name, RecordType.A, RecordClass.INet));
		return query.Encode().ToArraySegment(withLengthPrefix).ToArray();
	}

	[Fact]
	public async Task Server_WithUdpAndTcp_AnswersQueries_AfterRestart()
	{
		var (server, port) = StartServer(endpoint => new IServerTransport[] { new UdpServerTransport(endpoint), new TcpServerTransport(endpoint) }, AnswerQuery);

		try
		{
			await AssertUdpAndTcpAreAnsweredAsync(port, 0x7171);

			await CompletesWithinAsync(server.StopAsync(), TimeSpan.FromSeconds(5));
			server.Start();

			await AssertUdpAndTcpAreAnsweredAsync(port, 0x7272);
		}
		finally
		{
			((IDisposable) server).Dispose();
		}
	}

	private static async Task AssertUdpAndTcpAreAnsweredAsync(int port, ushort transactionId)
	{
		using (var udpClient = new UdpClient(AddressFamily.InterNetwork))
		{
			udpClient.Connect(IPAddress.Loopback, port);
			var query = EncodeQuery(transactionId, withLengthPrefix: false);
			await udpClient.SendAsync(query, query.Length);

			var receive = udpClient.ReceiveAsync();
			Assert.True(await Task.WhenAny(receive, Task.Delay(TimeSpan.FromSeconds(5))) == receive, "The UDP query was not answered");
			Assert.Equal(transactionId, DnsMessage.Parse(new ArraySegment<byte>((await receive).Buffer)).TransactionID);
		}

		using (var tcpClient = new TcpClient())
		{
			await tcpClient.ConnectAsync(IPAddress.Loopback, port);
			var stream = tcpClient.GetStream();
			var query = EncodeQuery(transactionId, withLengthPrefix: true);
			await stream.WriteAsync(query, 0, query.Length);

			Assert.Equal(transactionId, (await TcpTransportTests.ReadResponseAsync(stream)).TransactionID);
		}
	}

	private static (DnsServer Server, int Port) StartServer(Func<IPEndPoint, IServerTransport> createTransport, AsyncEventHandler<QueryReceivedEventArgs> handler)
	{
		return StartServer(endpoint => new[] { createTransport(endpoint) }, handler);
	}

	private static (DnsServer Server, int Port) StartServer(Func<IPEndPoint, IServerTransport[]> createTransports, AsyncEventHandler<QueryReceivedEventArgs> handler)
	{
		// another process may take the free port before the server binds it
		for (var attempt = 1;; attempt++)
		{
			var port = LocalDnsServer.GetFreePort();
			var server = new DnsServer(createTransports(new IPEndPoint(IPAddress.Loopback, port)));
			server.QueryReceived += handler;

			try
			{
				server.Start();
				return (server, port);
			}
			catch (SocketException) when (attempt < 5)
			{
				((IDisposable) server).Dispose();
			}
		}
	}

	private static async Task CompletesWithinAsync(Task task, TimeSpan timeout)
	{
		Assert.True(await Task.WhenAny(task, Task.Delay(timeout)) == task, $"The task did not complete within {timeout}");
		await task;
	}

	/// <summary>
	///   Answers queries only after it was released
	/// </summary>
	private sealed class BlockingQueryHandler
	{
		private readonly TaskCompletionSource<bool> _received = new(TaskCreationOptions.RunContinuationsAsynchronously);
		private readonly TaskCompletionSource<bool> _released = new(TaskCreationOptions.RunContinuationsAsynchronously);

		public async Task HandleAsync(object sender, QueryReceivedEventArgs e)
		{
			_received.TrySetResult(true);
			await _released.Task;
			await AnswerQuery(sender, e);
		}

		public async Task<bool> WaitForQueryAsync(TimeSpan timeout)
		{
			return await Task.WhenAny(_received.Task, Task.Delay(timeout)) == _received.Task;
		}

		public void Release() => _released.TrySetResult(true);
	}

	private static Task AnswerQuery(object sender, QueryReceivedEventArgs e)
	{
		var query = (DnsMessage) e.Query;
		var response = query.CreateResponseInstance();
		response.AnswerRecords.Add(new ARecord(query.Questions[0].Name, 60, IPAddress.Parse("192.0.2.1")));
		e.Response = response;
		return Task.CompletedTask;
	}

	/// <summary>
	///   A TSIG signed query. The server has no key, so it answers with BADKEY, which is signed as well.
	/// </summary>
	private static DnsReceivedRawPackage CreateSignedQueryPackage()
	{
		var query = new DnsMessage { TransactionID = 0x1111 };
		query.Questions.Add(new DnsQuestion(_name, RecordType.A, RecordClass.INet));
		query.TSigOptions = new TSigRecord(DomainName.Parse("key.example.test"), TSigAlgorithm.Sha256, DateTime.Now, TimeSpan.FromMinutes(5), 0x1111, ReturnCode.NoError, null, new byte[32]);

		return new DnsReceivedRawPackage(query.Encode().ToArraySegment(true).ToArray(), new IPEndPoint(IPAddress.Loopback, 50000), new IPEndPoint(IPAddress.Loopback, 53));
	}

	internal static DnsReceivedRawPackage CreateQueryPackage()
	{
		var query = new DnsMessage { TransactionID = 0x4242 };
		query.Questions.Add(new DnsQuestion(_name, RecordType.A, RecordClass.INet));

		return new DnsReceivedRawPackage(query.Encode().ToArraySegment(true).ToArray(), new IPEndPoint(IPAddress.Loopback, 50000), new IPEndPoint(IPAddress.Loopback, 53));
	}

	private sealed class FakeServerTransport : IServerTransport
	{
		private readonly FakeServerConnection? _connection;
		private readonly bool _alwaysReturnNull;
		private bool _throwOnNextAccept;
		private bool _connectionDelivered;
		private int _acceptCalls;
		private int _bindCalls;
		private int _closeCalls;
		private int _disposeCalls;

		private int _remainingFailedAccepts;
		private readonly bool _throwOnBind;
		private readonly bool _throwOnClose;

		public FakeServerTransport(FakeServerConnection? connection = null, bool alwaysReturnNull = false, bool throwOnFirstAccept = false, int failedAcceptsBeforeConnection = 0, bool throwOnBind = false, bool throwOnClose = false)
		{
			_connection = connection;
			_alwaysReturnNull = alwaysReturnNull;
			_throwOnNextAccept = throwOnFirstAccept;
			_remainingFailedAccepts = failedAcceptsBeforeConnection;
			_throwOnBind = throwOnBind;
			_throwOnClose = throwOnClose;
		}

		public int AcceptCalls => Volatile.Read(ref _acceptCalls);

		public int BindCalls => Volatile.Read(ref _bindCalls);

		public int CloseCalls => Volatile.Read(ref _closeCalls);

		public int DisposeCalls => Volatile.Read(ref _disposeCalls);

		public ushort DefaultAllowedResponseSize => UInt16.MaxValue;
		public bool SupportsMultipleResponses => true;
		public bool AllowTruncatedResponses => false;
		public TransportProtocol TransportProtocol => TransportProtocol.Tcp;

		public void Bind()
		{
			Interlocked.Increment(ref _bindCalls);

			if (_throwOnBind)
				throw new SocketException((int) SocketError.AddressAlreadyInUse);
		}

		public void Close()
		{
			Interlocked.Increment(ref _closeCalls);

			if (_throwOnClose)
				throw new InvalidOperationException("Closing failed");
		}

		public async Task<IServerConnection?> AcceptConnectionAsync(CancellationToken token = default)
		{
			Interlocked.Increment(ref _acceptCalls);

			if (_alwaysReturnNull)
				return null;

			if (_remainingFailedAccepts > 0)
			{
				_remainingFailedAccepts--;
				return null;
			}

			if (_throwOnNextAccept)
			{
				_throwOnNextAccept = false;
				throw new InvalidOperationException("Accept failed");
			}

			if (!_connectionDelivered && _connection != null)
			{
				_connectionDelivered = true;
				_connection.Transport = this;
				return _connection;
			}

			try
			{
				// no further connections, wait until the server is stopped
				await Task.Delay(Timeout.Infinite, token);
			}
			catch (OperationCanceledException)
			{
				// server stopped
			}

			return null;
		}

		public void Dispose() => Interlocked.Increment(ref _disposeCalls);
	}

	/// <summary>
	///   A transport without connections, which can be closed and disposed asynchronously
	/// </summary>
	private sealed class AsyncFakeServerTransport : IAsyncClosableServerTransport, IAsyncDisposable
	{
		private int _closeCalls;
		private int _closeAsyncCalls;
		private int _disposeCalls;
		private int _disposeAsyncCalls;

		public int CloseCalls => Volatile.Read(ref _closeCalls);
		public int CloseAsyncCalls => Volatile.Read(ref _closeAsyncCalls);
		public int DisposeCalls => Volatile.Read(ref _disposeCalls);
		public int DisposeAsyncCalls => Volatile.Read(ref _disposeAsyncCalls);

		public ushort DefaultAllowedResponseSize => UInt16.MaxValue;
		public bool SupportsMultipleResponses => true;
		public bool AllowTruncatedResponses => false;
		public TransportProtocol TransportProtocol => TransportProtocol.Tcp;

		public void Bind() { }

		public void Close() => Interlocked.Increment(ref _closeCalls);

		public async Task CloseAsync(CancellationToken token = default)
		{
			await Task.Yield();
			Interlocked.Increment(ref _closeAsyncCalls);
		}

		public async Task<IServerConnection?> AcceptConnectionAsync(CancellationToken token = default)
		{
			try
			{
				await Task.Delay(Timeout.Infinite, token);
			}
			catch (OperationCanceledException)
			{
				// server stopped
			}

			return null;
		}

		public void Dispose() => Interlocked.Increment(ref _disposeCalls);

		public async ValueTask DisposeAsync()
		{
			await Task.Yield();
			Interlocked.Increment(ref _disposeAsyncCalls);
		}
	}

	internal sealed class FakeServerConnection : IServerConnection
	{
		private readonly Queue<DnsReceivedRawPackage?> _packages;
		private readonly TaskCompletionSource<bool> _disposed = new(TaskCreationOptions.RunContinuationsAsynchronously);
		private int _sentPackages;

		public FakeServerConnection(params DnsReceivedRawPackage[] packages)
		{
			_packages = new Queue<DnsReceivedRawPackage?>(packages);
		}

		public int SentPackages => Volatile.Read(ref _sentPackages);

		public IServerTransport Transport { get; set; } = null!;
		public IPEndPoint RemoteEndPoint { get; } = new(IPAddress.Loopback, 50000);
		public IPEndPoint LocalEndPoint { get; } = new(IPAddress.Loopback, 53);
		public bool CanRead => !_disposed.Task.IsCompleted;

		public Task<bool> InitializeAsync(CancellationToken token = default) => Task.FromResult(true);

		public Task<DnsReceivedRawPackage?> ReceiveAsync(CancellationToken token = default)
		{
			lock (_packages)
			{
				// null signals the end of the stream, like a TCP connection closed by the client
				return Task.FromResult(_packages.Count > 0 ? _packages.Dequeue() : null);
			}
		}

		public Task<bool> SendAsync(DnsRawPackage package, CancellationToken token = default)
		{
			// like a real connection, a closed one sends nothing anymore
			if (_disposed.Task.IsCompleted)
				return Task.FromResult(false);

			Interlocked.Increment(ref _sentPackages);
			return Task.FromResult(true);
		}

		public async Task<bool> WaitForDisposeAsync(TimeSpan timeout)
		{
			return await Task.WhenAny(_disposed.Task, Task.Delay(timeout)) == _disposed.Task;
		}

		public void Dispose()
		{
			_disposed.TrySetResult(true);
		}
	}
}
