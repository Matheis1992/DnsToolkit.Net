using System.Net;
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

	private static Task AnswerQuery(object sender, QueryReceivedEventArgs e)
	{
		var query = (DnsMessage) e.Query;
		var response = query.CreateResponseInstance();
		response.AnswerRecords.Add(new ARecord(query.Questions[0].Name, 60, IPAddress.Parse("192.0.2.1")));
		e.Response = response;
		return Task.CompletedTask;
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

		public FakeServerTransport(FakeServerConnection? connection = null, bool alwaysReturnNull = false, bool throwOnFirstAccept = false)
		{
			_connection = connection;
			_alwaysReturnNull = alwaysReturnNull;
			_throwOnNextAccept = throwOnFirstAccept;
		}

		public int AcceptCalls => Volatile.Read(ref _acceptCalls);

		public ushort DefaultAllowedResponseSize => UInt16.MaxValue;
		public bool SupportsMultipleResponses => true;
		public bool AllowTruncatedResponses => false;
		public TransportProtocol TransportProtocol => TransportProtocol.Tcp;

		public void Bind() { }

		public void Close() { }

		public async Task<IServerConnection?> AcceptConnectionAsync(CancellationToken token = default)
		{
			Interlocked.Increment(ref _acceptCalls);

			if (_alwaysReturnNull)
				return null;

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

		public void Dispose() { }
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
