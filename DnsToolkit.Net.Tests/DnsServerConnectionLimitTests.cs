using System.Diagnostics;
using System.Net;
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

public class DnsServerConnectionLimitTests
{
	[Fact]
	public async Task ConcurrentConnections_AreLimited()
	{
		var transport = new EndlessTransport();
		var server = new DnsServer(transport) { MaxConcurrentConnectionsPerTransport = 5 };
		try
		{
			server.Start();

			Assert.True(await WaitUntilAsync(() => transport.Accepted == 5), $"{transport.Accepted} connections accepted");
			await Task.Delay(300);
			Assert.Equal(5, transport.Accepted);

			// closing one connection frees a slot for the next one
			transport.Connections.First().Close();

			Assert.True(await WaitUntilAsync(() => transport.Accepted == 6), $"{transport.Accepted} connections accepted after one was closed");
			await Task.Delay(300);
			Assert.Equal(6, transport.Accepted);
		}
		finally
		{
			((IDisposable) server).Dispose();
			transport.CloseAll();
		}
	}

	[Fact]
	public async Task RefusedConnections_ReleaseTheirSlot()
	{
		var transport = new EndlessTransport(maxConnections: 20);
		var server = new DnsServer(transport) { MaxConcurrentConnectionsPerTransport = 2 };
		server.ClientConnected += (_, e) =>
		{
			e.RefuseConnect = true;
			return Task.CompletedTask;
		};

		try
		{
			server.Start();

			Assert.True(await WaitUntilAsync(() => transport.Accepted == 20 && transport.Connections.All(c => c.IsDisposed)),
				$"{transport.Accepted} connections accepted, {transport.Connections.Count(c => c.IsDisposed)} disposed");
		}
		finally
		{
			((IDisposable) server).Dispose();
		}
	}

	[Fact]
	public async Task Limit_AppliesToEachTransportSeparately()
	{
		var first = new EndlessTransport();
		var second = new EndlessTransport();
		var server = new DnsServer(first, second) { MaxConcurrentConnectionsPerTransport = 1 };
		try
		{
			server.Start();

			// the open connection of the first transport does not block the second one
			Assert.True(await WaitUntilAsync(() => first.Accepted == 1 && second.Accepted == 1), $"accepted: {first.Accepted} and {second.Accepted}");
		}
		finally
		{
			((IDisposable) server).Dispose();
			first.CloseAll();
			second.CloseAll();
		}
	}

	[Theory]
	[InlineData(0)]
	[InlineData(-1)]
	public void Limit_MustAllowAtLeastOneConnection(int limit)
	{
		var server = new DnsServer(new EndlessTransport());

		Assert.Throws<ArgumentOutOfRangeException>(() => server.MaxConcurrentConnectionsPerTransport = limit);
	}

	private static async Task<bool> WaitUntilAsync(Func<bool> condition)
	{
		var stopwatch = Stopwatch.StartNew();
		while (stopwatch.Elapsed < TimeSpan.FromSeconds(5))
		{
			if (condition())
				return true;
			await Task.Delay(20);
		}

		return condition();
	}

	/// <summary>
	///   Delivers a new connection on every accept, optionally up to a maximum number
	/// </summary>
	private sealed class EndlessTransport : IServerTransport
	{
		private readonly int _maxConnections;
		private readonly List<HoldingConnection> _connections = new();

		public EndlessTransport(int maxConnections = Int32.MaxValue)
		{
			_maxConnections = maxConnections;
		}

		public int Accepted
		{
			get
			{
				lock (_connections)
					return _connections.Count;
			}
		}

		public List<HoldingConnection> Connections
		{
			get
			{
				lock (_connections)
					return _connections.ToList();
			}
		}

		public void CloseAll()
		{
			foreach (var connection in Connections)
				connection.Close();
		}

		public ushort DefaultAllowedResponseSize => UInt16.MaxValue;
		public bool SupportsMultipleResponses => true;
		public bool AllowTruncatedResponses => false;
		public TransportProtocol TransportProtocol => TransportProtocol.Tcp;

		public void Bind() { }

		public void Close() { }

		public async Task<IServerConnection?> AcceptConnectionAsync(CancellationToken token = default)
		{
			lock (_connections)
			{
				if (_connections.Count < _maxConnections)
				{
					var connection = new HoldingConnection(this);
					_connections.Add(connection);
					return connection;
				}
			}

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

		public void Dispose() { }
	}

	/// <summary>
	///   A connection on which the client sends nothing, until it is closed by the test
	/// </summary>
	private sealed class HoldingConnection : IServerConnection
	{
		private readonly TaskCompletionSource<DnsReceivedRawPackage?> _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
		private int _isDisposed;

		public HoldingConnection(IServerTransport transport)
		{
			Transport = transport;
		}

		public bool IsDisposed => Volatile.Read(ref _isDisposed) == 1;

		public void Close() => _closed.TrySetResult(null);

		public IServerTransport Transport { get; }
		public IPEndPoint RemoteEndPoint { get; } = new(IPAddress.Loopback, 50000);
		public IPEndPoint LocalEndPoint { get; } = new(IPAddress.Loopback, 53);
		public bool CanRead => !IsDisposed;

		public Task<bool> InitializeAsync(CancellationToken token = default) => Task.FromResult(true);

		public Task<DnsReceivedRawPackage?> ReceiveAsync(CancellationToken token = default)
		{
			// like a TCP connection, which ends without a further query when the server stops
			token.Register(Close);
			return _closed.Task;
		}

		public Task<bool> SendAsync(DnsRawPackage package, CancellationToken token = default) => Task.FromResult(true);

		public void Dispose()
		{
			Volatile.Write(ref _isDisposed, 1);
			Close();
		}
	}
}
