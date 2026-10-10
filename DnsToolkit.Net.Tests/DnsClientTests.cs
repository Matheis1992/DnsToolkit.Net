using System.Net;
using System.Net.Sockets;
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

public class DnsClientTests
{
	private static readonly DomainName _name = DomainName.Parse("host.example.test");

	[Fact]
	public async Task Tcp_QueryTimeout_DoesNotAbortOtherQueriesOnSameConnection()
	{
		// "slow" is never answered, "fast" is answered after 700 ms
		using var server = new ScriptedTcpDnsServer(query => query.Questions[0].Name.Labels[0] == "slow"
			? null
			: (TimeSpan.FromMilliseconds(700), Answer(query)));
		using var client = new DnsClient(new[] { IPAddress.Loopback }, new IClientTransport[] { new TcpClientTransport(server.Port) }, true, 1000);

		// The slow query opens the pooled connection and times out after 1 s.
		// The fast query uses the same connection and is answered at about 1.2 s, after the slow query timed out.
		var slow = client.ResolveAsync(DomainName.Parse("slow.example.test"));
		await Task.Delay(500);
		var fast = client.ResolveAsync(DomainName.Parse("fast.example.test"));

		var fastResponse = await fast;
		Assert.Null(await slow);

		Assert.NotNull(fastResponse);
		Assert.Single(fastResponse!.AnswerRecords);
		Assert.Equal(1, server.ConnectionCount);
	}

	private static DnsMessage Answer(DnsMessage query)
	{
		var response = query.CreateResponseInstance();
		response.AnswerRecords.Add(new ARecord(query.Questions[0].Name, 60, IPAddress.Parse("192.0.2.1")));
		return response;
	}

	/// <summary>
	///   A DNS server over TCP, which answers each query of a connection independently after the given delay
	/// </summary>
	private sealed class ScriptedTcpDnsServer : IDisposable
	{
		private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
		private readonly Func<DnsMessage, (TimeSpan Delay, DnsMessage Response)?> _handler;
		private readonly List<TcpClient> _clients = new();
		private int _connectionCount;

		public ScriptedTcpDnsServer(Func<DnsMessage, (TimeSpan Delay, DnsMessage Response)?> handler)
		{
			_handler = handler;
			_listener.Start();
			_ = AcceptLoopAsync();
		}

		public int Port => ((IPEndPoint) _listener.LocalEndpoint).Port;

		public int ConnectionCount => Volatile.Read(ref _connectionCount);

		private async Task AcceptLoopAsync()
		{
			while (true)
			{
				TcpClient client;
				try
				{
					client = await _listener.AcceptTcpClientAsync();
				}
				catch
				{
					return; // listener stopped
				}

				Interlocked.Increment(ref _connectionCount);
				lock (_clients)
					_clients.Add(client);

				_ = HandleConnectionAsync(client.GetStream());
			}
		}

		private async Task HandleConnectionAsync(NetworkStream stream)
		{
			var writeLock = new SemaphoreSlim(1);

			try
			{
				while (true)
				{
					var header = await ReadExactAsync(stream, 2);
					var length = (header[0] << 8) | header[1];
					var query = DnsMessage.Parse(new ArraySegment<byte>(await ReadExactAsync(stream, length)));

					var answer = _handler(query);
					if (answer != null)
						_ = RespondAsync(stream, writeLock, answer.Value.Delay, answer.Value.Response);
				}
			}
			catch
			{
				// connection closed
			}
		}

		private static async Task RespondAsync(NetworkStream stream, SemaphoreSlim writeLock, TimeSpan delay, DnsMessage response)
		{
			await Task.Delay(delay);
			var data = response.Encode().ToArraySegment(true).ToArray();

			await writeLock.WaitAsync();
			try
			{
				await stream.WriteAsync(data, 0, data.Length);
			}
			catch
			{
				// connection closed
			}
			finally
			{
				writeLock.Release();
			}
		}

		private static async Task<byte[]> ReadExactAsync(NetworkStream stream, int length)
		{
			var buffer = new byte[length];
			var read = 0;
			while (read < length)
			{
				var count = await stream.ReadAsync(buffer, read, length - read);
				if (count == 0)
					throw new IOException("Connection closed");
				read += count;
			}

			return buffer;
		}

		public void Dispose()
		{
			_listener.Stop();
			lock (_clients)
			{
				foreach (var client in _clients)
					client.Dispose();
			}
		}
	}

	[Fact]
	public async Task TruncatedMulticastResponse_IsResentOverReliableTransport()
	{
		var multicast = new FakeClientTransport(isMulticast: true, query => { var r = query.CreateResponseInstance(); r.IsTruncated = true; return r; });
		var reliable = new FakeClientTransport(isMulticast: false, query =>
		{
			var r = query.CreateResponseInstance();
			r.AnswerRecords.Add(new ARecord(query.Questions[0].Name, 60, IPAddress.Parse("192.0.2.1")));
			return r;
		});

		using var client = new ParallelTestClient(multicast, reliable);
		var query = new DnsMessage();
		query.Questions.Add(new DnsQuestion(_name, RecordType.A, RecordClass.INet));

		var results = await client.QueryAsync(query);

		var result = Assert.Single(results);
		Assert.False(result.IsTruncated, "The truncated response was returned instead of resending the query over the reliable transport");
		Assert.Single(result.AnswerRecords);
	}

	private sealed class ParallelTestClient : DnsClientBase
	{
		public ParallelTestClient(params IClientTransport[] transports)
			: base(new[] { IPAddress.Loopback }, 1000, transports, false) { }

		public Task<List<DnsMessage>> QueryAsync(DnsMessage message) => SendMessageParallelAsync(message, default);
	}

	private sealed class FakeClientTransport : IClientTransport
	{
		private readonly bool _isMulticast;
		private readonly Func<DnsMessage, DnsMessage> _createResponse;

		public FakeClientTransport(bool isMulticast, Func<DnsMessage, DnsMessage> createResponse)
		{
			_isMulticast = isMulticast;
			_createResponse = createResponse;
		}

		public ushort MaximumAllowedQuerySize => _isMulticast ? (ushort) 512 : UInt16.MaxValue;
		public bool SupportsReliableTransfer => !_isMulticast;
		public bool SupportsMulticastTransfer => _isMulticast;
		public bool SupportsPooledConnections => false;

		public Task<IClientConnection?> ConnectAsync(DnsClientEndpointInfo endpointInfo, int queryTimeout, CancellationToken token = default)
			=> Task.FromResult<IClientConnection?>(new FakeClientConnection(this, _createResponse));

		public Task<IClientConnection?> GetPooledConnectionAsync(DnsClientEndpointInfo endpointInfo, CancellationToken token = default)
			=> Task.FromResult<IClientConnection?>(null);

		public void Dispose() { }
	}

	private sealed class FakeClientConnection : IClientConnection
	{
		private readonly Func<DnsMessage, DnsMessage> _createResponse;
		private DnsReceivedRawPackage? _response;

		public FakeClientConnection(IClientTransport transport, Func<DnsMessage, DnsMessage> createResponse)
		{
			Transport = transport;
			_createResponse = createResponse;
		}

		public IClientTransport Transport { get; }
		public bool IsFaulty { get; private set; }

		public Task<bool> SendAsync(DnsRawPackage package, CancellationToken token = default)
		{
			var query = DnsMessage.Parse(package.ToArraySegment(false));
			var response = _createResponse(query);
			_response = new DnsReceivedRawPackage(response.Encode().ToArraySegment(true).ToArray(), new IPEndPoint(IPAddress.Loopback, 5355), new IPEndPoint(IPAddress.Loopback, 50000));
			return Task.FromResult(true);
		}

		public async Task<DnsReceivedRawPackage?> ReceiveAsync(DnsMessageIdentification identification, CancellationToken token = default)
		{
			var response = Interlocked.Exchange(ref _response, null);
			if (response != null)
				return response;

			// only one response, then wait for the end of the query
			try
			{
				await Task.Delay(Timeout.Infinite, token);
			}
			catch (OperationCanceledException)
			{
				// query finished
			}

			return null;
		}

		public void RestartIdleTimeout(TimeSpan? timeout) { }

		public void MarkFaulty() => IsFaulty = true;

		public void Dispose() { }
	}
}
