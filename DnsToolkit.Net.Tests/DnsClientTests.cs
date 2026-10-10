using System.Net;
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

public class DnsClientTests
{
	private static readonly DomainName _name = DomainName.Parse("host.example.test");

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
