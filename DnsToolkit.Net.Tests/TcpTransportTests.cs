using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

public class TcpTransportTests
{
	private static readonly DomainName _name = DomainName.Parse("host.example.test");
	private static readonly IPAddress _address = IPAddress.Parse("192.0.2.1");
	private static readonly RemoteCertificateValidationCallback _acceptAnyCertificate = (_, _, _, _) => true;

	[Fact]
	public async Task Server_ClosesIdleConnection_AfterKeepAlive()
	{
		using var server = CreateServer(tcpTimeout: 5000, tcpKeepAlive: 1000);
		using var client = new TcpClient();
		await client.ConnectAsync(IPAddress.Loopback, server.Port);

		var stopwatch = Stopwatch.StartNew();
		Assert.True(await TransportTests.WaitForRemoteCloseAsync(client, TimeSpan.FromSeconds(10)), "The idle connection was not closed");
		Assert.InRange(stopwatch.Elapsed, TimeSpan.FromMilliseconds(500), TimeSpan.FromSeconds(5));
	}

	[Fact]
	public async Task Server_ClosesConnectionWithIncompleteQuery_AfterTimeout()
	{
		// the keep alive is long, so only the timeout for the rest of a started query can close the connection
		using var server = CreateServer(tcpTimeout: 1000, tcpKeepAlive: 60000);
		using var client = new TcpClient();
		await client.ConnectAsync(IPAddress.Loopback, server.Port);

		// announces 30 bytes, but sends only 5
		await client.GetStream().WriteAsync(new byte[] { 0, 30, 1, 2, 3, 4, 5 }, 0, 7);

		var stopwatch = Stopwatch.StartNew();
		Assert.True(await TransportTests.WaitForRemoteCloseAsync(client, TimeSpan.FromSeconds(10)), "The connection with the incomplete query was not closed");
		Assert.InRange(stopwatch.Elapsed, TimeSpan.FromMilliseconds(500), TimeSpan.FromSeconds(5));
	}

	[Fact]
	public async Task Server_AnswersQuery_SentByteByByte()
	{
		using var server = CreateServer();
		using var client = new TcpClient();
		await client.ConnectAsync(IPAddress.Loopback, server.Port);
		var stream = client.GetStream();

		foreach (var b in Query(0x1111))
		{
			await stream.WriteAsync(new[] { b }, 0, 1);
			await Task.Delay(10);
		}

		var response = await ReadResponseAsync(stream);
		Assert.Equal(0x1111, response.TransactionID);
		Assert.Contains(response.AnswerRecords.OfType<ARecord>(), a => a.Address.Equals(_address));
	}

	[Fact]
	public async Task Server_AnswersSeveralQueries_SentInOneWrite()
	{
		using var server = CreateServer();
		using var client = new TcpClient();
		await client.ConnectAsync(IPAddress.Loopback, server.Port);
		var stream = client.GetStream();

		var queries = Query(0x1111).Concat(Query(0x2222)).Concat(Query(0x3333)).ToArray();
		await stream.WriteAsync(queries, 0, queries.Length);

		// the responses may arrive in any order
		var ids = new List<ushort>();
		for (var i = 0; i < 3; i++)
			ids.Add((await ReadResponseAsync(stream)).TransactionID);

		Assert.Equal(new ushort[] { 0x1111, 0x2222, 0x3333 }, ids.OrderBy(x => x));
	}

	[Fact]
	public async Task Tls_ParallelQueriesOnPooledConnection_AreAllAnswered()
	{
		// the queries share one TLS connection, SslStream does not allow concurrent writes
		using var server = CreateServer();
		using var client = server.CreateClient(new TlsClientTransport("localhost", remoteCertificateValidationCallback: _acceptAnyCertificate, port: server.TlsPort));

		var responses = await Task.WhenAll(Enumerable.Range(0, 50).Select(_ => Task.Run(() => client.ResolveAsync(_name))));

		Assert.All(responses, response => Assert.Contains(response!.AnswerRecords.OfType<ARecord>(), a => a.Address.Equals(_address)));
	}

	[Fact]
	public async Task Tcp_FastResponsesOnPooledConnection_AreNotLost()
	{
		// The local server answers immediately, so responses often arrive while the receive loop already runs for
		// other queries. A response read before its receiver was registered used to be dropped.
		using var server = CreateServer();
		using var client = server.CreateClient(new TcpClientTransport(server.Port), queryTimeout: 2000);

		for (var round = 0; round < 10; round++)
		{
			var responses = await Task.WhenAll(Enumerable.Range(0, 50).Select(_ => Task.Run(() => client.ResolveAsync(_name))));

			Assert.All(responses, response => Assert.NotNull(response));
		}
	}

	private static LocalDnsServer CreateServer(int tcpTimeout = 5000, int tcpKeepAlive = 120000)
	{
		return new LocalDnsServer(new DnsRecordBase[] { new ARecord(_name, 60, _address) }, tcpTimeout: tcpTimeout, tcpKeepAlive: tcpKeepAlive);
	}

	private static byte[] Query(ushort transactionId)
	{
		var query = new DnsMessage { TransactionID = transactionId };
		query.Questions.Add(new DnsQuestion(_name, RecordType.A, RecordClass.INet));
		return query.Encode().ToArraySegment(true).ToArray();
	}

	private static async Task<DnsMessage> ReadResponseAsync(Stream stream)
	{
		using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
		var header = await ReadExactAsync(stream, 2, cts.Token);
		var message = await ReadExactAsync(stream, (header[0] << 8) | header[1], cts.Token);
		return DnsMessage.Parse(new ArraySegment<byte>(message));
	}

	private static async Task<byte[]> ReadExactAsync(Stream stream, int length, CancellationToken token)
	{
		var buffer = new byte[length];
		var read = 0;
		while (read < length)
		{
			var count = await stream.ReadAsync(buffer, read, length - read, token);
			if (count == 0)
				throw new IOException("Connection closed");
			read += count;
		}

		return buffer;
	}
}
