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
	public async Task Server_ClosesConnection_WhoseClientDoesNotReadTheResponses()
	{
		// with a limit of one connection, the second client is only served after the first connection was closed
		var big = DomainName.Parse("big.example.test");
		var records = new List<DnsRecordBase> { new ARecord(_name, 60, _address) };
		records.AddRange(Enumerable.Range(0, 200).Select(i => new TxtRecord(big, 60, i + new string('x', 200))));
		using var server = new LocalDnsServer(records, tcpTimeout: 1000, maxConcurrentConnectionsPerTransport: 1);

		// queries for large responses, which the client never reads, so the buffers of both sides fill up and the writes of the server block
		using var first = new TcpClient();
		await first.ConnectAsync(IPAddress.Loopback, server.Port);
		var queries = Enumerable.Range(0, 500).SelectMany(i => Query((ushort) i, big, RecordType.Txt)).ToArray();
		await first.GetStream().WriteAsync(queries, 0, queries.Length);

		using var second = new TcpClient();
		await second.ConnectAsync(IPAddress.Loopback, server.Port);
		var query = Query(0x4242);
		await second.GetStream().WriteAsync(query, 0, query.Length);

		// before, the blocked writes kept the first connection and its slot forever
		var response = ReadResponseAsync(second.GetStream());
		Assert.True(await Task.WhenAny(response, Task.Delay(TimeSpan.FromSeconds(10))) == response, "The second client was not served, so the first connection was not closed");
		Assert.Equal(0x4242, (await response).TransactionID);
	}

	[IPv6Fact]
	public async Task TransportBoundToIPv6Any_AcceptsIPv4_AlsoAfterARestart()
	{
		var port = LocalDnsServer.GetFreePort();
		var transport = new TcpServerTransport(new IPEndPoint(IPAddress.IPv6Any, port));
		try
		{
			transport.Bind();
			transport.Close();

			// before, the socket of the restarted listener accepted only IPv6
			transport.Bind();

			using var client = new TcpClient(AddressFamily.InterNetwork);
			await client.ConnectAsync(IPAddress.Loopback, port);
			Assert.True(client.Connected);
		}
		finally
		{
			transport.Dispose();
		}
	}

	[Fact]
	public async Task Server_SendsResponseOfASlowQuery_AfterTheKeepAliveEnded()
	{
		// the keep alive ends, while the query is processed, but the response is still sent before the connection is closed
		using var server = new LocalDnsServer(new DnsRecordBase[] { new ARecord(_name, 60, _address) }, tcpKeepAlive: 500, answerDelay: TimeSpan.FromMilliseconds(1500));
		using var client = new TcpClient();
		await client.ConnectAsync(IPAddress.Loopback, server.Port);
		var stream = client.GetStream();

		var query = Query(0x1111);
		await stream.WriteAsync(query, 0, query.Length);

		Assert.Equal(0x1111, (await ReadResponseAsync(stream)).TransactionID);
		Assert.True(await TransportTests.WaitForRemoteCloseAsync(client, TimeSpan.FromSeconds(10)), "The idle connection was not closed after the response");
	}

	[Fact]
	public async Task Server_ReadsFurtherQueries_AfterTheKeepAlive_WhileAQueryIsInProgress()
	{
		// the keep alive only runs while no query is in progress (RFC 7766, section 6.2.3)
		using var server = new LocalDnsServer(new DnsRecordBase[] { new ARecord(_name, 60, _address) }, tcpKeepAlive: 500, answerDelay: TimeSpan.FromMilliseconds(1500));
		using var client = new TcpClient();
		await client.ConnectAsync(IPAddress.Loopback, server.Port);
		var stream = client.GetStream();

		var first = Query(0x1111);
		await stream.WriteAsync(first, 0, first.Length);

		// longer than the keep alive, but shorter than the processing of the first query. Before, the server stopped reading here.
		await Task.Delay(1000);
		var second = Query(0x2222);
		await stream.WriteAsync(second, 0, second.Length);

		var ids = new[] { (await ReadResponseAsync(stream)).TransactionID, (await ReadResponseAsync(stream)).TransactionID };
		Assert.Equal(new ushort[] { 0x1111, 0x2222 }, ids.OrderBy(x => x));

		Assert.True(await TransportTests.WaitForRemoteCloseAsync(client, TimeSpan.FromSeconds(10)), "The idle connection was not closed after the responses");
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
	public async Task Tcp_QueriesWithSameIdentification_AreAllAnswered()
	{
		// Random transaction ids of parallel queries for the same name collide now and then. Such a collision
		// used to abort the whole pooled connection, including all other queries on it.
		using var server = CreateServer();
		using var client = server.CreateClient(new TcpClientTransport(server.Port), queryTimeout: 2000);

		var responses = await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => Task.Run(() =>
		{
			var query = new DnsMessage { TransactionID = 0x5555 };
			query.Questions.Add(new DnsQuestion(_name, RecordType.A, RecordClass.INet));
			return client.SendMessageAsync(query);
		})));

		Assert.All(responses, response => Assert.Contains(response!.AnswerRecords.OfType<ARecord>(), a => a.Address.Equals(_address)));
	}

	[Fact]
	public async Task Server_AcceptsNextConnection_OnlyAfterOneWasClosed_WhenLimitIsReached()
	{
		using var server = CreateServer(maxConcurrentConnections: 1);

		// the first client takes the only connection slot and stays idle
		using var first = new TcpClient();
		await first.ConnectAsync(IPAddress.Loopback, server.Port);
		await Task.Delay(300);

		// the second client is in the backlog of the operating system, its query is not answered yet
		using var second = new TcpClient();
		await second.ConnectAsync(IPAddress.Loopback, server.Port);
		var query = Query(0x4242);
		await second.GetStream().WriteAsync(query, 0, query.Length);

		var response = ReadResponseAsync(second.GetStream());
		Assert.False(await Task.WhenAny(response, Task.Delay(700)) == response, "The second connection was served, although the limit is one");

		// closing the first connection frees the slot
		first.Close();

		Assert.True(await Task.WhenAny(response, Task.Delay(5000)) == response, "The second connection was not served after the first one was closed");
		Assert.Equal(0x4242, (await response).TransactionID);
	}

	private static LocalDnsServer CreateServer(int tcpTimeout = 5000, int tcpKeepAlive = 120000, int maxConcurrentConnections = 1000)
	{
		return new LocalDnsServer(new DnsRecordBase[] { new ARecord(_name, 60, _address) }, tcpTimeout: tcpTimeout, tcpKeepAlive: tcpKeepAlive, maxConcurrentConnectionsPerTransport: maxConcurrentConnections);
	}

	private static byte[] Query(ushort transactionId) => Query(transactionId, _name, RecordType.A);

	private static byte[] Query(ushort transactionId, DomainName name, RecordType recordType)
	{
		var query = new DnsMessage { TransactionID = transactionId };
		query.Questions.Add(new DnsQuestion(name, recordType, RecordClass.INet));
		return query.Encode().ToArraySegment(true).ToArray();
	}

	internal static async Task<DnsMessage> ReadResponseAsync(Stream stream)
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
