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

public class UdpTransportTests
{
	private static readonly DomainName _name = DomainName.Parse("host.example.test");
	private static readonly IPAddress _address = IPAddress.Parse("192.0.2.1");

	[Fact]
	public async Task Transport_ReceivesNextQuery_AfterIcmpPortUnreachable()
	{
		var endpoint = new IPEndPoint(IPAddress.Loopback, GetFreeUdpPort());
		using var transport = new UdpServerTransport(endpoint);
		transport.Bind();

		// the first client sends a query and closes its socket before the response arrives
		using (var firstClient = new UdpClient(AddressFamily.InterNetwork))
		{
			var query = Query(0x1111);
			await firstClient.SendAsync(query, query.Length, endpoint);
		}

		var first = await AcceptAsync(transport);
		Assert.NotNull(first);

		// the response to the closed port results in an ICMP port unreachable,
		// which on Windows fails the next receive of the server socket, if not disabled
		await first!.SendAsync(Response(0x1111));
		await Task.Delay(200);

		using var secondClient = new UdpClient(AddressFamily.InterNetwork);
		var secondQuery = Query(0x2222);
		await secondClient.SendAsync(secondQuery, secondQuery.Length, endpoint);

		var second = await AcceptAsync(transport);
		Assert.NotNull(second);
		Assert.Equal(0x2222, (await second!.ReceiveAsync())!.MessageIdentification.TransactionID);
	}

	[Fact]
	public async Task Server_AnswersQueryLargerThan512Bytes()
	{
		using var server = new LocalDnsServer(new DnsRecordBase[] { new ARecord(_name, 60, _address) });
		using var client = new UdpClient(AddressFamily.InterNetwork);

		// e.g. dynamic updates or queries with large EDNS options exceed 512 bytes
		var message = new DnsMessage { TransactionID = 0x3333 };
		message.Questions.Add(new DnsQuestion(_name, RecordType.A, RecordClass.INet));
		for (var i = 0; i < 6; i++)
			message.AdditionalRecords.Add(new TxtRecord(DomainName.Parse($"pad{i}.example.test"), 60, new string('x', 200)));
		var query = message.Encode().ToArraySegment(false).ToArray();
		Assert.True(query.Length > 1000);

		await client.SendAsync(query, query.Length, new IPEndPoint(IPAddress.Loopback, server.Port));

		var receive = client.ReceiveAsync();
		Assert.True(await Task.WhenAny(receive, Task.Delay(5000)) == receive, "The large query was not answered");

		var response = DnsMessage.Parse(new ArraySegment<byte>((await receive).Buffer));
		Assert.Equal(0x3333, response.TransactionID);
		Assert.Contains(response.AnswerRecords.OfType<ARecord>(), a => a.Address.Equals(_address));
	}

	[Fact]
	public async Task Transport_CanBeBoundAgain_AfterClose()
	{
		var endpoint = new IPEndPoint(IPAddress.Loopback, GetFreeUdpPort());
		using var transport = new UdpServerTransport(endpoint);

		transport.Bind();
		transport.Close();
		transport.Bind();

		using var client = new UdpClient(AddressFamily.InterNetwork);
		var query = Query(0x4444);
		await client.SendAsync(query, query.Length, endpoint);

		var connection = await AcceptAsync(transport);
		Assert.NotNull(connection);
		Assert.Equal(0x4444, (await connection!.ReceiveAsync())!.MessageIdentification.TransactionID);
	}

	[Fact]
	public async Task Transport_CanBeBound_AfterBindFailedBecausePortWasInUse()
	{
		var endpoint = new IPEndPoint(IPAddress.Loopback, GetFreeUdpPort());
		using var transport = new UdpServerTransport(endpoint);

		using (var blocker = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
		{
			blocker.Bind(endpoint);
			var exception = Assert.Throws<SocketException>(transport.Bind);
			Assert.Equal(SocketError.AddressAlreadyInUse, exception.SocketErrorCode);
		}

		transport.Bind();

		using var client = new UdpClient(AddressFamily.InterNetwork);
		var query = Query(0x5555);
		await client.SendAsync(query, query.Length, endpoint);

		var connection = await AcceptAsync(transport);
		Assert.NotNull(connection);
		Assert.Equal(0x5555, (await connection!.ReceiveAsync())!.MessageIdentification.TransactionID);
	}

	[Fact]
	public async Task Transport_ThrowsInvalidOperation_WhenNotBound()
	{
		var endpoint = new IPEndPoint(IPAddress.Loopback, GetFreeUdpPort());
		using var transport = new UdpServerTransport(endpoint);

		await Assert.ThrowsAsync<InvalidOperationException>(() => transport.AcceptConnectionAsync());

		transport.Bind();
		Assert.Throws<InvalidOperationException>(transport.Bind);

		transport.Close();
		await Assert.ThrowsAsync<InvalidOperationException>(() => transport.AcceptConnectionAsync());

		// closing again does nothing
		transport.Close();
	}

	[Fact]
	public void Transport_CannotBeBound_AfterDispose()
	{
		var transport = new UdpServerTransport(new IPEndPoint(IPAddress.Loopback, 0));
		transport.Dispose();

		Assert.Throws<ObjectDisposedException>(transport.Bind);
	}

	private static async Task<IServerConnection?> AcceptAsync(UdpServerTransport transport)
	{
		using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
		return await transport.AcceptConnectionAsync(cts.Token);
	}

	private static int GetFreeUdpPort()
	{
		using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
		socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
		return ((IPEndPoint) socket.LocalEndPoint!).Port;
	}

	private static byte[] Query(ushort transactionId)
	{
		var query = new DnsMessage { TransactionID = transactionId };
		query.Questions.Add(new DnsQuestion(_name, RecordType.A, RecordClass.INet));
		return query.Encode().ToArraySegment(false).ToArray();
	}

	private static DnsRawPackage Response(ushort transactionId)
	{
		var query = new DnsMessage { TransactionID = transactionId };
		query.Questions.Add(new DnsQuestion(_name, RecordType.A, RecordClass.INet));
		return query.CreateResponseInstance().Encode();
	}
}
