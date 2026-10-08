using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

public class TransportTests : IDisposable
{
	private static readonly DomainName _name = DomainName.Parse("host.example.test");
	private static readonly IPAddress _address = IPAddress.Parse("192.0.2.1");
	private static readonly RemoteCertificateValidationCallback _acceptAnyCertificate = (_, _, _, _) => true;

	private static readonly DnsRecordBase[] _records = { new ARecord(_name, 60, _address) };

	private readonly LocalDnsServer _server = new(_records);

	public void Dispose()
	{
		_server.Dispose();
	}

	[Fact]
	public async Task Udp_Resolves()
	{
		await AssertResolvesAsync(_server.CreateClient(new UdpClientTransport(_server.Port)));
	}

	[Fact]
	public async Task Tcp_Resolves()
	{
		await AssertResolvesAsync(_server.CreateClient(new TcpClientTransport(_server.Port)));
	}

	[Fact]
	public async Task Tcp_ResolvesParallelQueriesOverPooledConnection()
	{
		using var client = _server.CreateClient(new TcpClientTransport(_server.Port));

		var results = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => client.ResolveAsync(_name)));

		Assert.All(results, msg => Assert.Contains(msg!.AnswerRecords.OfType<ARecord>(), a => a.Address.Equals(_address)));
	}

	[Fact]
	public async Task Tls_WithExplicitParameters_Resolves()
	{
		await AssertResolvesAsync(_server.CreateClient(new TlsClientTransport("localhost", remoteCertificateValidationCallback: _acceptAnyCertificate, port: _server.TlsPort)));
	}

#if !NETFRAMEWORK
	[Fact]
	public async Task Tls_WithAuthenticationOptions_Resolves()
	{
		var options = new SslClientAuthenticationOptions { TargetHost = "localhost", RemoteCertificateValidationCallback = _acceptAnyCertificate };

		await AssertResolvesAsync(_server.CreateClient(new TlsClientTransport(options, _server.TlsPort)));
	}
#endif

	[Fact]
	public async Task Tls_WithUntrustedServerCertificate_ReturnsNoResponse()
	{
		using var client = _server.CreateClient(new TlsClientTransport("localhost", port: _server.TlsPort));

		var msg = await client.ResolveAsync(_name);

		Assert.Null(msg);
	}

	[Fact]
	public async Task TlsServer_ClosesConnectionWithoutHandshake_AfterTimeout()
	{
		// only this test uses a short handshake timeout, a handshake can take longer if the tests run in parallel
		using var server = new LocalDnsServer(_records, tlsHandshakeTimeout: 2000);
		using var idleClient = new TcpClient();
		await idleClient.ConnectAsync(IPAddress.Loopback, server.TlsPort);

		var stopwatch = Stopwatch.StartNew();
		var closed = await WaitForRemoteCloseAsync(idleClient, TimeSpan.FromSeconds(10));

		Assert.True(closed, "The server did not close a connection without TLS handshake");
		Assert.InRange(stopwatch.Elapsed, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(6));
	}

	[Fact]
	public async Task TlsClient_WithServerNotAnsweringHandshake_StopsOnCancellation()
	{
		// A server which accepts connections, but never answers the TLS handshake
		var silentServer = new TcpListener(IPAddress.Loopback, 0);
		silentServer.Start();
		var acceptTask = silentServer.AcceptTcpClientAsync();

		try
		{
			var port = ((IPEndPoint) silentServer.LocalEndpoint).Port;
			using var client = _server.CreateClient(new TlsClientTransport("localhost", remoteCertificateValidationCallback: _acceptAnyCertificate, port: port));
			using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(1));

			var stopwatch = Stopwatch.StartNew();
			DnsMessage? msg = null;
			try
			{
				msg = await client.ResolveAsync(_name, token: cts.Token);
			}
			catch (OperationCanceledException)
			{
				// expected as well
			}

			Assert.Null(msg);
			Assert.InRange(stopwatch.Elapsed, TimeSpan.Zero, TimeSpan.FromSeconds(5));
		}
		finally
		{
			silentServer.Stop();
			if (acceptTask.Status == TaskStatus.RanToCompletion)
				(await acceptTask).Dispose();
		}
	}

	private static async Task AssertResolvesAsync(DnsClient client)
	{
		using (client)
		{
			var msg = await client.ResolveAsync(_name);

			Assert.NotNull(msg);
			Assert.Equal(ReturnCode.NoError, msg!.ReturnCode);
			Assert.Contains(msg.AnswerRecords.OfType<ARecord>(), a => a.Address.Equals(_address));
		}
	}

	internal static async Task<bool> WaitForRemoteCloseAsync(TcpClient client, TimeSpan timeout)
	{
		var read = ReadUntilClosedAsync(client.GetStream());
		return await Task.WhenAny(read, Task.Delay(timeout)) == read;
	}

	private static async Task ReadUntilClosedAsync(Stream stream)
	{
		var buffer = new byte[256];
		try
		{
			while (await stream.ReadAsync(buffer, 0, buffer.Length) > 0) { }
		}
		catch (IOException)
		{
			// connection reset by the server
		}
	}
}
