#if !NETFRAMEWORK
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using DnsToolkit.Net.Dns;
using Microsoft.AspNetCore.Hosting;

namespace DnsToolkit.Net.Tests;

/// <summary>
///   Not parallel, as one test sets environment variables, which apply to the whole process
/// </summary>
[Collection(NonParallelCollection.Name)]
public class DohServerTests
{
	private static readonly DomainName _name = DomainName.Parse("host.example.test");
	private static readonly IPAddress _address = IPAddress.Parse("192.0.2.1");

	[Fact]
	public async Task AnswersPostAndGetQueries()
	{
		var port = LocalDnsServer.GetFreePort();
		using var server = StartServerWithEndpoint(port);
		using var http = CreateHttpClient();

		var post = await PostQueryAsync(http, port, 0x1111);
		Assert.Equal(HttpStatusCode.OK, post.StatusCode);
		AssertAnswer(await post.Content.ReadAsByteArrayAsync(), 0x1111);

		var get = await http.GetAsync($"https://localhost:{port}/dns-query?dns={ToBase64Url(Query(0x2222))}");
		Assert.Equal(HttpStatusCode.OK, get.StatusCode);
		AssertAnswer(await get.Content.ReadAsByteArrayAsync(), 0x2222);
	}

	[Fact]
	public async Task Post_QueryLargerThan512Bytes_IsAnswered()
	{
		var port = LocalDnsServer.GetFreePort();
		using var server = StartServer(port);
		using var http = CreateHttpClient();

		var query = LargeQuery(0x7777, 1000);
		var response = await http.PostAsync($"https://localhost:{port}/dns-query", DnsContent(query));

		Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		AssertAnswer(await response.Content.ReadAsByteArrayAsync(), 0x7777);
	}

	[Fact]
	public async Task Get_QueryLargerThan512Bytes_IsAnswered()
	{
		var port = LocalDnsServer.GetFreePort();
		using var server = StartServer(port);
		using var http = CreateHttpClient();

		var response = await http.GetAsync($"https://localhost:{port}/dns-query?dns={ToBase64Url(LargeQuery(0x8888, 3000))}");

		Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		AssertAnswer(await response.Content.ReadAsByteArrayAsync(), 0x8888);
	}

	/// <summary>
	///   The handling of too large bodies is tested with simulated requests in <see cref="DohRequestHandlingTests" />.
	///   This test ensures, that the real web server enforces the limit for a chunked body, which has no Content-Length.
	/// </summary>
	[Fact]
	public async Task Post_HugeChunkedBody_IsNotAccepted()
	{
		var port = LocalDnsServer.GetFreePort();
		using var server = StartServer(port);
		using var http = CreateHttpClient();

		var content = new StreamContent(new UnknownLengthStream(5_000_000));
		content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");

		HttpResponseMessage response;
		try
		{
			response = await http.PostAsync($"https://localhost:{port}/dns-query", content);
		}
		catch (HttpRequestException)
		{
			// Kestrel may also close the connection while the client is still sending, which rejects the body as well
			return;
		}

		Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
	}

	[Fact]
	public async Task RejectsGetQueryWithoutValue()
	{
		var port = LocalDnsServer.GetFreePort();
		using var server = StartServer(port);
		using var http = CreateHttpClient();

		var response = await http.GetAsync($"https://localhost:{port}/dns-query?dns=");

		Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
	}

	[Fact]
	public async Task IgnoresConfigurationOfTheHostingApplication()
	{
		var port = LocalDnsServer.GetFreePort();
		var extraPort = LocalDnsServer.GetFreePort();

		// configuration of the application which uses the library, e.g. for its own web server
		var environment = new Dictionary<string, string?>
		{
			["ASPNETCORE_ENVIRONMENT"] = "Development",
			["AllowedHosts"] = "www.example.com",
			["Kestrel__Endpoints__Extra__Url"] = $"http://127.0.0.1:{extraPort}",
		};
		var previous = environment.Keys.ToDictionary(key => key, Environment.GetEnvironmentVariable);

		try
		{
			foreach (var variable in environment)
				Environment.SetEnvironmentVariable(variable.Key, variable.Value);

			using var server = StartServer(port);
			using var http = CreateHttpClient();

			// AllowedHosts would reject the host name localhost
			var response = await PostQueryAsync(http, port, 0x3333);
			Assert.Equal(HttpStatusCode.OK, response.StatusCode);
			AssertAnswer(await response.Content.ReadAsByteArrayAsync(), 0x3333);

			// Kestrel:Endpoints would open a further port
			using var probe = new TcpClient();
			await Assert.ThrowsAnyAsync<SocketException>(() => probe.ConnectAsync(IPAddress.Loopback, extraPort));
		}
		finally
		{
			foreach (var variable in previous)
				Environment.SetEnvironmentVariable(variable.Key, variable.Value);
		}
	}

	[Fact]
	public void Bind_Throws_WhenPortIsInUse()
	{
		var blocker = new TcpListener(IPAddress.Loopback, 0);
		blocker.Start();
		try
		{
			var endpoint = new IPEndPoint(IPAddress.Loopback, ((IPEndPoint) blocker.LocalEndpoint).Port);
			using var transport = new HttpsServerTransport(LocalDnsServer.SharedCertificate, endpoint);

			Assert.ThrowsAny<Exception>(() => transport.Bind());
		}
		finally
		{
			blocker.Stop();
		}
	}

	[Fact]
	public async Task Options_PathAndEndpoint_AreApplied()
	{
		var port = LocalDnsServer.GetFreePort();
		using var server = StartServer(new HttpsServerTransportOptions { Address = IPAddress.Loopback, Port = port, Path = "custom-dns" });
		using var http = CreateHttpClient();

		var response = await PostQueryAsync(http, port, 0x4444, "custom-dns");
		Assert.Equal(HttpStatusCode.OK, response.StatusCode);
		AssertAnswer(await response.Content.ReadAsByteArrayAsync(), 0x4444);

		Assert.Equal(HttpStatusCode.NotFound, (await PostQueryAsync(http, port, 0x4444)).StatusCode);
	}

	[Fact]
	public async Task Options_ConfigureKestrel_IsApplied()
	{
		var port = LocalDnsServer.GetFreePort();
		var extraPort = LocalDnsServer.GetFreePort();
		using var server = StartServer(new HttpsServerTransportOptions
		{
			Address = IPAddress.Loopback,
			Port = port,
			ConfigureKestrel = kestrel =>
			{
				kestrel.Listen(IPAddress.Loopback, extraPort, listen => listen.UseHttps());
				kestrel.Limits.MaxRequestBodySize = 10;
			},
		});
		using var http = CreateHttpClient();

		// the additional endpoint works, the body size limit applies to the query of about 30 bytes
		var response = await PostQueryAsync(http, extraPort, 0x5555);
		Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
	}

	[Fact]
	public async Task Options_MaxConcurrentConnections_IsApplied()
	{
		var port = LocalDnsServer.GetFreePort();
		using var server = StartServer(new HttpsServerTransportOptions { Address = IPAddress.Loopback, Port = port, MaxConcurrentConnections = 1 });

		// an idle client takes the only connection
		var idle = new TcpClient();
		await idle.ConnectAsync(IPAddress.Loopback, port);
		await Task.Delay(300);

		using (var http = CreateHttpClient())
		{
			await Assert.ThrowsAnyAsync<HttpRequestException>(() => PostQueryAsync(http, port, 0x1111));
		}

		// after the idle client closed its connection, a new one is accepted
		idle.Dispose();
		Assert.True(await SucceedsWithinAsync(port, TimeSpan.FromSeconds(5)), "No connection was accepted after the idle client closed its connection");
	}

	[Fact]
	public async Task Options_ConfigureKestrel_CanOverrideMaxConcurrentConnections()
	{
		var port = LocalDnsServer.GetFreePort();
		using var server = StartServer(new HttpsServerTransportOptions
		{
			Address = IPAddress.Loopback,
			Port = port,
			MaxConcurrentConnections = 1,
			ConfigureKestrel = kestrel => kestrel.Limits.MaxConcurrentConnections = 10,
		});

		using var idle = new TcpClient();
		await idle.ConnectAsync(IPAddress.Loopback, port);
		await Task.Delay(300);

		using var http = CreateHttpClient();
		Assert.Equal(HttpStatusCode.OK, (await PostQueryAsync(http, port, 0x1111)).StatusCode);
	}

	private static async Task<bool> SucceedsWithinAsync(int port, TimeSpan timeout)
	{
		var stopwatch = System.Diagnostics.Stopwatch.StartNew();
		while (stopwatch.Elapsed < timeout)
		{
			try
			{
				using var http = CreateHttpClient();
				if ((await PostQueryAsync(http, port, 0x2222)).StatusCode == HttpStatusCode.OK)
					return true;
			}
			catch (HttpRequestException)
			{
				// the slot is not yet released
			}

			await Task.Delay(100);
		}

		return false;
	}

	[Fact]
	public async Task Options_ChangedAfterConstruction_HaveNoEffect()
	{
		var port = LocalDnsServer.GetFreePort();
		var options = new HttpsServerTransportOptions { Address = IPAddress.Loopback, Port = port };
		var server = new DnsServer(new HttpsServerTransport(LocalDnsServer.SharedCertificate, options));
		server.QueryReceived += AnswerQuery;

		options.Port = LocalDnsServer.GetFreePort();
		options.ConfigureKestrel = _ => throw new InvalidOperationException("must not be called");

		using var started = Start(server);
		using var http = CreateHttpClient();

		Assert.Equal(HttpStatusCode.OK, (await PostQueryAsync(http, port, 0x6666)).StatusCode);
	}

	[Fact]
	public void Options_InvalidValues_AreRejected()
	{
		var options = new HttpsServerTransportOptions();

		Assert.Throws<ArgumentOutOfRangeException>(() => options.Port = -1);
		Assert.Throws<ArgumentOutOfRangeException>(() => options.Port = 65536);
		Assert.Throws<ArgumentException>(() => options.Path = " ");
		Assert.Throws<ArgumentOutOfRangeException>(() => options.ShutdownTimeout = TimeSpan.FromSeconds(-1));
		Assert.Throws<ArgumentOutOfRangeException>(() => options.MaxConcurrentConnections = 0);

		options.MaxConcurrentConnections = null;
		Assert.Null(options.MaxConcurrentConnections);
	}

	[Fact]
	public void Options_HaveDefaults()
	{
		var options = new HttpsServerTransportOptions();

		Assert.Null(options.Address);
		Assert.Equal(443, options.Port);
		Assert.Equal("dns-query", options.Path);
		Assert.Equal(System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13, options.SslProtocols);
		Assert.Equal(TimeSpan.FromSeconds(5), options.ShutdownTimeout);
		Assert.Equal(1000, options.MaxConcurrentConnections);
		Assert.Null(options.ConfigureKestrel);
	}

	[Fact]
	public async Task StopAsync_AnswersQueryInProgress_AndRejectsQueuedQueryImmediately()
	{
		var port = LocalDnsServer.GetFreePort();
		var received = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
		var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

		// a long shutdown timeout, so waiting for it cannot be mistaken for the rejection
		var shutdownTimeout = TimeSpan.FromSeconds(10);
		var server = new DnsServer(new HttpsServerTransport(LocalDnsServer.SharedCertificate, new HttpsServerTransportOptions { Address = IPAddress.Loopback, Port = port, ShutdownTimeout = shutdownTimeout }));
		server.QueryReceived += async (sender, e) =>
		{
			if (((DnsMessage) e.Query).TransactionID == 0x1111)
			{
				received.TrySetResult(true);
				await release.Task;
			}

			await AnswerQuery(sender, e);
		};
		server.Start();

		using var http = CreateHttpClient();
		try
		{
			// The server listens on IPv4 only. With localhost the client tries IPv6 first, which takes about 2 seconds
			// on Windows, so the queued query could arrive only after the server closed.
			var inProgress = PostQueryAsync(http, port, 0x1111, host: "127.0.0.1");
			Assert.True(await Task.WhenAny(received.Task, Task.Delay(TimeSpan.FromSeconds(5))) == received.Task, "The query was not received");

			var stopping = server.StopAsync();

			// the server does not accept queries anymore, so this one waits in the queue of the transport
			var queued = PostQueryAsync(http, port, 0x2222, host: "127.0.0.1");
			await Task.Delay(500);
			release.TrySetResult(true);

			var stopwatch = System.Diagnostics.Stopwatch.StartNew();

			var answered = await inProgress;
			Assert.Equal(HttpStatusCode.OK, answered.StatusCode);
			AssertAnswer(await answered.Content.ReadAsByteArrayAsync(), 0x1111);

			var rejected = await queued;
			Assert.Equal(HttpStatusCode.ServiceUnavailable, rejected.StatusCode);

			Assert.True(await Task.WhenAny(stopping, Task.Delay(shutdownTimeout)) == stopping, "The server did not stop");
			await stopping;
			Assert.InRange(stopwatch.Elapsed, TimeSpan.Zero, TimeSpan.FromSeconds(3));
		}
		finally
		{
			release.TrySetResult(true);
			await ((IAsyncDisposable) server).DisposeAsync();
		}
	}

	private static StartedServer StartServer(int port)
	{
		return StartServer(new HttpsServerTransportOptions { Address = IPAddress.Loopback, Port = port });
	}

	private static StartedServer StartServer(HttpsServerTransportOptions options)
	{
		var server = new DnsServer(new HttpsServerTransport(LocalDnsServer.SharedCertificate, options));
		server.QueryReceived += AnswerQuery;
		return Start(server);
	}

	private static StartedServer Start(DnsServer server)
	{
		server.Start();
		return new StartedServer(server);
	}

	private static Task AnswerQuery(object sender, QueryReceivedEventArgs e)
	{
		var query = (DnsMessage) e.Query;
		var response = query.CreateResponseInstance();
		response.AnswerRecords.Add(new ARecord(query.Questions[0].Name, 60, _address));
		e.Response = response;
		return Task.CompletedTask;
	}

	/// <summary>
	///   Uses the constructor with an IP endpoint instead of the options
	/// </summary>
	private static StartedServer StartServerWithEndpoint(int port)
	{
		var server = new DnsServer(new HttpsServerTransport(LocalDnsServer.SharedCertificate, new IPEndPoint(IPAddress.Loopback, port)));
		server.QueryReceived += AnswerQuery;
		return Start(server);
	}

	private sealed class StartedServer : IDisposable
	{
		private readonly DnsServer _server;

		public StartedServer(DnsServer server) => _server = server;

		public void Dispose() => ((IDisposable) _server).Dispose();
	}

	private static HttpClient CreateHttpClient()
	{
		// the test certificate is self signed
		var handler = new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };
		return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
	}

	private static Task<HttpResponseMessage> PostQueryAsync(HttpClient http, int port, ushort transactionId, string path = "dns-query", string host = "localhost")
	{
		var content = new ByteArrayContent(Query(transactionId));
		content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
		return http.PostAsync($"https://{host}:{port}/{path}", content);
	}

	private static byte[] Query(ushort transactionId)
	{
		var query = new DnsMessage { TransactionID = transactionId };
		query.Questions.Add(new DnsQuestion(_name, RecordType.A, RecordClass.INet));
		return query.Encode().ToArraySegment(false).ToArray();
	}

	private static void AssertAnswer(byte[] data, ushort transactionId)
	{
		var response = DnsMessage.Parse(new ArraySegment<byte>(data));
		Assert.Equal(transactionId, response.TransactionID);
		Assert.Contains(response.AnswerRecords.OfType<ARecord>(), a => a.Address.Equals(_address));
	}

	/// <summary>
	///   A query of about the given size, padded by additional TXT records
	/// </summary>
	private static byte[] LargeQuery(ushort transactionId, int size)
	{
		var query = new DnsMessage { TransactionID = transactionId };
		query.Questions.Add(new DnsQuestion(_name, RecordType.A, RecordClass.INet));
		for (var i = 0; query.Encode().Length < size; i++)
			query.AdditionalRecords.Add(new TxtRecord(DomainName.Parse($"pad{i}.example.test"), 60, new string('x', 200)));

		var data = query.Encode().ToArraySegment(false).ToArray();
		Assert.True(data.Length > 512);
		return data;
	}

	private static ByteArrayContent DnsContent(byte[] data)
	{
		var content = new ByteArrayContent(data);
		content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
		return content;
	}

	/// <summary>
	///   A stream of the given length, which does not report its length, so HttpClient sends it chunked
	/// </summary>
	private sealed class UnknownLengthStream : Stream
	{
		private long _remaining;

		public UnknownLengthStream(long length) => _remaining = length;

		public override int Read(byte[] buffer, int offset, int count)
		{
			var length = (int) Math.Min(count, _remaining);
			Array.Clear(buffer, offset, length);
			_remaining -= length;
			return length;
		}

		public override bool CanRead => true;
		public override bool CanSeek => false;
		public override bool CanWrite => false;
		public override long Length => throw new NotSupportedException();
		public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
		public override void Flush() { }
		public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
		public override void SetLength(long value) => throw new NotSupportedException();
		public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
	}

	private static string ToBase64Url(byte[] data)
	{
		return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
	}
}
#endif
