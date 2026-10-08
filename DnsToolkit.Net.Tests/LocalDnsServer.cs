using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

/// <summary>
///   A DNS server on the loopback interface which answers from a fixed set of records
/// </summary>
internal sealed class LocalDnsServer : IDisposable
{
	private DnsServer _server = null!;
	private readonly List<DnsRecordBase> _records;

	public int Port { get; private set; }
	public int TlsPort { get; private set; }
	// generating a RSA key is expensive, so all servers share one certificate
	private static readonly Lazy<X509Certificate2> _certificate = new(CreateSelfSignedCertificate);

	public X509Certificate2 Certificate => _certificate.Value;

	public LocalDnsServer(IEnumerable<DnsRecordBase> records, int tlsHandshakeTimeout = 5000, int tcpTimeout = 5000, int tcpKeepAlive = 120000, int maxConcurrentConnectionsPerTransport = 1000)
	{
		_records = records.ToList();

		// A free port may be taken by another test (process) before the server binds it, so retry with other ports
		for (var attempt = 1;; attempt++)
		{
			Port = GetFreePort();
			TlsPort = GetFreePort();

			var endpoint = new IPEndPoint(IPAddress.Loopback, Port);
			_server = new DnsServer(
				new UdpServerTransport(endpoint),
				new TcpServerTransport(endpoint, tcpTimeout, tcpKeepAlive),
				new TlsServerTransport(new IPEndPoint(IPAddress.Loopback, TlsPort), Certificate, timeout: tlsHandshakeTimeout));
			_server.QueryReceived += AnswerQuery;
			_server.MaxConcurrentConnectionsPerTransport = maxConcurrentConnectionsPerTransport;

			try
			{
				_server.Start();
				return;
			}
			catch (SocketException) when (attempt < 10)
			{
				// closes the transports, which were already bound
				((IDisposable) _server).Dispose();
			}
		}
	}

	private Task AnswerQuery(object sender, QueryReceivedEventArgs e)
	{
		var query = (DnsMessage) e.Query;
		var question = query.Questions[0];
		var response = query.CreateResponseInstance();

		var answers = _records.Where(r => r.Name.Equals(question.Name) && r.RecordType == question.RecordType).ToList();
		response.AnswerRecords.AddRange(answers);
		response.ReturnCode = answers.Count > 0 || _records.Any(r => r.Name.Equals(question.Name)) ? ReturnCode.NoError : ReturnCode.NxDomain;

		e.Response = response;
		return Task.CompletedTask;
	}

	public DnsClient CreateClient(IClientTransport transport, int queryTimeout = 5000)
	{
		return new DnsClient(new[] { IPAddress.Loopback }, new[] { transport }, true, queryTimeout);
	}

	public void Dispose()
	{
		_server.Stop();
		((IDisposable) _server).Dispose();
	}

	public static int GetFreePort()
	{
		var listener = new TcpListener(IPAddress.Loopback, 0);
		listener.Start();
		var port = ((IPEndPoint) listener.LocalEndpoint).Port;
		listener.Stop();
		return port;
	}

	private static X509Certificate2 CreateSelfSignedCertificate()
	{
		using var rsa = RSA.Create(2048);
		var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
		using var ephemeral = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

		// SChannel needs a persisted private key, so round trip through PFX
#pragma warning disable SYSLIB0057
		return new X509Certificate2(ephemeral.Export(X509ContentType.Pfx, "test"), "test", X509KeyStorageFlags.Exportable);
#pragma warning restore SYSLIB0057
	}
}
