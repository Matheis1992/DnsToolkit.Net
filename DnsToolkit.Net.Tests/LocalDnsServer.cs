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
	private readonly TimeSpan _answerDelay;

	public int Port { get; private set; }
	public int TlsPort { get; private set; }
	// generating a RSA key is expensive, so all servers share one certificate
	private static readonly Lazy<X509Certificate2> _certificate = new(CreateSelfSignedCertificate);

	public X509Certificate2 Certificate => _certificate.Value;

	public static X509Certificate2 SharedCertificate => _certificate.Value;

	public LocalDnsServer(IEnumerable<DnsRecordBase> records, int tlsHandshakeTimeout = 5000, int tcpTimeout = 5000, int tcpKeepAlive = 120000, int maxConcurrentConnectionsPerTransport = 1000, TimeSpan answerDelay = default)
	{
		_records = records.ToList();
		_answerDelay = answerDelay;

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

	private async Task AnswerQuery(object sender, QueryReceivedEventArgs e)
	{
		// like a handler, which waits for an upstream server
		if (_answerDelay > TimeSpan.Zero)
			await Task.Delay(_answerDelay);

		var query = (DnsMessage) e.Query;
		var question = query.Questions[0];
		var response = query.CreateResponseInstance();

		var answers = _records.Where(r => r.Name.Equals(question.Name) && r.RecordType == question.RecordType).ToList();

		// like an authoritative server, an alias is answered with its CNAME record, which the client follows (RFC 1034, section 3.6.2)
		if (answers.Count == 0)
			answers = _records.Where(r => r.Name.Equals(question.Name) && r.RecordType == RecordType.CName).ToList();
		response.AnswerRecords.AddRange(answers);
		response.ReturnCode = answers.Count > 0 || _records.Any(r => r.Name.Equals(question.Name)) ? ReturnCode.NoError : ReturnCode.NxDomain;

		e.Response = response;
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

	private static readonly Random _random = new();

	/// <summary>
	///   A port, which is free for TCP and UDP. On Windows, e.g. Hyper-V reserves blocks of ports, often for only one of the
	///   protocols, and binding a reserved port fails with WSAEACCES. The ports, which the system hands out, are taken one
	///   after another from the dynamic range, where these blocks usually are, so a port free for TCP was often reserved for
	///   UDP, and so were the next ones. Random ports below the dynamic range avoid both.
	/// </summary>
	public static int GetFreePort()
	{
		for (var attempt = 1;; attempt++)
		{
			int port;
			lock (_random)
				port = _random.Next(20000, 45000);

			if (IsFreeForTcpAndUdp(port))
				return port;

			if (attempt == 100)
				throw new InvalidOperationException("No port free for TCP and UDP was found");
		}
	}

	private static bool IsFreeForTcpAndUdp(int port)
	{
		var endpoint = new IPEndPoint(IPAddress.Loopback, port);
		TcpListener? tcp = null;

		try
		{
			tcp = new TcpListener(endpoint);
			tcp.Start();

			using var udp = new UdpClient(endpoint);
			return true;
		}
		catch (SocketException)
		{
			return false;
		}
		finally
		{
			tcp?.Stop();
		}
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
