#region Copyright and License
// Copyright 2010..2024 Alexander Reinert
//
// This file is part of the ARSoft.Tools.Net - C# DNS client/server and SPF Library (https://github.com/alexreinert/ARSoft.Tools.Net)
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
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using static DnsToolkit.Net.Dns.TlsServerTransport;

namespace DnsToolkit.Net.Dns;

/// <summary>
///   A transport used by a server using tls communication
/// </summary>
public class TlsServerTransport : TcpServerTransportBase<TlsServerTransport>
{
	/// <summary>
	///   The default port of TCP DNS communication
	/// </summary>
	public const int DEFAULT_PORT = 853;

	/// <summary>
	///   The transport protocol this transport is using
	/// </summary>
	public override TransportProtocol TransportProtocol => TransportProtocol.Tls;

#if NETSTANDARD2_0
	private readonly X509Certificate _serverCertificate;
	private readonly bool _clientCertificateRequired;
	private readonly SslProtocols _enabledSslProtocols;
	private readonly bool _checkCertificateRevocation;
	private readonly RemoteCertificateValidationCallback? _remoteCertificateValidationCallback;
#else
	private readonly SslServerAuthenticationOptions _sslServerAuthenticationOptions;
#endif

	/// <summary>
	///   Creates a new instance of the TcpServerTransport
	/// </summary>
	/// <param name="bindAddress">The IP address on which the transport should listen</param>
	/// <param name="serverCertificate">The certificate used to authenticate the server</param>
	/// <param name="clientCertificateRequired">A value that specifies whether the client must supply a certificate for authentication</param>
	/// <param name="enabledSslProtocols">The enabled protocols, SslProtocols.None for the system default</param>
	/// <param name="checkCertificateRevocation">A value that specifies whether the certificate revocation list is checked</param>
	/// <param name="remoteCertificateValidationCallback">A callback for validating the client certificate, or null for the default validation</param>
	/// <param name="timeout">The read an write timeout in milliseconds, which also limits the duration of the TLS handshake</param>
	/// <param name="keepAlive">
	///   The keep alive timeout in milliseconds for waiting for subsequent queries on the same
	///   connection
	/// </param>
	public TlsServerTransport(IPAddress bindAddress, X509Certificate serverCertificate, bool clientCertificateRequired = false, SslProtocols enabledSslProtocols = SslProtocols.None, bool checkCertificateRevocation = false, RemoteCertificateValidationCallback? remoteCertificateValidationCallback = null, int timeout = 5000, int keepAlive = 120000)
		: this(new IPEndPoint(bindAddress, DEFAULT_PORT), serverCertificate, clientCertificateRequired, enabledSslProtocols, checkCertificateRevocation, remoteCertificateValidationCallback, timeout, keepAlive) { }

	/// <summary>
	///   Creates a new instance of the TcpServerTransport
	/// </summary>
	/// <param name="bindEndPoint">The IP endpoint on which the transport should listen</param>
	/// <param name="serverCertificate">The certificate used to authenticate the server</param>
	/// <param name="clientCertificateRequired">A value that specifies whether the client must supply a certificate for authentication</param>
	/// <param name="enabledSslProtocols">The enabled protocols, SslProtocols.None for the system default</param>
	/// <param name="checkCertificateRevocation">A value that specifies whether the certificate revocation list is checked</param>
	/// <param name="remoteCertificateValidationCallback">A callback for validating the client certificate, or null for the default validation</param>
	/// <param name="timeout">The read an write timeout in milliseconds, which also limits the duration of the TLS handshake</param>
	/// <param name="keepAlive">
	///   The keep alive timeout in milliseconds for waiting for subsequent queries on the same
	///   connection
	/// </param>
	public TlsServerTransport(IPEndPoint bindEndPoint, X509Certificate serverCertificate, bool clientCertificateRequired = false, SslProtocols enabledSslProtocols = SslProtocols.None, bool checkCertificateRevocation = false, RemoteCertificateValidationCallback? remoteCertificateValidationCallback = null, int timeout = 5000, int keepAlive = 120000)
		: base(bindEndPoint, timeout, keepAlive)
	{
#if NETSTANDARD2_0
		_serverCertificate = serverCertificate;
		_clientCertificateRequired = clientCertificateRequired;
		_enabledSslProtocols = enabledSslProtocols;
		_checkCertificateRevocation = checkCertificateRevocation;
		_remoteCertificateValidationCallback = remoteCertificateValidationCallback;
#else
		_sslServerAuthenticationOptions = new SslServerAuthenticationOptions
		{
			ServerCertificate = serverCertificate,
			ClientCertificateRequired = clientCertificateRequired,
			EnabledSslProtocols = enabledSslProtocols,
			CertificateRevocationCheckMode = checkCertificateRevocation ? X509RevocationMode.Online : X509RevocationMode.NoCheck,
			RemoteCertificateValidationCallback = remoteCertificateValidationCallback,
		};
#endif
	}

#if !NETSTANDARD2_0
	/// <summary>
	///   Creates a new instance of the TcpServerTransport
	/// </summary>
	/// <param name="bindAddress">The IP address on which the transport should listen</param>
	/// <param name="sslServerAuthenticationOptions">The ssl connection property bag</param>
	/// <param name="timeout">The read an write timeout in milliseconds, which also limits the duration of the TLS handshake</param>
	/// <param name="keepAlive">
	///   The keep alive timeout in milliseconds for waiting for subsequent queries on the same
	///   connection
	/// </param>
	public TlsServerTransport(IPAddress bindAddress, SslServerAuthenticationOptions sslServerAuthenticationOptions, int timeout = 5000, int keepAlive = 120000)
		: this(new IPEndPoint(bindAddress, DEFAULT_PORT), sslServerAuthenticationOptions, timeout, keepAlive) { }

	/// <summary>
	///   Creates a new instance of the TcpServerTransport
	/// </summary>
	/// <param name="bindEndPoint">The IP endpoint on which the transport should listen</param>
	/// <param name="sslServerAuthenticationOptions">The ssl connection property bag</param>
	/// <param name="timeout">The read an write timeout in milliseconds, which also limits the duration of the TLS handshake</param>
	/// <param name="keepAlive">
	///   The keep alive timeout in milliseconds for waiting for subsequent queries on the same
	///   connection
	/// </param>
	public TlsServerTransport(IPEndPoint bindEndPoint, SslServerAuthenticationOptions sslServerAuthenticationOptions, int timeout = 5000, int keepAlive = 120000)
		: base(bindEndPoint, timeout, keepAlive)
	{
		_sslServerAuthenticationOptions = sslServerAuthenticationOptions;
	}
#endif

	private async Task<Stream> AuthenticateAsServerAsync(Stream innerStream, CancellationToken token)
	{
		// Limit the handshake duration, otherwise clients which never complete the handshake keep their connection open
		using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(token);
		if (Timeout > 0)
			handshakeCts.CancelAfter(Timeout);

#if NETSTANDARD2_0
		var sslStream = new SslStream(innerStream, false, _remoteCertificateValidationCallback);
#else
		var sslStream = new SslStream(innerStream, false);
#endif

		try
		{
#if NETSTANDARD2_0
			// AuthenticateAsServerAsync does not support cancellation on netstandard2.0, so abort the handshake by disposing the stream
			using (handshakeCts.Token.Register(sslStream.Dispose))
			{
				await sslStream.AuthenticateAsServerAsync(_serverCertificate, _clientCertificateRequired, _enabledSslProtocols, _checkCertificateRevocation);
			}
#else
			await sslStream.AuthenticateAsServerAsync(_sslServerAuthenticationOptions, handshakeCts.Token);
#endif
			handshakeCts.Token.ThrowIfCancellationRequested();

			return sslStream;
		}
		catch (Exception) when (handshakeCts.IsCancellationRequested)
		{
			sslStream.Dispose();
			throw new OperationCanceledException(handshakeCts.Token);
		}
		catch
		{
			sslStream.Dispose();
			throw;
		}
	}

	protected override TcpServerConnectionBase CreateConnection(TcpClient client, CancellationToken token)
	{
		return new TlsServerConnection(this, client);
	}

	private class TlsServerConnection : TcpServerConnectionBase
	{
		public TlsServerConnection(TlsServerTransport transport, TcpClient client) : base(transport, client) { }

		protected override async Task<Stream?> GetStreamFromClientAsync(CancellationToken token)
		{
			return await TransportInternal.AuthenticateAsServerAsync(Client.GetStream(), token);
		}
	}
}
