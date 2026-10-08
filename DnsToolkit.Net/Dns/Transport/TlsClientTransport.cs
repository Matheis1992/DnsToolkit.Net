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

using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace DnsToolkit.Net.Dns;

/// <summary>
///   A transport used by a client using tls communication
/// </summary>
public class TlsClientTransport : TcpClientTransportBase<TlsClientTransport>
{
	/// <summary>
	///   The default port of TLS DNS communication
	/// </summary>
	public const int DEFAULT_PORT = 853;

#if NETSTANDARD2_0
	private readonly string _targetHost;
	private readonly X509CertificateCollection? _clientCertificates;
	private readonly SslProtocols _enabledSslProtocols;
	private readonly bool _checkCertificateRevocation;
	private readonly RemoteCertificateValidationCallback? _remoteCertificateValidationCallback;
#else
	private readonly SslClientAuthenticationOptions _sslClientAuthenticationOptions;
#endif

	/// <summary>
	///   Creates a new instance of the TlsClientTransport
	/// </summary>
	/// <param name="targetHost">The name of the server that shares the SslStream</param>
	/// <param name="clientCertificates">The client certificates to be used, or null for none</param>
	/// <param name="enabledSslProtocols">The enabled protocols, SslProtocols.None for the system default</param>
	/// <param name="checkCertificateRevocation">A value that specifies whether the certificate revocation list is checked</param>
	/// <param name="remoteCertificateValidationCallback">A callback for validating the server certificate, or null for the default validation</param>
	/// <param name="port">The port to be used</param>
	public TlsClientTransport(string targetHost, X509CertificateCollection? clientCertificates = null, SslProtocols enabledSslProtocols = SslProtocols.None, bool checkCertificateRevocation = false, RemoteCertificateValidationCallback? remoteCertificateValidationCallback = null, int port = DEFAULT_PORT)
		: base(port)
	{
#if NETSTANDARD2_0
		_targetHost = targetHost;
		_clientCertificates = clientCertificates;
		_enabledSslProtocols = enabledSslProtocols;
		_checkCertificateRevocation = checkCertificateRevocation;
		_remoteCertificateValidationCallback = remoteCertificateValidationCallback;
#else
		_sslClientAuthenticationOptions = new SslClientAuthenticationOptions
		{
			TargetHost = targetHost,
			ClientCertificates = clientCertificates,
			EnabledSslProtocols = enabledSslProtocols,
			CertificateRevocationCheckMode = checkCertificateRevocation ? X509RevocationMode.Online : X509RevocationMode.NoCheck,
			RemoteCertificateValidationCallback = remoteCertificateValidationCallback,
		};
#endif
	}

#if !NETSTANDARD2_0
	/// <summary>
	///   Creates a new instance of the TlsClientTransport
	/// </summary>
	/// <param name="sslClientAuthenticationOptions">Options for SSL Client Authentication</param>
	/// <param name="port">The port to be used</param>
	public TlsClientTransport(SslClientAuthenticationOptions sslClientAuthenticationOptions, int port = DEFAULT_PORT)
		: base(port)
	{
		_sslClientAuthenticationOptions = sslClientAuthenticationOptions;
	}
#endif

	protected override async Task<Stream?> GetStreamAsync(TcpClient client, CancellationToken token)
	{
#if NETSTANDARD2_0
		var stream = new SslStream(client.GetStream(), false, _remoteCertificateValidationCallback);
#else
		var stream = new SslStream(client.GetStream(), false);
#endif

		try
		{
#if NETSTANDARD2_0
			// AuthenticateAsClientAsync does not support cancellation on netstandard2.0, so abort the handshake by disposing the stream
			using (token.Register(stream.Dispose))
			{
				await stream.AuthenticateAsClientAsync(_targetHost, _clientCertificates ?? new X509CertificateCollection(), _enabledSslProtocols, _checkCertificateRevocation);
			}
#else
			await stream.AuthenticateAsClientAsync(_sslClientAuthenticationOptions, token);
#endif
			token.ThrowIfCancellationRequested();

			return stream;
		}
		catch (Exception) when (token.IsCancellationRequested)
		{
			stream.Dispose();
			throw new OperationCanceledException(token);
		}
		catch
		{
			stream.Dispose();
			throw;
		}
	}
}
