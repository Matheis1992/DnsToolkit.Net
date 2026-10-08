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

using System.Collections.Concurrent;
using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Channels;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace DnsToolkit.Net.Dns;

public class HttpsServerTransport : IServerTransport
{
	private readonly WebApplication _app;

	private readonly Channel<HttpsServerConnection> _connectionQueue = Channel.CreateUnbounded<HttpsServerConnection>();

	/// <summary>
	///   Creates a new instance of the HttpsServerTransport, which listens on all interfaces
	/// </summary>
	/// <param name="cert">The certificate of the server</param>
	/// <param name="port">The port on which the transport should listen</param>
	public HttpsServerTransport(X509Certificate2 cert, int port = 443)
		: this(cert, new HttpsServerTransportOptions { Port = port }) { }

	/// <summary>
	///   Creates a new instance of the HttpsServerTransport
	/// </summary>
	/// <param name="cert">The certificate of the server</param>
	/// <param name="endpoint">The IP endpoint on which the transport should listen</param>
	public HttpsServerTransport(X509Certificate2 cert, IPEndPoint endpoint)
		: this(cert, new HttpsServerTransportOptions { Address = endpoint.Address, Port = endpoint.Port }) { }

	/// <summary>
	///   Creates a new instance of the HttpsServerTransport
	/// </summary>
	/// <param name="cert">The certificate of the server</param>
	/// <param name="options">The settings of the server, every setting which is not set keeps its default</param>
	public HttpsServerTransport(X509Certificate2 cert, HttpsServerTransportOptions options)
	{
		// The empty builder does not read the configuration of the hosting application (appsettings.json, environment variables),
		// only the given options are used. Otherwise the configuration could e.g. add further endpoints (Kestrel:Endpoints),
		// reject requests by host name (AllowedHosts) or send stack traces to the clients (ASPNETCORE_ENVIRONMENT=Development).
		var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions());

		// Kestrel is configured when the server starts, so later changes of the options must not have an effect
		var address = options.Address;
		var port = options.Port;
		var sslProtocols = options.SslProtocols;
		var shutdownTimeout = options.ShutdownTimeout;
		var maxConcurrentConnections = options.MaxConcurrentConnections;
		var configureKestrel = options.ConfigureKestrel;

		builder.WebHost.UseKestrelCore();
		builder.WebHost.UseKestrelHttpsConfiguration();
		builder.WebHost.ConfigureKestrel(kestrel =>
		{
			kestrel.ConfigureHttpsDefaults(https =>
			{
				https.SslProtocols = sslProtocols;
				https.ServerCertificate = cert;
			});

			// Kestrel itself does not limit the connections, which would allow a client to exhaust the server
			kestrel.Limits.MaxConcurrentConnections = maxConcurrentConnections;

			if (address == null)
			{
				kestrel.ListenAnyIP(port, listen => listen.UseHttps());
			}
			else
			{
				kestrel.Listen(address, port, listen => listen.UseHttps());
			}

			// called last, so the developer can change every setting
			configureKestrel?.Invoke(kestrel);
		});

		builder.Services.AddRouting();
		builder.Services.AddLogging();
		builder.Services.Configure<HostOptions>(hostOptions => hostOptions.ShutdownTimeout = shutdownTimeout);

		_app = builder.Build();
		_app.UseStatusCodePages();
		_app.MapDnsOverHttps(options.Path, HandleRequest);
	}

	private async Task<DnsRawPackage?> HandleRequest(DnsReceivedRawPackage query, HttpContext context, CancellationToken token)
	{
		var tcs = new TaskCompletionSource<DnsRawPackage?>();
		var connection = new HttpsServerConnection(this, query, tcs);
		await _connectionQueue.Writer.WriteAsync(connection, token);
		return await tcs.Task.WaitAsync(token);
	}

	public void Dispose()
	{
		_app.TryDispose();
	}

	public ushort DefaultAllowedResponseSize => ushort.MaxValue;
	public bool SupportsMultipleResponses => false;
	public bool AllowTruncatedResponses => false;

	public TransportProtocol TransportProtocol => TransportProtocol.Https;

	/// <summary>
	///   Starts the web server. Like the other transports, it throws if the server cannot listen, e.g. because the port is in use.
	/// </summary>
	public void Bind()
	{
		_app.StartAsync().GetAwaiter().GetResult();
	}

	/// <summary>
	///   Stops the web server, requests in progress get up to 5 seconds to complete
	/// </summary>
	public void Close()
	{
		_app.StopAsync().GetAwaiter().GetResult();
	}

	public async Task<IServerConnection?> AcceptConnectionAsync(CancellationToken token = default)
	{
		await _connectionQueue.Reader.WaitToReadAsync(token);
		return _connectionQueue.Reader.TryRead(out var connection) ? connection : null;
	}

	private class HttpsServerConnection : IServerConnection
	{
		private readonly DnsReceivedRawPackage _query;
		private readonly TaskCompletionSource<DnsRawPackage?> _tcs;

		public HttpsServerConnection(IServerTransport transport, DnsReceivedRawPackage query, TaskCompletionSource<DnsRawPackage?> tcs)
		{
			Transport = transport;
			_query = query;
			_tcs = tcs;
		}

		public void Dispose()
		{
			_tcs.TrySetResult(null);
		}

		public IServerTransport Transport { get; }

		public IPEndPoint RemoteEndPoint => _query.RemoteEndpoint;

		public IPEndPoint LocalEndPoint => _query.LocalEndpoint;

		public bool CanRead { get; private set; } = true;

		public Task<bool> InitializeAsync(CancellationToken token = default)
		{
			return Task.FromResult(true);
		}

		public Task<DnsReceivedRawPackage?> ReceiveAsync(CancellationToken token = default)
		{
			if (CanRead)
			{
				CanRead = false;
				return Task.FromResult<DnsReceivedRawPackage?>(_query);
			}

			return Task.FromResult<DnsReceivedRawPackage?>(null);
		}

		public Task<bool> SendAsync(DnsRawPackage package, CancellationToken token = default)
		{
			return Task.FromResult(_tcs.TrySetResult(package));
		}
	}
}