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

public class HttpsServerTransport : IAsyncClosableServerTransport, IAsyncDisposable
{
	// Kestrel is configured when the server starts, so later changes of the options must not have an effect
	private readonly X509Certificate2 _cert;
	private readonly IPAddress? _address;
	private readonly int _port;
	private readonly string _path;
	private readonly SslProtocols _sslProtocols;
	private readonly TimeSpan _shutdownTimeout;
	private readonly long? _maxConcurrentConnections;
	private readonly Action<KestrelServerOptions>? _configureKestrel;

	private readonly object _lock = new();
	private bool _isDisposed;

	// A web application cannot be started again after it was stopped, so every bind creates a new one.
	// Null, if the transport is not bound.
	private Run? _run;

	private sealed class Run
	{
		public Run(WebApplication app, Channel<HttpsServerConnection> connectionQueue)
		{
			App = app;
			ConnectionQueue = connectionQueue;
		}

		public WebApplication App { get; }

		public Channel<HttpsServerConnection> ConnectionQueue { get; }
	}

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
		_cert = cert;
		_address = options.Address;
		_port = options.Port;
		_path = options.Path;
		_sslProtocols = options.SslProtocols;
		_shutdownTimeout = options.ShutdownTimeout;
		_maxConcurrentConnections = options.MaxConcurrentConnections;
		_configureKestrel = options.ConfigureKestrel;
	}

	private WebApplication CreateApplication(Channel<HttpsServerConnection> connectionQueue)
	{
		// The empty builder does not read the configuration of the hosting application (appsettings.json, environment variables),
		// only the given options are used. Otherwise the configuration could e.g. add further endpoints (Kestrel:Endpoints),
		// reject requests by host name (AllowedHosts) or send stack traces to the clients (ASPNETCORE_ENVIRONMENT=Development).
		var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions());

		var cert = _cert;
		var address = _address;
		var port = _port;
		var sslProtocols = _sslProtocols;
		var shutdownTimeout = _shutdownTimeout;
		var maxConcurrentConnections = _maxConcurrentConnections;
		var configureKestrel = _configureKestrel;

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

		var app = builder.Build();
		app.UseStatusCodePages();
		app.MapDnsOverHttps(_path, (DnsReceivedRawPackage query, HttpContext context, CancellationToken token) => HandleRequest(connectionQueue, query, context, token));
		return app;
	}

	private async Task<DnsRawPackage?> HandleRequest(Channel<HttpsServerConnection> connectionQueue, DnsReceivedRawPackage query, HttpContext context, CancellationToken token)
	{
		var tcs = new TaskCompletionSource<DnsRawPackage?>(TaskCreationOptions.RunContinuationsAsynchronously);
		var connection = new HttpsServerConnection(this, query, tcs);

		// the queue is unbounded, so writing only fails once the transport is closing
		if (!connectionQueue.Writer.TryWrite(connection))
			throw new EndpointRouteBuilderExtensions.ServiceUnavailableException();

		return await tcs.Task.WaitAsync(token);
	}

	/// <summary>
	///   Rejects the requests, which were not passed to the server yet, and all further requests. Otherwise they would wait
	///   until the shutdown timeout of the web server, as the server does not accept connections anymore when it is stopping.
	/// </summary>
	private static void RejectQueuedRequests(Channel<HttpsServerConnection> connectionQueue)
	{
		connectionQueue.Writer.TryComplete();

		while (connectionQueue.Reader.TryRead(out var connection))
		{
			connection.Reject();
		}
	}

	/// <summary>
	///   Ends the current run, so the transport can be bound again
	/// </summary>
	/// <returns>The run, which has to be stopped and disposed, or null if the transport was not bound</returns>
	private Run? TakeRun(bool dispose = false)
	{
		Run? run;

		lock (_lock)
		{
			if (dispose)
				_isDisposed = true;

			run = _run;
			_run = null;
		}

		if (run != null)
			RejectQueuedRequests(run.ConnectionQueue);

		return run;
	}

	public void Dispose()
	{
		// disposing stops the web server as well
		TakeRun(dispose: true)?.App.TryDispose();
	}

	public async ValueTask DisposeAsync()
	{
		var run = TakeRun(dispose: true);
		if (run == null)
			return;

		try
		{
			await run.App.DisposeAsync().ConfigureAwait(false);
		}
		catch
		{
			// like TryDispose, disposing must not fail
		}
	}

	public ushort DefaultAllowedResponseSize => ushort.MaxValue;
	public bool SupportsMultipleResponses => false;
	public bool AllowTruncatedResponses => false;

	public TransportProtocol TransportProtocol => TransportProtocol.Https;

	/// <summary>
	///   Starts the web server. Like the other transports, it throws if the server cannot listen, e.g. because the port is in use.
	///   After the transport was closed, it can be bound again.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The transport was disposed</exception>
	/// <exception cref="InvalidOperationException">The transport is already bound</exception>
	public void Bind()
	{
		lock (_lock)
		{
			if (_isDisposed)
				throw new ObjectDisposedException(GetType().FullName);

			if (_run != null)
				throw new InvalidOperationException("The transport is already bound");

			var connectionQueue = Channel.CreateUnbounded<HttpsServerConnection>();
			var app = CreateApplication(connectionQueue);

			try
			{
				app.StartAsync().GetAwaiter().GetResult();
			}
			catch
			{
				app.TryDispose();
				throw;
			}

			_run = new Run(app, connectionQueue);
		}
	}

	/// <summary>
	///   Stops the web server. The requests, which were not passed to the server yet, are rejected with 503 Service Unavailable.
	///   The requests in progress get up to the shutdown timeout to complete.
	/// </summary>
	public void Close()
	{
		var run = TakeRun();
		if (run == null)
			return;

		try
		{
			run.App.StopAsync().GetAwaiter().GetResult();
		}
		finally
		{
			run.App.TryDispose();
		}
	}

	/// <summary>
	///   Stops the web server. The requests, which were not passed to the server yet, are rejected with 503 Service Unavailable.
	///   The requests in progress get up to the shutdown timeout to complete.
	/// </summary>
	/// <param name="token">The token to indicate, that stopping should no longer be graceful</param>
	public async Task CloseAsync(CancellationToken token = default)
	{
		var run = TakeRun();
		if (run == null)
			return;

		try
		{
			await run.App.StopAsync(token).ConfigureAwait(false);
		}
		finally
		{
			try
			{
				await run.App.DisposeAsync().ConfigureAwait(false);
			}
			catch
			{
				// like TryDispose, disposing must not fail
			}
		}
	}

	/// <summary>
	///   Waits for the next request and returns it as connection
	/// </summary>
	/// <param name="token"> The token to monitor cancellation requests </param>
	/// <returns>The next request, or null if the transport was closed meanwhile</returns>
	/// <exception cref="InvalidOperationException">The transport is not bound</exception>
	public async Task<IServerConnection?> AcceptConnectionAsync(CancellationToken token = default)
	{
		var connectionQueue = Volatile.Read(ref _run)?.ConnectionQueue ?? throw new InvalidOperationException("The transport is not bound");

		await connectionQueue.Reader.WaitToReadAsync(token);
		return connectionQueue.Reader.TryRead(out var connection) ? connection : null;
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

		public void Reject()
		{
			_tcs.TrySetException(new EndpointRouteBuilderExtensions.ServiceUnavailableException());
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