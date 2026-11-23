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
using System.Runtime.CompilerServices;
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

/// <summary>
///   The recursive resolvers create a client for every query. The transports belong to the resolver, which uses them for
///   the next queries, so they must not be disposed with such a client, e.g. by its finalizer.
/// </summary>
public class RecursiveResolverTransportTests
{
	[Theory]
	[InlineData(false)]
	[InlineData(true)]
	public void TransportsOfTheResolver_AreNotDisposedWithTheClientOfAQuery(bool isDnsSec)
	{
		var transport = new UnreachableTransport();
		using var resolver = CreateResolver(isDnsSec, transport);

		RunFailingQuery(resolver);
		Assert.True(transport.ConnectCount > 0, "The resolver sent no query");

		FinalizeTheClientsOfTheQuery();

		Assert.Equal(0, transport.DisposeCount);
	}

	[Theory]
	[InlineData(false)]
	[InlineData(true)]
	public void PooledConnection_IsReusedAfterTheClientOfAQueryWasFinalized(bool isDnsSec)
	{
		using var server = new FailingTcpServer();
		using var resolver = CreateResolver(isDnsSec, new TcpClientTransport(server.Port));

		RunFailingQuery(resolver);
		Assert.Equal(1, server.ConnectionCount);
		var queryCount = server.QueryCount;

		FinalizeTheClientsOfTheQuery();

		RunFailingQuery(resolver);
		Assert.True(server.QueryCount > queryCount, "The second query did not reach the server");
		Assert.Equal(1, server.ConnectionCount);
	}

	[Theory]
	[InlineData(false)]
	[InlineData(true)]
	public void Dispose_DisposesTheTransports(bool isDnsSec)
	{
		var transport = new UnreachableTransport();
		var resolver = CreateResolver(isDnsSec, transport);

		resolver.Dispose();

		Assert.Equal(1, transport.DisposeCount);
	}

	private static IDnsResolver CreateResolver(bool isDnsSec, IClientTransport transport)
	{
		var transports = new[] { transport };
		var hintStore = new LoopbackHintStore();
		return isDnsSec ? new DnsSecRecursiveDnsResolver(hintStore, transports) : new RecursiveDnsResolver(hintStore, transports);
	}

	/// <summary>
	///   The clients are not referenced anymore after the query, so they are finalized by a garbage collection
	/// </summary>
	private static void FinalizeTheClientsOfTheQuery()
	{
		for (var i = 0; i < 3; i++)
		{
			GC.Collect();
			GC.WaitForPendingFinalizers();
		}
	}

	// not inlined and on another stack, so no reference to the clients remains on the stack of the test
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void RunFailingQuery(IDnsResolver resolver)
	{
		Task.Run(async () =>
		{
			// exactly this type, so e.g. a NullReferenceException is no expected failure
			var exception = await Assert.ThrowsAsync<Exception>(() => resolver.ResolveAsync<ARecord>(DomainName.Parse("host.example.test"), token: TestToken));
			Assert.StartsWith("Could not resolve", exception.Message);
		}, TestToken).GetAwaiter().GetResult();
	}

	private sealed class LoopbackHintStore : IResolverHintStore
	{
		public IReadOnlyList<IPAddress> RootServers { get; } = new[] { IPAddress.Loopback };

		public IReadOnlyList<DsRecord> RootKeys { get; } = Array.Empty<DsRecord>();
	}

	/// <summary>
	///   A TCP server, which answers every query with SERVFAIL, and lets the client keep the connection
	/// </summary>
	private sealed class FailingTcpServer : IDisposable
	{
		private readonly DnsServer _server;
		private int _connectionCount;
		private int _queryCount;

		public int Port { get; }
		public int ConnectionCount => Volatile.Read(ref _connectionCount);
		public int QueryCount => Volatile.Read(ref _queryCount);

		public FailingTcpServer()
		{
			// A free port may be taken by another test (process) before the server binds it, so retry with other ports
			for (var attempt = 1;; attempt++)
			{
				Port = LocalDnsServer.GetFreePort();
				_server = new DnsServer(new TcpServerTransport(new IPEndPoint(IPAddress.Loopback, Port)));
				_server.ClientConnected += (_, _) =>
				{
					Interlocked.Increment(ref _connectionCount);
					return Task.CompletedTask;
				};
				_server.QueryReceived += (_, e) =>
				{
					Interlocked.Increment(ref _queryCount);
					var response = ((DnsMessage) e.Query).CreateResponseInstance();
					response.ReturnCode = ReturnCode.ServerFailure;
					response.EDnsOptions = new OptRecord(1232, new TcpKeepAliveOption(TimeSpan.FromSeconds(25)));
					e.Response = response;
					return Task.CompletedTask;
				};

				try
				{
					_server.Start();
					return;
				}
				catch (SocketException) when (attempt < 10)
				{
					((IDisposable) _server).Dispose();
				}
			}
		}

		public void Dispose()
		{
			_server.Stop();
			((IDisposable) _server).Dispose();
		}
	}

	/// <summary>
	///   A transport, which can connect to no server, and counts how often it is disposed
	/// </summary>
	private sealed class UnreachableTransport : IClientTransport
	{
		private int _connectCount;
		private int _disposeCount;

		public int ConnectCount => Volatile.Read(ref _connectCount);
		public int DisposeCount => Volatile.Read(ref _disposeCount);

		public ushort MaximumAllowedQuerySize => UInt16.MaxValue;
		public bool SupportsReliableTransfer => true;
		public bool SupportsMulticastTransfer => false;
		public bool SupportsPooledConnections => false;

		public Task<IClientConnection?> ConnectAsync(DnsClientEndpointInfo endpointInfo, int queryTimeout, CancellationToken token = default)
		{
			Interlocked.Increment(ref _connectCount);
			return Task.FromResult<IClientConnection?>(null);
		}

		public Task<IClientConnection?> GetPooledConnectionAsync(DnsClientEndpointInfo endpointInfo, CancellationToken token = default)
			=> Task.FromResult<IClientConnection?>(null);

		public void Dispose() => Interlocked.Increment(ref _disposeCount);
	}
}
