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

		// the clients of the query are not referenced anymore, so they are finalized
		for (var i = 0; i < 3; i++)
		{
			GC.Collect();
			GC.WaitForPendingFinalizers();
		}

		Assert.Equal(0, transport.DisposeCount);
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
		return isDnsSec ? new DnsSecRecursiveDnsResolver(null, transports) : new RecursiveDnsResolver(null, transports);
	}

	// not inlined and on another stack, so no reference to the clients remains on the stack of the test
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void RunFailingQuery(IDnsResolver resolver)
	{
		Task.Run(async () =>
		{
			await Assert.ThrowsAnyAsync<Exception>(() => resolver.ResolveAsync<ARecord>(DomainName.Parse("host.example.test")));
		}).GetAwaiter().GetResult();
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
