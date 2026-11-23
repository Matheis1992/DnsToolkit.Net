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
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

/// <summary>
///   The stub resolvers dispose the clients, which they created themselves, but not the ones of the caller
/// </summary>
public class StubResolverDisposeTests
{
	private static readonly DomainName _name = DomainName.Parse("host.example.test");
	private static readonly Uri _endpoint = new("https://192.0.2.1/dns-query");
	private static readonly IPAddress[] _servers = { IPAddress.Parse("192.0.2.1") };

	[Theory]
	[InlineData(false)]
	[InlineData(true)]
	public void Dispose_DisposesAnOwnedClient(bool isDnsSec)
	{
		var transport = new DisposeCountingTransport();
		var resolver = CreateResolver(isDnsSec, CreateClient(transport), ownsClient: true);

		resolver.Dispose();

		Assert.Equal(1, transport.DisposeCount);
	}

	[Theory]
	[InlineData(false)]
	[InlineData(true)]
	public void Dispose_Twice_DoesNotThrow(bool isDnsSec)
	{
		var resolver = CreateResolver(isDnsSec, CreateClient(new DisposeCountingTransport()), ownsClient: true);

		resolver.Dispose();
		resolver.Dispose();
	}

	[Theory]
	[InlineData(false)]
	[InlineData(true)]
	public void Dispose_DoesNotDisposeTheClientOfTheCaller(bool isDnsSec)
	{
		var transport = new DisposeCountingTransport();
		using var client = CreateClient(transport);

		IDisposable resolver = isDnsSec ? new SelfValidatingInternalDnsSecStubResolver(client) : new DnsStubResolver(client);
		resolver.Dispose();

		Assert.Equal(0, transport.DisposeCount);
	}

	[Fact]
	public async Task Dispose_KeepsTheClientOfTheCallerAndTheCacheUsable()
	{
		using var server = new LocalDnsServer(new[] { new ARecord(_name, 3600, IPAddress.Parse("192.0.2.1")) });
		using var client = server.CreateClient(new UdpClientTransport(server.Port));
		var resolver = new DnsStubResolver(client);

		Assert.Single(await resolver.ResolveAsync<ARecord>(_name, token: TestToken));
		resolver.ClearCache();
		((IDisposable) resolver).Dispose();

		// the first one queries the server, the second one is answered by the cache
		Assert.Single(await resolver.ResolveAsync<ARecord>(_name, token: TestToken));
		Assert.Single(await resolver.ResolveAsync<ARecord>(_name, token: TestToken));
		Assert.NotNull(await client.ResolveAsync(_name, token: TestToken));
	}

	[Theory]
	[InlineData(false)]
	[InlineData(true)]
	public async Task Dispose_OfTheOwnedClient_LetsFurtherQueriesThrow(bool isDnsSec)
	{
		var transport = new DisposeCountingTransport();

		// also the constructors, which create the client
		foreach (var resolver in new[] { CreateResolver(isDnsSec, CreateClient(transport), true), CreateServerListResolver(isDnsSec), CreateDohResolver(isDnsSec) })
		{
			resolver.Dispose();
			await Assert.ThrowsAsync<ObjectDisposedException>(() => resolver.ResolveAsync<ARecord>(_name, token: TestToken));
		}

		Assert.Equal(0, transport.ConnectCount);
	}

	[Fact]
	public async Task Dispose_OfTheOwnedClient_LetsCachedAnswersThrow()
	{
		using var server = new LocalDnsServer(new[] { new ARecord(_name, 3600, IPAddress.Parse("192.0.2.1")) });
		IDnsResolver resolver = new DnsStubResolver(server.CreateClient(new UdpClientTransport(server.Port)), true);
		Assert.Single(await resolver.ResolveAsync<ARecord>(_name, token: TestToken));

		resolver.Dispose();

		await Assert.ThrowsAsync<ObjectDisposedException>(() => resolver.ResolveAsync<ARecord>(_name, token: TestToken));
	}

	[Theory]
	[InlineData(false)]
	[InlineData(true)]
	public async Task Dispose_OfTheOwnedClient_LetsTheQueryInProgressThrow(bool isDnsSec)
	{
		var transport = new DisposeCountingTransport { Connected = new TaskCompletionSource<IClientConnection?>(TaskCreationOptions.RunContinuationsAsynchronously) };
		var resolver = CreateResolver(isDnsSec, CreateClient(transport), ownsClient: true);
		var query = resolver.ResolveAsync<ARecord>(_name, token: TestToken);

		resolver.Dispose();
		transport.Connected.SetResult(null);

		await Assert.ThrowsAsync<ObjectDisposedException>(() => query);
	}

	[Theory]
	[InlineData(false)]
	[InlineData(true)]
	public async Task Dispose_WithTheClientOfTheCaller_StillSendsQueries(bool isDnsSec)
	{
		var transport = new DisposeCountingTransport();
		using var client = CreateClient(transport);
		var resolver = CreateResolver(isDnsSec, client, ownsClient: false);
		resolver.Dispose();

		// the transport connects to no server
		var exception = await Assert.ThrowsAsync<Exception>(() => resolver.ResolveAsync<ARecord>(_name, token: TestToken));

		Assert.Equal("DNS request failed", exception.Message);
		Assert.Equal(1, transport.ConnectCount);
	}

	[Fact]
	public void Finalization_DoesNotAccessTheClient()
	{
		var transport = new DisposeCountingTransport();
		using var client = CreateClient(transport);

		// like the finalizer does
		using (var stub = new FinalizableStubResolver(client))
			stub.DisposeLikeFinalizer();
		using (var selfValidating = new FinalizableSelfValidatingResolver(client))
			selfValidating.DisposeLikeFinalizer();

		Assert.Equal(0, transport.DisposeCount);
	}

	[Fact]
	public void Constructors_OwnOnlyTheClientsTheyCreate()
	{
		using var client = CreateClient(new DisposeCountingTransport());

		Assert.False(new DnsStubResolver().OwnsClient);
		Assert.False(new DnsStubResolver(client).OwnsClient);
		Assert.True(new DnsStubResolver(_servers).OwnsClient);
		Assert.True(new DnsStubResolver(_endpoint).OwnsClient);

		Assert.False(new SelfValidatingInternalDnsSecStubResolver().OwnsClient);
		Assert.False(new SelfValidatingInternalDnsSecStubResolver(client).OwnsClient);
		Assert.True(new SelfValidatingInternalDnsSecStubResolver(_servers).OwnsClient);
		Assert.True(new SelfValidatingInternalDnsSecStubResolver(_servers, 1000).OwnsClient);
		Assert.True(new SelfValidatingInternalDnsSecStubResolver(_endpoint).OwnsClient);
	}

	private static DnsClient CreateClient(IClientTransport transport) => new(new[] { IPAddress.Loopback }, new[] { transport }, true, 1000);

	private static IDnsResolver CreateServerListResolver(bool isDnsSec)
		=> isDnsSec ? new SelfValidatingInternalDnsSecStubResolver(_servers) : new DnsStubResolver(_servers);

	private static IDnsResolver CreateDohResolver(bool isDnsSec)
		=> isDnsSec ? new SelfValidatingInternalDnsSecStubResolver(_endpoint) : new DnsStubResolver(_endpoint);

	private static IDnsResolver CreateResolver(bool isDnsSec, DnsClient client, bool ownsClient)
		=> isDnsSec ? new SelfValidatingInternalDnsSecStubResolver(client, null, ownsClient) : new DnsStubResolver(client, ownsClient);

	// the resolvers own the client, but are only disposed like by the finalizer, Dispose(true) is not forwarded
	private sealed class FinalizableStubResolver : DnsStubResolver
	{
		public FinalizableStubResolver(DnsClient client)
			: base(client, true) { }

		public void DisposeLikeFinalizer() => base.Dispose(false);

		protected override void Dispose(bool isDisposing) { }
	}

	private sealed class FinalizableSelfValidatingResolver : SelfValidatingInternalDnsSecStubResolver
	{
		public FinalizableSelfValidatingResolver(DnsClient client)
			: base(client, null, true) { }

		public void DisposeLikeFinalizer() => base.Dispose(false);

		protected override void Dispose(bool isDisposing) { }
	}

	private sealed class DisposeCountingTransport : IClientTransport
	{
		private int _connectCount;
		private int _disposeCount;

		/// <summary>
		///   The result of the connects, they fail immediately if it is null
		/// </summary>
		public TaskCompletionSource<IClientConnection?>? Connected { get; set; }

		public int ConnectCount => Volatile.Read(ref _connectCount);

		public int DisposeCount => Volatile.Read(ref _disposeCount);

		public ushort MaximumAllowedQuerySize => UInt16.MaxValue;
		public bool SupportsReliableTransfer => true;
		public bool SupportsMulticastTransfer => false;
		public bool SupportsPooledConnections => false;

		public Task<IClientConnection?> ConnectAsync(DnsClientEndpointInfo endpointInfo, int queryTimeout, CancellationToken token = default)
		{
			Interlocked.Increment(ref _connectCount);
			return Connected?.Task ?? Task.FromResult<IClientConnection?>(null);
		}

		public Task<IClientConnection?> GetPooledConnectionAsync(DnsClientEndpointInfo endpointInfo, CancellationToken token = default)
			=> Task.FromResult<IClientConnection?>(null);

		public void Dispose() => Interlocked.Increment(ref _disposeCount);
	}
}
