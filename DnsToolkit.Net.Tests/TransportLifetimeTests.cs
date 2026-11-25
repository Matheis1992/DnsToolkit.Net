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
using System.Reflection;
using System.Runtime.CompilerServices;
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

/// <summary>
///   The transports are only disposed explicitly
/// </summary>
public class TransportLifetimeTests
{
	[Theory]
	[InlineData("client")]
	[InlineData("recursive")]
	[InlineData("dnssec")]
	public void Finalizer_DoesNotDisposeTheTransports(string owner)
	{
		var transport = new UnreachableTransport();
		var reference = CreateOwner(owner, transport);

		// also the resurrection is tracked, so the finalizer has finished, when the reference is cleared
		var isFinalized = SpinWait.SpinUntil(() =>
		{
			GC.Collect();
			GC.WaitForPendingFinalizers();
			return !reference.IsAlive;
		}, TimeSpan.FromSeconds(5));

		Assert.True(isFinalized, "The owner of the transport was not finalized");
		Assert.Equal(0, transport.DisposeCount);
	}

	[Fact]
	public void Dispose_OfAClient_DisposesItsTransports()
	{
		var transport = new UnreachableTransport();
		IDisposable client = new DnsClient(new[] { IPAddress.Loopback }, new IClientTransport[] { transport }, true, 1000);

		client.Dispose();

		Assert.Equal(1, transport.DisposeCount);
	}

	[Theory]
	[InlineData("client")]
	[InlineData("recursive")]
	[InlineData("dnssec")]
	public void Dispose_Repeatedly_DisposesTheTransportsOnce(string owner)
	{
		var transport = new UnreachableTransport();
		var disposable = (IDisposable) CreateInstance(owner, transport);

		disposable.Dispose();
		disposable.Dispose();
		Parallel.For(0, 20, _ => disposable.Dispose());

		Assert.Equal(1, transport.DisposeCount);
	}

	[Theory]
	[InlineData("client")]
	[InlineData("recursive")]
	[InlineData("dnssec")]
	public void Dispose_DisposesAllTransports_IfOneThrows(string owner)
	{
		var first = new UnreachableTransport { DisposeException = new InvalidOperationException("first") };
		var second = new UnreachableTransport { DisposeException = new InvalidOperationException("second") };
		var third = new UnreachableTransport();
		var disposable = (IDisposable) CreateInstance(owner, first, second, third);

		var exception = Assert.Throws<InvalidOperationException>(() => disposable.Dispose());
		disposable.Dispose();

		Assert.Same(first.DisposeException, exception);
		Assert.Equal(new[] { 1, 1, 1 }, new[] { first.DisposeCount, second.DisposeCount, third.DisposeCount });
	}

	[Theory]
	[InlineData(false)]
	[InlineData(true)]
	public void Dispose_OfAStubResolver_DisposesTheCache_IfTheClientThrows(bool isDnsSec)
	{
		var transport = new UnreachableTransport { DisposeException = new InvalidOperationException() };
		var client = (DnsClient) CreateInstance("client", transport);
		IDisposable resolver = isDnsSec ? new SelfValidatingInternalDnsSecStubResolver(client, null, true) : new DnsStubResolver(client, true);

		Assert.Throws<InvalidOperationException>(() => resolver.Dispose());

		var cache = (DnsCache) resolver.GetType().GetField("_cache", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(resolver)!;
		Assert.True(cache.IsDisposed);
	}

	[Fact]
	public void Types_HaveNoFinalizer()
	{
		// none of the types owns unmanaged resources directly
		var types = typeof(DnsClient).Assembly.GetTypes()
			.Where(t => t.GetMethod("Finalize", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly, null, Type.EmptyTypes, null) != null)
			.Select(t => t.FullName);

		Assert.Empty(types);
	}

	// not inlined and on another stack, so no reference to the owner remains on the stack of the test
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static WeakReference CreateOwner(string owner, IClientTransport transport)
	{
		return Task.Run(() =>
		{
			return new WeakReference(CreateInstance(owner, transport), true);
		}).GetAwaiter().GetResult();
	}

	private static object CreateInstance(string owner, params IClientTransport[] transports)
	{
		return owner switch
		{
			"client" => new DnsClient(new[] { IPAddress.Loopback }, transports, true, 1000),
			"recursive" => new RecursiveDnsResolver(null, transports),
			_ => new DnsSecRecursiveDnsResolver(null, transports),
		};
	}
}
