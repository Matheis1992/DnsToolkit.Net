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

	// not inlined and on another stack, so no reference to the owner remains on the stack of the test
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static WeakReference CreateOwner(string owner, IClientTransport transport)
	{
		return Task.Run(() =>
		{
			var transports = new[] { transport };
			return new WeakReference(owner switch
			{
				"client" => new DnsClient(new[] { IPAddress.Loopback }, transports, true, 1000),
				"recursive" => new RecursiveDnsResolver(null, transports),
				_ => (object) new DnsSecRecursiveDnsResolver(null, transports),
			}, true);
		}).GetAwaiter().GetResult();
	}
}
