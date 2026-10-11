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

#if !NETFRAMEWORK
using System.Net;
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

[Collection(NonParallelCollection.Name)]
public class AllocationTests
{
	private static readonly DomainName _name = DomainName.Parse("host.example.test");

	[Fact]
	public async Task Udp_AllocatesNoReceiveBufferOfSocketBufferSize()
	{
		using var server = new LocalDnsServer(new DnsRecordBase[] { new ARecord(_name, 60, IPAddress.Parse("192.0.2.1")) });
		using var client = server.CreateClient(new UdpClientTransport(server.Port));

		for (var i = 0; i < 20; i++)
			Assert.NotNull(await client.ResolveAsync(_name));

		const int queries = 200;
		var before = GC.GetTotalAllocatedBytes(true);
		for (var i = 0; i < queries; i++)
			Assert.NotNull(await client.ResolveAsync(_name));
		var perQuery = (GC.GetTotalAllocatedBytes(true) - before) / queries;

		// client and server together; the socket receive buffer alone is 64 KB on Windows and ~208 KB on Linux
		Assert.True(perQuery < 32 * 1024, $"{perQuery} bytes allocated per UDP query");
	}
}
#endif
