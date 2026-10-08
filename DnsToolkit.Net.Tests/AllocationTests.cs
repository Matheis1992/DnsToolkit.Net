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
