using System.Net;
using DnsToolkit.Net.Dns;
using DnsToolkit.Net.Spf;

namespace DnsToolkit.Net.Tests;

public class SpfTests : IDisposable
{
	private static readonly DomainName _domain = DomainName.Parse("example.test");

	// %{ir} expands to the client IP with reversed labels, e.g. 192.0.2.1 -> 1.2.0.192
	private readonly LocalDnsServer _server = new(new DnsRecordBase[]
	{
		new TxtRecord(_domain, 60, "v=spf1 exists:%{ir}._spf.example.test -all"),
		new ARecord(DomainName.Parse("1.2.0.192._spf.example.test"), 60, IPAddress.Parse("127.0.0.2")),
	});

	public void Dispose()
	{
		_server.Dispose();
	}

	[Theory]
	[InlineData("192.0.2.1", SpfQualifier.Pass)]
	[InlineData("192.0.2.99", SpfQualifier.Fail)]
	public async Task ReverseMacro_ExpandsToReversedIpAddress(string ip, SpfQualifier expected)
	{
		var validator = new SpfValidator
		{
			DnsResolver = new DnsStubResolver(_server.CreateClient(new UdpClientTransport(_server.Port)))
		};

		var result = await validator.CheckHostAsync(IPAddress.Parse(ip), _domain, "user@example.test");

		Assert.Equal(expected, result.Result);
	}
}
