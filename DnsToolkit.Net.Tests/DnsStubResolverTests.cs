using System.Net;
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

public class DnsStubResolverTests
{
	private static readonly DomainName _alias = DomainName.Parse("alias.example.test");
	private static readonly DomainName _target = DomainName.Parse("target.example.test");

	private static readonly DnsRecordBase[] _records =
	{
		new CNameRecord(_alias, 3600, _target),
		new ARecord(_target, 3600, IPAddress.Parse("192.0.2.1")),
	};

	[Theory]
	[InlineData(false)]
	[InlineData(true)]
	public async Task Resolve_ForTypeCName_ReturnsTheCNameRecord(bool synchronous)
	{
		using var server = new LocalDnsServer(_records);
		using IDnsResolver resolver = new DnsStubResolver(server.CreateClient(new UdpClientTransport(server.Port)));

		// before, the asynchronous version followed the CNAME and returned the CNAME records of the target, which has none
		var records = await ResolveAsync<CNameRecord>(resolver, _alias, RecordType.CName, synchronous);

		Assert.Equal(_target, Assert.Single(records).CanonicalName);
	}

	[Theory]
	[InlineData(false)]
	[InlineData(true)]
	public async Task Resolve_FollowsTheCName(bool synchronous)
	{
		using var server = new LocalDnsServer(_records);
		using IDnsResolver resolver = new DnsStubResolver(server.CreateClient(new UdpClientTransport(server.Port)));

		var records = await ResolveAsync<ARecord>(resolver, _alias, RecordType.A, synchronous);

		Assert.Equal(IPAddress.Parse("192.0.2.1"), Assert.Single(records).Address);
	}

	private static async Task<List<T>> ResolveAsync<T>(IDnsResolver resolver, DomainName name, RecordType recordType, bool synchronous)
		where T : DnsRecordBase
	{
#pragma warning disable CS0618 // the obsolete method is tested
		var resolve = synchronous ? Task.Run(() => resolver.Resolve<T>(name, recordType)) : resolver.ResolveAsync<T>(name, recordType);
#pragma warning restore CS0618

		return await resolve.WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None);
	}
}
