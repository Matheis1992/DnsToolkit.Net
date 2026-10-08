using System.Net;
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

public class DnsCacheTests
{
	private static readonly DomainName _name = DomainName.Parse("host.example.test");

	[Fact]
	public void ExpiredEntries_AreRemoved_WithoutBeingQueriedAgain()
	{
		var cache = new DnsCache();

		// e.g. a resolver which looks up many different names exactly once
		for (var i = 0; i < 5000; i++)
			cache.Add(DomainName.Parse($"host{i}.example.test"), RecordType.A, RecordClass.INet, new DnsCacheRecordList<DnsRecordBase>(), -1);

		Assert.True(cache.Count < 5000, $"The cache still holds {cache.Count} expired entries");
	}

	[Fact]
	public void ValidEntries_AreKept_ByCleanup()
	{
		var cache = new DnsCache();

		cache.Add(_name, RecordType.A, RecordClass.INet, Records(_name, "192.0.2.1"), 3600);
		for (var i = 0; i < 5000; i++)
			cache.Add(DomainName.Parse($"host{i}.example.test"), RecordType.A, RecordClass.INet, new DnsCacheRecordList<DnsRecordBase>(), -1);

		Assert.True(cache.TryGetRecords<ARecord>(_name, RecordType.A, RecordClass.INet, out List<ARecord>? records));
		Assert.Equal(IPAddress.Parse("192.0.2.1"), Assert.Single(records!).Address);
	}

	[Fact]
	public void FreshEntry_ReplacesExpiredEntry()
	{
		var cache = new DnsCache();

		cache.Add(_name, RecordType.A, RecordClass.INet, Records(_name, "192.0.2.1"), -1);
		cache.Add(_name, RecordType.A, RecordClass.INet, Records(_name, "192.0.2.2"), 3600);

		Assert.True(cache.TryGetRecords<ARecord>(_name, RecordType.A, RecordClass.INet, out List<ARecord>? records), "The fresh records were not cached");
		Assert.Equal(IPAddress.Parse("192.0.2.2"), Assert.Single(records!).Address);
	}

	[Fact]
	public void Nameserver_ExpiredZones_AreRemoved_WithoutBeingQueriedAgain()
	{
		var cache = new NameserverCache();

		for (var i = 0; i < 5000; i++)
			cache.Add(DomainName.Parse($"zone{i}.example.test"), IPAddress.Parse("192.0.2.1"), -1);

		Assert.True(cache.Count < 5000, $"The nameserver cache still holds {cache.Count} zones with expired addresses");
	}

	[Fact]
	public void Nameserver_KnownAddress_GetsNewExpiration()
	{
		var cache = new NameserverCache();
		var zone = DomainName.Parse("example.test");
		var address = IPAddress.Parse("192.0.2.1");

		cache.Add(zone, address, -1);
		cache.Add(zone, address, 3600);

		Assert.True(cache.TryGetAddresses(zone, out var addresses), "The address with the new time to live was not cached");
		Assert.Equal(address, Assert.Single(addresses!));
	}

	private static DnsCacheRecordList<DnsRecordBase> Records(DomainName name, string address)
	{
		return new DnsCacheRecordList<DnsRecordBase> { new ARecord(name, 3600, IPAddress.Parse(address)) };
	}
}
