using System.Diagnostics;
using System.Net;
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

public class DnsCacheTests
{
	private static readonly DomainName _name = DomainName.Parse("host.example.test");
	private static readonly TimeSpan _fastScan = TimeSpan.FromMilliseconds(100);

	[Fact]
	public async Task ExpiredEntries_AreRemoved_WithoutBeingQueriedAgain()
	{
		var cache = new DnsCache(DnsCache.DEFAULT_SIZE_LIMIT, _fastScan);

		// e.g. a resolver which looks up many different names exactly once
		for (var i = 0; i < 1000; i++)
			cache.Add(Name(i), RecordType.A, RecordClass.INet, Records(Name(i), "192.0.2.1"), 1);
		Assert.Equal(1000, cache.Count);

		await Task.Delay(TimeSpan.FromSeconds(1.2));

		// any access of the cache triggers the scan for expired entries
		Assert.True(await WaitUntilAsync(() => Touch(cache) && cache.Count == 0), $"The cache still holds {cache.Count} expired entries");
	}

	[Fact]
	public async Task ValidEntries_AreKept_WhenExpiredEntriesAreRemoved()
	{
		var cache = new DnsCache(DnsCache.DEFAULT_SIZE_LIMIT, _fastScan);

		cache.Add(_name, RecordType.A, RecordClass.INet, Records(_name, "192.0.2.1"), 3600);
		for (var i = 0; i < 1000; i++)
			cache.Add(Name(i), RecordType.A, RecordClass.INet, Records(Name(i), "192.0.2.1"), 1);

		await Task.Delay(TimeSpan.FromSeconds(1.2));
		Assert.True(await WaitUntilAsync(() => Touch(cache) && cache.Count == 1), $"The cache holds {cache.Count} entries");

		Assert.True(cache.TryGetRecords<ARecord>(_name, RecordType.A, RecordClass.INet, out List<ARecord>? records));
		Assert.Equal(IPAddress.Parse("192.0.2.1"), Assert.Single(records!).Address);
	}

	[Fact]
	public async Task SizeLimit_IsNotExceeded()
	{
		// every entry has a size of its records + 1, so 2 per entry here
		var cache = new DnsCache(200, _fastScan);

		for (var i = 0; i < 1000; i++)
			cache.Add(Name(i), RecordType.A, RecordClass.INet, Records(Name(i), "192.0.2.1"), 3600);

		Assert.True(await WaitUntilAsync(() => cache.Count <= 100), $"The cache holds {cache.Count} entries, the limit allows 100");
		Assert.True(cache.Count > 0);
	}

	[Fact]
	public void NewEntry_ReplacesExistingEntry()
	{
		var cache = new DnsCache();

		cache.Add(_name, RecordType.A, RecordClass.INet, Records(_name, "192.0.2.1"), 3600);
		cache.Add(_name, RecordType.A, RecordClass.INet, Records(_name, "192.0.2.2"), 3600);

		Assert.True(cache.TryGetRecords<ARecord>(_name, RecordType.A, RecordClass.INet, out List<ARecord>? records));
		Assert.Equal(IPAddress.Parse("192.0.2.2"), Assert.Single(records!).Address);
	}

	[Fact]
	public void ZeroTimeToLive_RemovesExistingEntry()
	{
		var cache = new DnsCache();

		cache.Add(_name, RecordType.A, RecordClass.INet, Records(_name, "192.0.2.1"), 3600);
		cache.Add(_name, RecordType.A, RecordClass.INet, Records(_name, "192.0.2.2"), 0);

		Assert.False(cache.TryGetRecords<ARecord>(_name, RecordType.A, RecordClass.INet, out List<ARecord>? _));
	}

	[Fact]
	public void CachedRecords_HaveRemainingTimeToLive()
	{
		var cache = new DnsCache();

		cache.Add(_name, RecordType.A, RecordClass.INet, Records(_name, "192.0.2.1"), 3600);

		Assert.True(cache.TryGetRecords<ARecord>(_name, RecordType.A, RecordClass.INet, out List<ARecord>? records));
		Assert.InRange(Assert.Single(records!).TimeToLive, 3590, 3600);
	}

	[Fact]
	public async Task Nameserver_ExpiredZones_AreRemoved_WithoutBeingQueriedAgain()
	{
		var cache = new NameserverCache(NameserverCache.DEFAULT_SIZE_LIMIT, _fastScan);

		for (var i = 0; i < 1000; i++)
			cache.Add(Zone(i), IPAddress.Parse("192.0.2.1"), 1);
		Assert.Equal(1000, cache.Count);

		await Task.Delay(TimeSpan.FromSeconds(1.2));

		Assert.True(await WaitUntilAsync(() => !cache.TryGetAddresses(Zone(0), out _) && cache.Count == 0),
			$"The nameserver cache still holds {cache.Count} zones with expired addresses");
	}

	[Fact]
	public async Task Nameserver_SizeLimit_IsNotExceeded()
	{
		var cache = new NameserverCache(100, _fastScan);

		for (var i = 0; i < 1000; i++)
			cache.Add(Zone(i), IPAddress.Parse("192.0.2.1"), 3600);

		Assert.True(await WaitUntilAsync(() => cache.Count <= 100), $"The nameserver cache holds {cache.Count} zones, the limit allows 100");
		Assert.True(cache.Count > 0);
	}

	[Fact]
	public async Task Nameserver_KnownAddress_GetsNewExpiration()
	{
		var cache = new NameserverCache();
		var zone = DomainName.Parse("example.test");
		var address = IPAddress.Parse("192.0.2.1");

		cache.Add(zone, address, 1);
		cache.Add(zone, address, 3600);
		await Task.Delay(TimeSpan.FromSeconds(1.2));

		Assert.True(cache.TryGetAddresses(zone, out var addresses), "The address expired with its old time to live");
		Assert.Equal(address, Assert.Single(addresses!));
	}

	[Fact]
	public async Task Nameserver_AddressesExpireIndividually()
	{
		var cache = new NameserverCache();
		var zone = DomainName.Parse("example.test");

		cache.Add(zone, IPAddress.Parse("192.0.2.1"), 1);
		cache.Add(zone, IPAddress.Parse("192.0.2.2"), 3600);
		await Task.Delay(TimeSpan.FromSeconds(1.2));

		Assert.True(cache.TryGetAddresses(zone, out var addresses));
		Assert.Equal(IPAddress.Parse("192.0.2.2"), Assert.Single(addresses!));
	}

	private static DomainName Name(int i) => DomainName.Parse($"host{i}.example.test");

	private static DomainName Zone(int i) => DomainName.Parse($"zone{i}.example.test");

	private static DnsCacheRecordList<DnsRecordBase> Records(DomainName name, string address)
	{
		return new DnsCacheRecordList<DnsRecordBase> { new ARecord(name, 3600, IPAddress.Parse(address)) };
	}

	private static bool Touch(DnsCache cache)
	{
		cache.TryGetRecords<ARecord>(DomainName.Parse("other.example.test"), RecordType.A, RecordClass.INet, out List<ARecord>? _);
		return true;
	}

	/// <summary>
	///   The cache removes entries in the background, so the condition is checked repeatedly
	/// </summary>
	private static async Task<bool> WaitUntilAsync(Func<bool> condition)
	{
		var stopwatch = Stopwatch.StartNew();
		while (stopwatch.Elapsed < TimeSpan.FromSeconds(5))
		{
			if (condition())
				return true;
			await Task.Delay(50);
		}

		return condition();
	}
}
