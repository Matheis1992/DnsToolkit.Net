using System.Diagnostics;
using System.Net;
using DnsToolkit.Net.Dns;
using Microsoft.Extensions.Internal;

namespace DnsToolkit.Net.Tests;

/// <summary>
///   Tests the caches with a manual clock, so the time to live expires without waiting
/// </summary>
public class DnsCacheTests
{
	private static readonly DomainName _name = DomainName.Parse("host.example.test");
	private static readonly TimeSpan _scanFrequency = TimeSpan.FromMinutes(1);

	[Fact]
	public async Task ExpiredEntries_AreRemoved_WithoutBeingQueriedAgain()
	{
		var clock = new ManualClock();
		var cache = new DnsCache(DnsCache.DEFAULT_SIZE_LIMIT, _scanFrequency, clock);

		// e.g. a resolver which looks up many different names exactly once
		for (var i = 0; i < 1000; i++)
			cache.Add(Name(i), RecordType.A, RecordClass.INet, Records(Name(i), "192.0.2.1"), 60);
		Assert.Equal(1000, cache.Count);

		// after the time to live and the scan frequency, any access of the cache triggers the scan for expired entries
		clock.Advance(TimeSpan.FromMinutes(2));

		Assert.True(await WaitUntilAsync(() => Touch(cache) && cache.Count == 0), $"The cache still holds {cache.Count} expired entries");
	}

	[Fact]
	public async Task ValidEntries_AreKept_WhenExpiredEntriesAreRemoved()
	{
		var clock = new ManualClock();
		var cache = new DnsCache(DnsCache.DEFAULT_SIZE_LIMIT, _scanFrequency, clock);

		cache.Add(_name, RecordType.A, RecordClass.INet, Records(_name, "192.0.2.1"), 3600);
		for (var i = 0; i < 1000; i++)
			cache.Add(Name(i), RecordType.A, RecordClass.INet, Records(Name(i), "192.0.2.1"), 60);

		clock.Advance(TimeSpan.FromMinutes(2));
		Assert.True(await WaitUntilAsync(() => Touch(cache) && cache.Count == 1), $"The cache holds {cache.Count} entries");

		Assert.True(cache.TryGetRecords<ARecord>(_name, RecordType.A, RecordClass.INet, out List<ARecord>? records));
		Assert.Equal(IPAddress.Parse("192.0.2.1"), Assert.Single(records!).Address);
	}

	[Fact]
	public void Entry_ExpiresExactlyAfterTimeToLive()
	{
		var clock = new ManualClock();
		var cache = new DnsCache(DnsCache.DEFAULT_SIZE_LIMIT, _scanFrequency, clock);

		cache.Add(_name, RecordType.A, RecordClass.INet, Records(_name, "192.0.2.1"), 60);

		clock.Advance(TimeSpan.FromSeconds(59));
		Assert.True(cache.TryGetRecords<ARecord>(_name, RecordType.A, RecordClass.INet, out List<ARecord>? records), "The entry expired before its time to live");
		Assert.Equal(1, Assert.Single(records!).TimeToLive);

		clock.Advance(TimeSpan.FromSeconds(1));
		Assert.False(cache.TryGetRecords<ARecord>(_name, RecordType.A, RecordClass.INet, out List<ARecord>? _), "The entry is returned after its time to live");
	}

	[Fact]
	public void CachedRecords_HaveRemainingTimeToLive()
	{
		var clock = new ManualClock();
		var cache = new DnsCache(DnsCache.DEFAULT_SIZE_LIMIT, _scanFrequency, clock);

		cache.Add(_name, RecordType.A, RecordClass.INet, Records(_name, "192.0.2.1"), 3600);
		clock.Advance(TimeSpan.FromSeconds(100));

		Assert.True(cache.TryGetRecords<ARecord>(_name, RecordType.A, RecordClass.INet, out List<ARecord>? records));
		Assert.Equal(3500, Assert.Single(records!).TimeToLive);
	}

	[Fact]
	public async Task SizeLimit_IsNotExceeded()
	{
		// every entry has a size of its records + 1, so 2 per entry here
		var cache = new DnsCache(200, _scanFrequency);

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
	public async Task Nameserver_ExpiredZones_AreRemoved_WithoutBeingQueriedAgain()
	{
		var clock = new ManualClock();
		var cache = new NameserverCache(NameserverCache.DEFAULT_SIZE_LIMIT, _scanFrequency, clock);

		for (var i = 0; i < 1000; i++)
			cache.Add(Zone(i), IPAddress.Parse("192.0.2.1"), 60);
		Assert.Equal(1000, cache.Count);

		clock.Advance(TimeSpan.FromMinutes(2));

		Assert.True(await WaitUntilAsync(() => !cache.TryGetAddresses(Zone(0), out _) && cache.Count == 0),
			$"The nameserver cache still holds {cache.Count} zones with expired addresses");
	}

	[Fact]
	public async Task Nameserver_SizeLimit_IsNotExceeded()
	{
		var cache = new NameserverCache(100, _scanFrequency);

		for (var i = 0; i < 1000; i++)
			cache.Add(Zone(i), IPAddress.Parse("192.0.2.1"), 3600);

		Assert.True(await WaitUntilAsync(() => cache.Count <= 100), $"The nameserver cache holds {cache.Count} zones, the limit allows 100");
		Assert.True(cache.Count > 0);
	}

	[Fact]
	public void Nameserver_KnownAddress_GetsNewExpiration()
	{
		var clock = new ManualClock();
		var cache = new NameserverCache(NameserverCache.DEFAULT_SIZE_LIMIT, _scanFrequency, clock);
		var zone = DomainName.Parse("example.test");
		var address = IPAddress.Parse("192.0.2.1");

		cache.Add(zone, address, 60);
		cache.Add(zone, address, 3600);
		clock.Advance(TimeSpan.FromMinutes(2));

		Assert.True(cache.TryGetAddresses(zone, out var addresses), "The address expired with its old time to live");
		Assert.Equal(address, Assert.Single(addresses!));
	}

	[Fact]
	public void Nameserver_AddressesExpireIndividually()
	{
		var clock = new ManualClock();
		var cache = new NameserverCache(NameserverCache.DEFAULT_SIZE_LIMIT, _scanFrequency, clock);
		var zone = DomainName.Parse("example.test");

		cache.Add(zone, IPAddress.Parse("192.0.2.1"), 60);
		cache.Add(zone, IPAddress.Parse("192.0.2.2"), 3600);
		clock.Advance(TimeSpan.FromMinutes(2));

		Assert.True(cache.TryGetAddresses(zone, out var addresses));
		Assert.Equal(IPAddress.Parse("192.0.2.2"), Assert.Single(addresses!));
	}

	[Fact]
	public void Nameserver_ZoneExpiresExactlyAfterTimeToLiveOfLastAddress()
	{
		var clock = new ManualClock();
		var cache = new NameserverCache(NameserverCache.DEFAULT_SIZE_LIMIT, _scanFrequency, clock);
		var zone = DomainName.Parse("example.test");

		cache.Add(zone, IPAddress.Parse("192.0.2.1"), 30);
		cache.Add(zone, IPAddress.Parse("192.0.2.2"), 60);

		clock.Advance(TimeSpan.FromSeconds(59));
		Assert.True(cache.TryGetAddresses(zone, out _), "The zone expired before the time to live of its last address");

		clock.Advance(TimeSpan.FromSeconds(1));
		Assert.False(cache.TryGetAddresses(zone, out _), "The zone is returned after the time to live of its last address");
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

	/// <summary>
	///   A clock which only moves when the test advances it
	/// </summary>
	private sealed class ManualClock : ISystemClock
	{
		private long _ticks = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero).UtcTicks;

		public DateTimeOffset UtcNow => new(Interlocked.Read(ref _ticks), TimeSpan.Zero);

		public void Advance(TimeSpan time) => Interlocked.Add(ref _ticks, time.Ticks);
	}
}
