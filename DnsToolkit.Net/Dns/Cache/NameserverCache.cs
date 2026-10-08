#region Copyright and License
// Copyright 2010..2024 Alexander Reinert
//
// This file is part of the ARSoft.Tools.Net - C# DNS client/server and SPF Library (https://github.com/alexreinert/ARSoft.Tools.Net)
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
using Microsoft.Extensions.Caching.Memory;

namespace DnsToolkit.Net.Dns
{
	/// <summary>
	///   Caches the nameserver addresses of zones. Every address expires on its own, a zone is removed with its
	///   last address. The cache is limited in size, the zones used least recently are removed first.
	/// </summary>
	internal class NameserverCache
	{
		/// <summary>
		///   The default maximum number of cached zones
		/// </summary>
		public const long DEFAULT_SIZE_LIMIT = 10_000;

		private static readonly TimeSpan _defaultExpirationScanFrequency = TimeSpan.FromMinutes(1);

		/// <summary>
		///   The addresses of a zone with their expiration
		/// </summary>
		private class ZoneAddresses
		{
			public readonly Dictionary<IPAddress, DateTime> ExpireDatesUtc = new();
		}

		private readonly MemoryCache _cache;

		// serializes the read-modify-write of zone entries, adding nameservers is rare compared to lookups
		private readonly object _addLock = new();

		public NameserverCache()
			: this(DEFAULT_SIZE_LIMIT, _defaultExpirationScanFrequency) { }

		internal NameserverCache(long sizeLimit, TimeSpan expirationScanFrequency)
		{
			_cache = new MemoryCache(new MemoryCacheOptions
			{
				SizeLimit = sizeLimit,
				ExpirationScanFrequency = expirationScanFrequency,
			});
		}

		/// <summary>
		///   The number of zones
		/// </summary>
		internal int Count => _cache.Count;

		public void Add(DomainName zoneName, IPAddress address, int timeToLive)
		{
			var utcNow = DateTime.UtcNow;
			var expireDateUtc = utcNow.AddSeconds(timeToLive);

			lock (_addLock)
			{
				var zone = _cache.TryGetValue(zoneName, out ZoneAddresses? existing) ? existing! : new ZoneAddresses();

				DateTime zoneExpireDateUtc;
				lock (zone)
				{
					// replaces the expiration of a known address
					zone.ExpireDatesUtc[address] = expireDateUtc;
					RemoveExpired(zone, utcNow);

					if (zone.ExpireDatesUtc.Count == 0)
					{
						_cache.Remove(zoneName);
						return;
					}

					zoneExpireDateUtc = zone.ExpireDatesUtc.Values.Max();
				}

				// the expiration of a cache entry cannot be changed, so the entry is set again
				_cache.Set(zoneName, zone, new MemoryCacheEntryOptions
				{
					AbsoluteExpiration = new DateTimeOffset(zoneExpireDateUtc, TimeSpan.Zero),
					Size = 1,
				});
			}
		}

		public bool TryGetAddresses(DomainName zoneName, out List<IPAddress>? addresses)
		{
			if (_cache.TryGetValue(zoneName, out ZoneAddresses? zone))
			{
				var utcNow = DateTime.UtcNow;

				lock (zone!)
				{
					addresses = zone.ExpireDatesUtc.Where(x => x.Value > utcNow).Select(x => x.Key).ToList();
				}

				if (addresses.Count > 0)
					return true;
			}

			addresses = null;
			return false;
		}

		private static void RemoveExpired(ZoneAddresses zone, DateTime utcNow)
		{
			foreach (var expired in zone.ExpireDatesUtc.Where(x => x.Value <= utcNow).Select(x => x.Key).ToList())
				zone.ExpireDatesUtc.Remove(expired);
		}
	}
}
