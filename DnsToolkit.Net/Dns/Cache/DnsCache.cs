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

using Microsoft.Extensions.Caching.Memory;

namespace DnsToolkit.Net.Dns
{
	internal class DnsCacheRecordList<T> : List<T>
	{
		public DnsSecValidationResult ValidationResult { get; set; }
	}

	/// <summary>
	///   Caches resolved records until their time to live expires. The cache is limited in size, expired entries
	///   are removed regularly and the entries used least recently are removed first if the limit is reached.
	/// </summary>
	internal class DnsCache
	{
		/// <summary>
		///   The default maximum number of cached records. An entry counts as its number of records plus one,
		///   so that also negative answers without records count.
		/// </summary>
		public const long DEFAULT_SIZE_LIMIT = 100_000;

		private static readonly TimeSpan _defaultExpirationScanFrequency = TimeSpan.FromMinutes(1);

		private class CacheKey
		{
			private readonly DomainName _name;
			private readonly RecordClass _recordClass;
			private readonly int _hashCode;
			private readonly RecordType _recordType;

			public CacheKey(DomainName name, RecordType recordType, RecordClass recordClass)
			{
				_name = name;
				_recordClass = recordClass;
				_recordType = recordType;

				_hashCode = name.GetHashCode() ^ (7 * (int) recordType) ^ (11 * (int) recordClass);
			}

			public override int GetHashCode()
			{
				return _hashCode;
			}

			public override bool Equals(object? obj)
			{
				CacheKey? other = obj as CacheKey;

				if (other == null)
					return false;

				return (_recordType == other._recordType) && (_recordClass == other._recordClass) && (_name.Equals(other._name));
			}

			public override string ToString()
			{
				return _name.ToString(true) + " " + _recordClass.ToShortString() + " " + _recordType.ToShortString();
			}
		}

		private class CacheValue
		{
			public DateTime ExpireDateUtc { get; }
			public DnsCacheRecordList<DnsRecordBase> Records { get; }

			public CacheValue(DnsCacheRecordList<DnsRecordBase> records, DateTime expireDateUtc)
			{
				Records = records;
				ExpireDateUtc = expireDateUtc;
			}
		}

		private readonly MemoryCache _cache;

		public DnsCache()
			: this(DEFAULT_SIZE_LIMIT, _defaultExpirationScanFrequency) { }

		internal DnsCache(long sizeLimit, TimeSpan expirationScanFrequency)
		{
			_cache = new MemoryCache(new MemoryCacheOptions
			{
				SizeLimit = sizeLimit,
				ExpirationScanFrequency = expirationScanFrequency,
			});
		}

		/// <summary>
		///   The number of entries
		/// </summary>
		internal int Count => _cache.Count;

		public void Add<TRecord>(DomainName name, RecordType recordType, RecordClass recordClass, IEnumerable<TRecord> records, DnsSecValidationResult validationResult, int timeToLive)
			where TRecord : DnsRecordBase
		{
			DnsCacheRecordList<DnsRecordBase> cacheValues = new DnsCacheRecordList<DnsRecordBase>();
			cacheValues.AddRange(records);
			cacheValues.ValidationResult = validationResult;

			Add(name, recordType, recordClass, cacheValues, timeToLive);
		}

		public void Add(DomainName name, RecordType recordType, RecordClass recordClass, DnsCacheRecordList<DnsRecordBase> records, int timeToLive)
		{
			CacheKey key = new CacheKey(name, recordType, recordClass);

			if (timeToLive <= 0)
			{
				// nothing to cache, but an older entry must not be returned anymore
				_cache.Remove(key);
				return;
			}

			var expireDateUtc = DateTime.UtcNow.AddSeconds(timeToLive);

			// replaces an existing entry
			_cache.Set(key, new CacheValue(records, expireDateUtc), new MemoryCacheEntryOptions
			{
				AbsoluteExpiration = new DateTimeOffset(expireDateUtc, TimeSpan.Zero),
				Size = records.Count + 1,
			});
		}

		public bool TryGetRecords<TRecord>(DomainName name, RecordType recordType, RecordClass recordClass, out List<TRecord>? records)
			where TRecord : DnsRecordBase
		{
			if (TryGetRecords(name, recordType, recordClass, out DnsCacheRecordList<TRecord>? cachedRecords))
			{
				records = cachedRecords;
				return true;
			}

			records = null;
			return false;
		}

		public bool TryGetRecords<TRecord>(DomainName name, RecordType recordType, RecordClass recordClass, out DnsCacheRecordList<TRecord>? records)
			where TRecord : DnsRecordBase
		{
			CacheKey key = new CacheKey(name, recordType, recordClass);
			DateTime utcNow = DateTime.UtcNow;

			if (_cache.TryGetValue(key, out CacheValue? cacheValue) && (cacheValue!.ExpireDateUtc > utcNow))
			{
				int ttl = (int) (cacheValue.ExpireDateUtc - utcNow).TotalSeconds;

				records = new DnsCacheRecordList<TRecord>();

				records.AddRange(cacheValue
					.Records
					.OfType<TRecord>()
					.Select(x =>
					{
						TRecord record = x.Clone<TRecord>();
						record.TimeToLive = ttl;
						return record;
					}));

				records.ValidationResult = cacheValue.Records.ValidationResult;

				return true;
			}

			records = null;
			return false;
		}
	}
}
