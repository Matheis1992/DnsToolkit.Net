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

namespace DnsToolkit.Net.Dns
{
	/// <summary>
	///   Decides when a cache should remove its expired entries. Without that, entries which are never
	///   queried again would stay in the cache forever.
	/// </summary>
	internal class CacheCleanupSchedule
	{
		private const int ADDS_PER_CLEANUP = 1000;
		private static readonly TimeSpan _maxCleanupInterval = TimeSpan.FromMinutes(1);

		private int _addsSinceCleanup;
		private long _nextCleanupTicks = DateTime.UtcNow.Add(_maxCleanupInterval).Ticks;

		/// <summary>
		///   Has to be called on every add. Returns true for exactly one caller, when a cleanup is due.
		/// </summary>
		public bool IsCleanupDue()
		{
			var adds = Interlocked.Increment(ref _addsSinceCleanup);
			var nextCleanupTicks = Interlocked.Read(ref _nextCleanupTicks);

			if ((adds < ADDS_PER_CLEANUP) && (DateTime.UtcNow.Ticks < nextCleanupTicks))
				return false;

			// only the caller which moves the schedule forward does the cleanup
			if (Interlocked.CompareExchange(ref _nextCleanupTicks, DateTime.UtcNow.Add(_maxCleanupInterval).Ticks, nextCleanupTicks) != nextCleanupTicks)
				return false;

			Interlocked.Exchange(ref _addsSinceCleanup, 0);
			return true;
		}
	}
}
