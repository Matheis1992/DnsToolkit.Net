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
