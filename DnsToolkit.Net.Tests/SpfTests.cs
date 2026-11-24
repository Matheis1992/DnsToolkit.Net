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
using System.Net.Sockets;
using DnsToolkit.Net.Dns;
using DnsToolkit.Net.Spf;

namespace DnsToolkit.Net.Tests;

/// <summary>
///   Tests the SPF validation with a simulated resolver, which answers from a fixed set of records without network
/// </summary>
public class SpfTests
{
	private static readonly DomainName _domain = DomainName.Parse("example.test");

	[Theory]
	[InlineData("192.0.2.1", SpfQualifier.Pass)]
	[InlineData("192.0.2.99", SpfQualifier.Fail)]
	public async Task ReverseMacro_ExpandsToReversedIpAddress(string ip, SpfQualifier expected)
	{
		// %{ir} expands to the client IP with reversed labels, e.g. 192.0.2.1 -> 1.2.0.192
		var resolver = new SimulatedResolver()
			.Add(new TxtRecord(_domain, 60, "v=spf1 exists:%{ir}._spf.example.test -all"))
			.Add(new ARecord(DomainName.Parse("1.2.0.192._spf.example.test"), 60, IPAddress.Parse("127.0.0.2")));

		Assert.Equal(expected, await CheckAsync(resolver, ip));
	}

	[Theory]
	[InlineData("192.0.2.5", SpfQualifier.Pass)]
	[InlineData("192.0.3.5", SpfQualifier.Fail)]
	public async Task Ip4Mechanism_MatchesNetwork(string ip, SpfQualifier expected)
	{
		var resolver = new SimulatedResolver().Add(new TxtRecord(_domain, 60, "v=spf1 ip4:192.0.2.0/24 -all"));

		Assert.Equal(expected, await CheckAsync(resolver, ip));
	}

	[Fact]
	public async Task AMechanism_MatchesAddressOfDomain()
	{
		var resolver = new SimulatedResolver()
			.Add(new TxtRecord(_domain, 60, "v=spf1 a -all"))
			.Add(new ARecord(_domain, 60, IPAddress.Parse("192.0.2.10")));

		Assert.Equal(SpfQualifier.Pass, await CheckAsync(resolver, "192.0.2.10"));
		Assert.Equal(SpfQualifier.Fail, await CheckAsync(resolver, "192.0.2.11"));
	}

	[Theory]
	[InlineData("a//64", "2001:db8::99", SpfQualifier.Pass)]
	[InlineData("a//64", "2001:db8:0:1::99", SpfQualifier.Fail)]
	[InlineData("a//64", "192.0.2.10", SpfQualifier.Pass)]
	[InlineData("a//64", "192.0.2.11", SpfQualifier.Fail)]
	[InlineData("a/24//64", "2001:db8::99", SpfQualifier.Pass)]
	[InlineData("a/24/64", "2001:db8::99", SpfQualifier.Pass)]
	[InlineData("a/24//64", "192.0.2.11", SpfQualifier.Pass)]
	[InlineData("a/24", "192.0.2.11", SpfQualifier.Pass)]
	[InlineData("a/24", "2001:db8::99", SpfQualifier.Fail)]
	[InlineData("a:example.test//64", "2001:db8::99", SpfQualifier.Pass)]
	[InlineData("a:example.test/24//64", "192.0.2.11", SpfQualifier.Pass)]
	[InlineData("a//0", "2001:db8:ffff::9", SpfQualifier.Pass)]
	[InlineData("a//128", "2001:db8::1", SpfQualifier.Pass)]
	[InlineData("mx//64", "2001:db8::99", SpfQualifier.Pass)]
	[InlineData("mx/24//64", "192.0.2.11", SpfQualifier.Pass)]
	[InlineData("mx:example.test//64", "2001:db8:0:1::99", SpfQualifier.Fail)]
	public async Task PrefixLengths_ApplyToTheirIpVersion(string term, string ip, SpfQualifier expected)
	{
		// dual-cidr-length (RFC 7208 section 5.6)
		Assert.Equal(expected, await CheckAsync(CreateDualStackResolver(term), ip));
	}

	[Theory]
	[InlineData("a/33")]
	[InlineData("a//129")]
	[InlineData("a/24//129")]
	[InlineData("a/99999999999")]
	[InlineData("a//99999999999")]
	[InlineData("mx/33")]
	[InlineData("mx//129")]
	[InlineData("a//")]
	[InlineData("a/24//")]
	[InlineData("a///64")]
	[InlineData("a/24s")]
	[InlineData("a//64s")]
	[InlineData("a//64/24")]
	[InlineData("ip4:192.0.2.10//32")]
	[InlineData("ip6:2001:db8::1//64")]
	[InlineData("exists:example.test//64")]
	[InlineData("ip4:192.0.2.10//99999999999")]
	[InlineData("exists:example.test//99999999999")]
	[InlineData("ip4:192.0.2.10/99999999999")]
	[InlineData("ip6:2001:db8::1/99999999999")]
	[InlineData("exists:example.test/24")]
	[InlineData("ptr/24")]
	[InlineData("all/24")]
	[InlineData("all/99999999999")]
	public async Task InvalidPrefixLengths_ResultInPermError(string term)
	{
		Assert.Equal(SpfQualifier.PermError, await CheckAsync(CreateDualStackResolver(term), "192.0.2.10"));
		Assert.Equal(SpfQualifier.PermError, await CheckAsync(CreateDualStackResolver(term), "2001:db8::1"));
	}

	[Theory]
	[InlineData("ip4:2001:db8::1")]
	[InlineData("ip4:2001:db8::/32")]
	[InlineData("ip4:::ffff:192.0.2.10")]
	[InlineData("ip6:192.0.2.10")]
	[InlineData("ip6:192.0.2.0/24")]
	public async Task IpMechanismWithOtherIpVersion_ResultsInPermError(string term)
	{
		Assert.Equal(SpfQualifier.PermError, await CheckAsync(CreateDualStackResolver(term), "192.0.2.10"));
		Assert.Equal(SpfQualifier.PermError, await CheckAsync(CreateDualStackResolver(term), "2001:db8::1"));
	}

	[Theory]
	[InlineData("ip4:192.0.2.0/24", SpfQualifier.Pass, SpfQualifier.Fail)]
	[InlineData("ip4:192.0.2.10", SpfQualifier.Pass, SpfQualifier.Fail)]
	[InlineData("ip6:2001:db8::/32", SpfQualifier.Fail, SpfQualifier.Pass)]
	[InlineData("ip6:2001:db8::1", SpfQualifier.Fail, SpfQualifier.Pass)]
	public async Task IpMechanism_MatchesOnlyItsIpVersion(string term, SpfQualifier expectedIPv4, SpfQualifier expectedIPv6)
	{
		Assert.Equal(expectedIPv4, await CheckAsync(CreateDualStackResolver(term), "192.0.2.10"));
		Assert.Equal(expectedIPv6, await CheckAsync(CreateDualStackResolver(term), "2001:db8::1"));
	}

	[Theory]
	[InlineData("v=spf1 a//64 -all")]
	[InlineData("v=spf1 a/24//64 -all")]
	[InlineData("v=spf1 mx:example.test/24//64 -all")]
	public void PrefixLengths_AreParsedAndFormatted(string record)
	{
		Assert.True(DnsToolkit.Net.Spf.SpfRecord.TryParse(record, out var parsed));
		Assert.Equal(record, parsed!.ToString());
	}

	private static SimulatedResolver CreateDualStackResolver(string term)
	{
		return new SimulatedResolver()
			.Add(new TxtRecord(_domain, 60, $"v=spf1 {term} -all"))
			.Add(new MxRecord(_domain, 60, 10, _domain))
			.Add(new ARecord(_domain, 60, IPAddress.Parse("192.0.2.10")))
			.Add(new AaaaRecord(_domain, 60, IPAddress.Parse("2001:db8::1")));
	}

	[Fact]
	public async Task MxMechanism_MatchesAddressOfMailExchanger()
	{
		var mailServer = DomainName.Parse("mail.example.test");
		var resolver = new SimulatedResolver()
			.Add(new TxtRecord(_domain, 60, "v=spf1 mx -all"))
			.Add(new MxRecord(_domain, 60, 10, mailServer))
			.Add(new ARecord(mailServer, 60, IPAddress.Parse("192.0.2.20")));

		Assert.Equal(SpfQualifier.Pass, await CheckAsync(resolver, "192.0.2.20"));
		Assert.Equal(SpfQualifier.Fail, await CheckAsync(resolver, "192.0.2.21"));
	}

	[Theory]
	[InlineData("192.0.2.1", "192.0.2.1", SpfQualifier.Pass)]
	[InlineData("192.0.2.1", "203.0.113.77", SpfQualifier.Fail)]
	[InlineData("2001:db8::1", "2001:db8::1", SpfQualifier.Pass)]
	[InlineData("2001:db8::1", "2001:db8:ffff::9", SpfQualifier.Fail)]
	public async Task PtrMechanism_RequiresThatTheNameResolvesToTheClient(string ip, string hostAddress, SpfQualifier expected)
	{
		// the PTR record is controlled by the owner of the address, so the name only counts, if it
		// has the address of the client (RFC 7208 section 5.5)
		var host = DomainName.Parse("mail.example.test");
		var resolver = new SimulatedResolver()
			.Add(new TxtRecord(_domain, 60, "v=spf1 ptr -all"))
			.Add(new PtrRecord(IPAddress.Parse(ip).GetReverseLookupDomain(), 60, host))
			.Add(CreateAddressRecord(host, hostAddress));

		Assert.Equal(expected, await CheckAsync(resolver, ip));
	}

	[Fact]
	public async Task PtrMechanism_MatchesAnyAddressOfTheName()
	{
		var host = DomainName.Parse("mail.example.test");
		var resolver = new SimulatedResolver()
			.Add(new TxtRecord(_domain, 60, "v=spf1 ptr -all"))
			.Add(new PtrRecord(IPAddress.Parse("192.0.2.1").GetReverseLookupDomain(), 60, host))
			.Add(CreateAddressRecord(host, "203.0.113.77"))
			.Add(CreateAddressRecord(host, "192.0.2.1"));

		Assert.Equal(SpfQualifier.Pass, await CheckAsync(resolver, "192.0.2.1"));
	}

	[Theory]
	[InlineData("192.0.2.1", "192.0.2.1", "mail.example.test")]
	[InlineData("192.0.2.1", "203.0.113.77", "unknown")]
	[InlineData("2001:db8::1", "2001:db8::1", "mail.example.test")]
	[InlineData("2001:db8::1", "2001:db8:ffff::9", "unknown")]
	public async Task PtrMacro_ExpandsToValidatedNameOnly(string ip, string hostAddress, string expectedName)
	{
		// without a validated name %{p} expands to "unknown" (RFC 7208 section 7.3)
		var host = DomainName.Parse("mail.example.test");
		var resolver = new SimulatedResolver()
			.Add(new TxtRecord(_domain, 60, "v=spf1 exists:%{p}._spf.example.test -all"))
			.Add(new PtrRecord(IPAddress.Parse(ip).GetReverseLookupDomain(), 60, host))
			.Add(CreateAddressRecord(host, hostAddress))
			.Add(new ARecord(DomainName.Parse(expectedName + "._spf.example.test"), 60, IPAddress.Parse("127.0.0.2")));

		Assert.Equal(SpfQualifier.Pass, await CheckAsync(resolver, ip));
	}

	[Fact]
	public async Task IncludeMechanism_UsesResultOfIncludedDomain()
	{
		var resolver = new SimulatedResolver()
			.Add(new TxtRecord(_domain, 60, "v=spf1 include:provider.test -all"))
			.Add(new TxtRecord(DomainName.Parse("provider.test"), 60, "v=spf1 ip4:198.51.100.0/24 -all"));

		// a match of the included domain matches, a fail of it continues with the next mechanism
		Assert.Equal(SpfQualifier.Pass, await CheckAsync(resolver, "198.51.100.7"));
		Assert.Equal(SpfQualifier.Fail, await CheckAsync(resolver, "192.0.2.1"));
	}

	[Fact]
	public async Task RedirectModifier_UsesRecordOfOtherDomain()
	{
		var resolver = new SimulatedResolver()
			.Add(new TxtRecord(_domain, 60, "v=spf1 redirect=other.test"))
			.Add(new TxtRecord(DomainName.Parse("other.test"), 60, "v=spf1 ip4:203.0.113.0/24 ~all"));

		Assert.Equal(SpfQualifier.Pass, await CheckAsync(resolver, "203.0.113.9"));
		Assert.Equal(SpfQualifier.SoftFail, await CheckAsync(resolver, "192.0.2.1"));
	}

	[Theory]
	[InlineData("v=spf1 -all", SpfQualifier.Fail)]
	[InlineData("v=spf1 ~all", SpfQualifier.SoftFail)]
	[InlineData("v=spf1 ?all", SpfQualifier.Neutral)]
	[InlineData("v=spf1 +all", SpfQualifier.Pass)]
	[InlineData("v=spf1", SpfQualifier.Neutral)]
	public async Task Qualifiers_AreReturned(string record, SpfQualifier expected)
	{
		var resolver = new SimulatedResolver().Add(new TxtRecord(_domain, 60, record));

		Assert.Equal(expected, await CheckAsync(resolver, "192.0.2.1"));
	}

	[Theory]
	[InlineData("v=spf1", true)]
	[InlineData("v=spf1 -all", true)]
	[InlineData("v=spf1x -all", false)]
	[InlineData("v=spf10 -all", false)]
	[InlineData("spf1 -all", false)]
	[InlineData("", false)]
	public void IsSpfRecord_RequiresVersionFollowedBySpaceOrEnd(string text, bool expected)
	{
		Assert.Equal(expected, DnsToolkit.Net.Spf.SpfRecord.IsSpfRecord(text));
	}

	[Fact]
	public async Task NoSpfRecord_ResultsInNone()
	{
		var resolver = new SimulatedResolver().Add(new TxtRecord(_domain, 60, "some other text"));

		Assert.Equal(SpfQualifier.None, await CheckAsync(resolver, "192.0.2.1"));
	}

	[Fact]
	public async Task TwoSpfRecords_ResultInPermError()
	{
		var resolver = new SimulatedResolver()
			.Add(new TxtRecord(_domain, 60, "v=spf1 -all"))
			.Add(new TxtRecord(_domain, 60, "v=spf1 +all"));

		Assert.Equal(SpfQualifier.PermError, await CheckAsync(resolver, "192.0.2.1"));
	}

	[Fact]
	public async Task DnsFailure_ResultsInTempError()
	{
		var resolver = new SimulatedResolver().Fail(_domain);

		Assert.Equal(SpfQualifier.TempError, await CheckAsync(resolver, "192.0.2.1"));
	}

	[Fact]
	public async Task MoreThanTenDnsLookups_ResultInPermError()
	{
		// a chain of includes, each one needs a DNS lookup (RFC 7208 section 4.6.4)
		var resolver = new SimulatedResolver().Add(new TxtRecord(_domain, 60, "v=spf1 include:i1.test -all"));
		for (var i = 1; i <= 11; i++)
			resolver.Add(new TxtRecord(DomainName.Parse($"i{i}.test"), 60, $"v=spf1 include:i{i + 1}.test -all"));
		resolver.Add(new TxtRecord(DomainName.Parse("i12.test"), 60, "v=spf1 +all"));

		Assert.Equal(SpfQualifier.PermError, await CheckAsync(resolver, "192.0.2.1"));
	}

	private static DnsRecordBase CreateAddressRecord(DomainName name, string address)
	{
		var ip = IPAddress.Parse(address);
		return ip.AddressFamily == AddressFamily.InterNetworkV6 ? new AaaaRecord(name, 60, ip) : new ARecord(name, 60, ip);
	}

	private static async Task<SpfQualifier> CheckAsync(SimulatedResolver resolver, string ip)
	{
		var validator = new SpfValidator { DnsResolver = resolver };
		var result = await validator.CheckHostAsync(IPAddress.Parse(ip), _domain, "user@example.test");
		return result.Result;
	}

	/// <summary>
	///   Answers from a fixed set of records. A failing name throws, like a resolver on a server failure.
	/// </summary>
	private sealed class SimulatedResolver : IDnsResolver
	{
		private readonly List<DnsRecordBase> _records = new();
		private readonly HashSet<DomainName> _failingNames = new();

		public SimulatedResolver Add(DnsRecordBase record)
		{
			_records.Add(record);
			return this;
		}

		public SimulatedResolver Fail(DomainName name)
		{
			_failingNames.Add(name);
			return this;
		}

		public List<T> Resolve<T>(DomainName name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet)
			where T : DnsRecordBase
		{
			if (_failingNames.Contains(name))
				throw new Exception("Server failure");

			return _records.Where(r => r.Name.Equals(name) && r.RecordType == recordType && r.RecordClass == recordClass).OfType<T>().ToList();
		}

		public Task<List<T>> ResolveAsync<T>(DomainName name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet, CancellationToken token = default)
			where T : DnsRecordBase
		{
			return Task.FromResult(Resolve<T>(name, recordType, recordClass));
		}

		public void ClearCache() { }

		public void Dispose() { }
	}
}
