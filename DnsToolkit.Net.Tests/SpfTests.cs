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
	[InlineData("192.0.2.1", "%{i}", "192.0.2.1")]
	[InlineData("2001:db8::1", "%{i}", "2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1")]
	[InlineData("2001:db8::cb01", "%{i}", "2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.b.0.1")]
	[InlineData("2001:db8::cb01", "%{ir}.%{v}", "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6")]
	[InlineData("2001:db8::cb01", "%{i4}", "c.b.0.1")]
	public async Task IpMacro_ExpandsToDottedAddress(string ip, string macro, string expected)
	{
		// IPv6 addresses are expanded to the hexadecimal digits separated by dots (RFC 7208 section 7.3)
		var resolver = new SimulatedResolver()
			.Add(new TxtRecord(_domain, 60, $"v=spf1 exists:{macro}._spf.example.test -all"))
			.Add(new ARecord(DomainName.Parse(expected + "._spf.example.test"), 60, IPAddress.Parse("127.0.0.2")));

		Assert.Equal(SpfQualifier.Pass, await CheckAsync(resolver, ip));
	}

	[Fact]
	public async Task IpMacro_InIncludeMatchesIPv6Client()
	{
		var resolver = new SimulatedResolver()
			.Add(new TxtRecord(_domain, 60, "v=spf1 include:%{ir}.%{v}.spf.test -all"))
			.Add(new TxtRecord(DomainName.Parse("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.spf.test"), 60, "v=spf1 ip6:2001:db8::1 -all"));

		Assert.Equal(SpfQualifier.Pass, await CheckAsync(resolver, "2001:db8::1"));
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

	[Theory]
	[InlineData("ip4:192.0.2.1", SpfQualifier.Pass)]
	[InlineData("ip4:192.0.2.0/24", SpfQualifier.Pass)]
	[InlineData("ip4:203.0.113.77", SpfQualifier.Fail)]
	[InlineData("ip6:::ffff:192.0.2.1", SpfQualifier.Fail)]
	[InlineData("ip6:::/0", SpfQualifier.Fail)]
	[InlineData("a", SpfQualifier.Pass)]
	[InlineData("a/24", SpfQualifier.Pass)]
	[InlineData("mx", SpfQualifier.Pass)]
	[InlineData("ptr", SpfQualifier.Pass)]
	[InlineData("include:other.test", SpfQualifier.Pass)]
	[InlineData("exists:%{ir}.%{v}._spf.example.test", SpfQualifier.Pass)]
	public async Task IPv4MappedClient_IsTreatedAsIPv4(string term, SpfQualifier expected)
	{
		// RFC 7208 section 5, such addresses are passed by servers with a dual mode socket
		var resolver = new SimulatedResolver()
			.Add(new TxtRecord(_domain, 60, $"v=spf1 {term} -all"))
			.Add(new TxtRecord(DomainName.Parse("other.test"), 60, "v=spf1 ip4:192.0.2.1 -all"))
			.Add(new MxRecord(_domain, 60, 10, _domain))
			.Add(new ARecord(_domain, 60, IPAddress.Parse("192.0.2.1")))
			.Add(new PtrRecord(IPAddress.Parse("192.0.2.1").GetReverseLookupDomain(), 60, _domain))
			.Add(new ARecord(DomainName.Parse("1.2.0.192.in-addr._spf.example.test"), 60, IPAddress.Parse("127.0.0.2")));

		Assert.Equal(expected, await CheckAsync(resolver, "192.0.2.1"));
		Assert.Equal(expected, await CheckAsync(resolver, "::ffff:192.0.2.1"));
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

	[Theory]
	[InlineData(null, 10, SpfQualifier.Pass)]
	[InlineData(null, 11, SpfQualifier.PermError)]
	[InlineData(5, 5, SpfQualifier.Pass)]
	[InlineData(5, 6, SpfQualifier.PermError)]
	[InlineData(12, 12, SpfQualifier.Pass)]
	[InlineData(12, 13, SpfQualifier.PermError)]
	[InlineData(0, 1, SpfQualifier.PermError)]
	public async Task DnsLookupLimit_LimitsTheTerms(int? limit, int termCount, SpfQualifier expected)
	{
		// only the last term matches
		var terms = Enumerable.Range(1, termCount).Select(i => $"a:a{i}.test");
		var resolver = new SimulatedResolver().Add(new TxtRecord(_domain, 60, $"v=spf1 {String.Join(" ", terms)} -all"));
		for (var i = 1; i <= termCount; i++)
			resolver.Add(CreateAddressRecord(DomainName.Parse($"a{i}.test"), i == termCount ? "192.0.2.1" : "203.0.113.77"));

		var validator = new SpfValidator { DnsResolver = resolver };
		if (limit.HasValue)
			validator.DnsLookupLimit = limit.Value;

		Assert.Equal(expected, await CheckAsync(validator, "192.0.2.1"));
	}

	[Theory]
	[InlineData(2, SpfQualifier.Pass)]
	[InlineData(1, SpfQualifier.PermError)]
	public async Task DnsLookupLimit_CountsIncludeAndRedirect(int limit, SpfQualifier expected)
	{
		var resolver = new SimulatedResolver()
			.Add(new TxtRecord(_domain, 60, "v=spf1 include:other.test redirect=target.test"))
			.Add(new TxtRecord(DomainName.Parse("other.test"), 60, "v=spf1 -all"))
			.Add(new TxtRecord(DomainName.Parse("target.test"), 60, "v=spf1 +all"));

		var validator = new SpfValidator { DnsResolver = resolver, DnsLookupLimit = limit };

		Assert.Equal(expected, await CheckAsync(validator, "192.0.2.1"));
	}

	[Fact]
	public async Task DnsLookupLimit_IgnoresTermsWithoutLookup()
	{
		var terms = Enumerable.Range(1, 20).Select(i => $"ip4:203.0.113.{i}");
		var resolver = new SimulatedResolver().Add(new TxtRecord(_domain, 60, $"v=spf1 {String.Join(" ", terms)} ip4:192.0.2.1 -all"));

		Assert.Equal(SpfQualifier.Pass, await CheckAsync(resolver, "192.0.2.1"));
	}

	[Theory]
	[InlineData("a:void1.test a:void2.test", SpfQualifier.Pass)]
	[InlineData("a:void1.test a:void2.test a:void3.test", SpfQualifier.PermError)]
	[InlineData("mx:void1.test mx:void2.test", SpfQualifier.Pass)]
	[InlineData("mx:void1.test mx:void2.test mx:void3.test", SpfQualifier.PermError)]
	[InlineData("exists:void1.test exists:void2.test", SpfQualifier.Pass)]
	[InlineData("exists:void1.test exists:void2.test exists:void3.test", SpfQualifier.PermError)]
	[InlineData("ptr ptr:void1.test", SpfQualifier.Pass)]
	[InlineData("ptr ptr:void1.test ptr:void2.test", SpfQualifier.PermError)]
	[InlineData("a:void1.test mx:void2.test exists:void3.test", SpfQualifier.PermError)]
	[InlineData("a:void1.test include:other.test", SpfQualifier.Pass)]
	[InlineData("a:void1.test a:void2.test include:other.test", SpfQualifier.PermError)]
	public async Task VoidLookupLimit_LimitsTermsWithoutAnswer(string terms, SpfQualifier expected)
	{
		// terms, whose query has no answer (RFC 7208 section 4.6.4), also those of included records
		var resolver = new SimulatedResolver()
			.Add(new TxtRecord(_domain, 60, $"v=spf1 {terms} +all"))
			.Add(new TxtRecord(DomainName.Parse("other.test"), 60, "v=spf1 a:void4.test -all"));

		Assert.Equal(expected, await CheckAsync(new SpfValidator { DnsResolver = resolver, VoidLookupLimit = 2 }, "192.0.2.1"));
	}

	[Theory]
	[InlineData("192.0.2.1")]
	[InlineData("2001:db8::1")]
	public async Task VoidLookups_AreNotLimitedByDefault(string ip)
	{
		// hosts with addresses of only one IP version, so each client has three queries without an answer
		var resolver = new SimulatedResolver()
			.Add(new TxtRecord(_domain, 60, "v=spf1 a:v4a.test a:v4b.test a:v4c.test a:v6a.test a:v6b.test a:v6c.test -all"));
		foreach (var name in new[] { "a", "b", "c" })
		{
			resolver.Add(CreateAddressRecord(DomainName.Parse($"v4{name}.test"), name == "c" ? "192.0.2.1" : "203.0.113.77"));
			resolver.Add(CreateAddressRecord(DomainName.Parse($"v6{name}.test"), name == "c" ? "2001:db8::1" : "2001:db8:ffff::9"));
		}

		Assert.Equal(SpfQualifier.Pass, await CheckAsync(resolver, ip));
		Assert.Equal(SpfQualifier.PermError, await CheckAsync(new SpfValidator { DnsResolver = resolver, VoidLookupLimit = 2 }, "2001:db8::2"));
	}

	[Theory]
	[InlineData(0, 1, SpfQualifier.PermError)]
	[InlineData(4, 4, SpfQualifier.Pass)]
	[InlineData(4, 5, SpfQualifier.PermError)]
	public async Task VoidLookupLimit_IsConfigurable(int limit, int voidCount, SpfQualifier expected)
	{
		var terms = Enumerable.Range(1, voidCount).Select(i => $"a:void{i}.test");
		var resolver = new SimulatedResolver().Add(new TxtRecord(_domain, 60, $"v=spf1 {String.Join(" ", terms)} +all"));

		var validator = new SpfValidator { DnsResolver = resolver, VoidLookupLimit = limit };

		Assert.Equal(expected, await CheckAsync(validator, "192.0.2.1"));
	}

	[Fact]
	public async Task VoidLookups_DoNotCountTheAddressesOfMailExchangers()
	{
		// mail servers with IPv4 only, the queries for their IPv6 addresses have no answer, but the MX query of the term has one
		var resolver = new SimulatedResolver().Add(new TxtRecord(_domain, 60, "v=spf1 mx ip6:2001:db8::1 -all"));
		for (var i = 1; i <= 5; i++)
		{
			resolver.Add(new MxRecord(_domain, 60, 10, DomainName.Parse($"m{i}.test")));
			resolver.Add(CreateAddressRecord(DomainName.Parse($"m{i}.test"), "203.0.113.77"));
		}

		Assert.Equal(SpfQualifier.Pass, await CheckAsync(new SpfValidator { DnsResolver = resolver, VoidLookupLimit = 2 }, "2001:db8::1"));
	}

	[Fact]
	public async Task VoidLookups_DoNotCountFailedQueries()
	{
		var resolver = new SimulatedResolver()
			.Add(new TxtRecord(_domain, 60, "v=spf1 a:void1.test a:void2.test a:failing.test -all"))
			.Fail(DomainName.Parse("failing.test"));

		Assert.Equal(SpfQualifier.TempError, await CheckAsync(new SpfValidator { DnsResolver = resolver, VoidLookupLimit = 2 }, "192.0.2.1"));
	}

	[Theory]
	[InlineData(10, 10, SpfQualifier.Pass)]
	[InlineData(10, 0, SpfQualifier.Fail)]
	[InlineData(11, 10, SpfQualifier.Pass)]
	[InlineData(11, 11, SpfQualifier.PermError)]
	[InlineData(11, 0, SpfQualifier.PermError)]
	public async Task MxMechanism_ChecksTenMailExchangers(int count, int matchingIndex, SpfQualifier expected)
	{
		var resolver = new SimulatedResolver().Add(new TxtRecord(_domain, 60, "v=spf1 mx -all"));
		for (var i = 1; i <= count; i++)
		{
			var host = DomainName.Parse($"m{i}.test");
			resolver.Add(new MxRecord(_domain, 60, 10, host));
			resolver.Add(CreateAddressRecord(host, i == matchingIndex ? "192.0.2.1" : "203.0.113.77"));
		}

		Assert.Equal(expected, await CheckAsync(resolver, "192.0.2.1"));
	}

	[Theory]
	[InlineData("ptr", 10, SpfQualifier.Pass)]
	[InlineData("ptr", 11, SpfQualifier.Fail)]
	[InlineData("exists:%{p}._spf.example.test", 10, SpfQualifier.Pass)]
	[InlineData("exists:%{p}._spf.example.test", 11, SpfQualifier.Fail)]
	public async Task Ptr_ChecksTenNames(string term, int matchingIndex, SpfQualifier expected)
	{
		// the names after the tenth are ignored, without an error
		const string ip = "192.0.2.1";
		var resolver = new SimulatedResolver()
			.Add(new TxtRecord(_domain, 60, $"v=spf1 {term} -all"))
			.Add(new ARecord(DomainName.Parse("example.test._spf.example.test"), 60, IPAddress.Parse("127.0.0.2")));
		for (var i = 1; i <= 12; i++)
		{
			var host = i == matchingIndex ? _domain : DomainName.Parse($"h{i}.test");
			resolver.Add(new PtrRecord(IPAddress.Parse(ip).GetReverseLookupDomain(), 60, host));
			resolver.Add(CreateAddressRecord(host, i == matchingIndex ? ip : "203.0.113.77"));
		}

		Assert.Equal(expected, await CheckAsync(resolver, ip));
	}

	private static DnsRecordBase CreateAddressRecord(DomainName name, string address)
	{
		var ip = IPAddress.Parse(address);
		return ip.AddressFamily == AddressFamily.InterNetworkV6 ? new AaaaRecord(name, 60, ip) : new ARecord(name, 60, ip);
	}

	private static Task<SpfQualifier> CheckAsync(SimulatedResolver resolver, string ip)
	{
		return CheckAsync(new SpfValidator { DnsResolver = resolver }, ip);
	}

	private static async Task<SpfQualifier> CheckAsync(SpfValidator validator, string ip)
	{
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
