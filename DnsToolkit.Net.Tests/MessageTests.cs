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

public class MessageTests
{
	[Fact]
	public void RawPackage_SlicesLengthHeader()
	{
		var message = new DnsMessage { TransactionID = 0x1234 };
		message.Questions.Add(new DnsQuestion(DomainName.Parse("host.example.test"), RecordType.A, RecordClass.INet));

		var package = message.Encode();
		var withHeader = package.ToArraySegment(true);
		var withoutHeader = package.ToArraySegment(false);

		Assert.Equal(package.Length + DnsRawPackage.LENGTH_HEADER_LENGTH, withHeader.Count);
		Assert.Equal(package.Length, withoutHeader.Count);
		Assert.Equal(withHeader.Skip(DnsRawPackage.LENGTH_HEADER_LENGTH), withoutHeader);

		var copy = new DnsRawPackage(withHeader.ToArray());
		Assert.Equal(package.MessageIdentification, copy.MessageIdentification);
		Assert.Equal(0x1234, copy.MessageIdentification.TransactionID);

		var parsed = DnsMessage.Parse(withoutHeader);
		Assert.Equal(0x1234, parsed.TransactionID);
		Assert.Equal(message.Questions[0].Name, parsed.Questions[0].Name);
	}

	[Fact]
	public void SvcB_ParsesAndFormatsParameterLists()
	{
		var zone = ParseZone(
			"_svc.example.test. 3600 IN SVCB 1 svc.example.test. mandatory=alpn,ipv4hint alpn=h2,h3 ipv4hint=192.0.2.1,192.0.2.2 ipv6hint=2001:db8::1,2001:db8::2\n");

		var record = Assert.Single(zone.OfType<SvcBRecord>());

		var alpn = Assert.IsType<ALPNServiceBindingParameter>(record.Parameters[ServiceBindingParameterKey.ALPN]);
		Assert.Equal(new[] { "h2", "h3" }, alpn.ALPNIdentifier.Select(id => System.Text.Encoding.ASCII.GetString(id)));

		var text = record.ToString();
		Assert.Contains("mandatory=alpn,ipv4hint", text);
		Assert.Contains("alpn=\"h2,h3\"", text);
		Assert.Contains("ipv4hint=192.0.2.1,192.0.2.2", text);
		Assert.Contains("ipv6hint=2001:db8::1,2001:db8::2", text);
	}

	[Fact]
	public void SvcB_SurvivesWireFormatRoundTrip()
	{
		var zone = ParseZone(
			"_svc.example.test. 3600 IN SVCB 1 svc.example.test. alpn=h2,h3 ipv4hint=192.0.2.1 port=8443\n");
		var record = Assert.Single(zone.OfType<SvcBRecord>());

		var message = new DnsMessage { IsQuery = false };
		message.AnswerRecords.Add(record);

		var parsed = DnsMessage.Parse(message.Encode().ToArraySegment(false));

		var parsedRecord = Assert.IsType<SvcBRecord>(Assert.Single(parsed.AnswerRecords));
		Assert.Equal(record.Priority, parsedRecord.Priority);
		Assert.Equal(record.Target, parsedRecord.Target);

		// on the wire the parameters are sorted by key (RFC 9460), so compare independent of the order
		static IEnumerable<string> Canonical(SvcBRecord r) => r.Parameters.OrderBy(p => p.Key).Select(p => p.Value.ToString()!);
		Assert.Equal(Canonical(record), Canonical(parsedRecord));
		Assert.Equal(3, parsedRecord.Parameters.Count);
	}

	[Fact]
	public void SvcB_ParsesEchDohPathAndObliviousHttp()
	{
		// before, the keys were parsed as unknown keys, so the zone file names were rejected
		var zone = ParseZone(
			"_dns.resolver.example.test. 3600 IN SVCB 1 doh.example.test. alpn=h2 dohpath=/dns-query{?dns} ohttp ech=AQIDBA==\n");
		var record = Assert.Single(zone.OfType<SvcBRecord>());

		Assert.Equal("/dns-query{?dns}", Assert.IsType<DohPathServiceBindingParameter>(record.Parameters[ServiceBindingParameterKey.DohPath]).Template);
		Assert.IsType<ObliviousHttpServiceBindingParameter>(record.Parameters[ServiceBindingParameterKey.ObliviousHttp]);
		Assert.Equal(new byte[] { 1, 2, 3, 4 }, Assert.IsType<EchServiceBindingParameter>(record.Parameters[ServiceBindingParameterKey.ECH]).EchConfigList);

		var text = record.ToString();
		Assert.Contains("dohpath=\"/dns-query{?dns}\"", text);
		Assert.Contains(" ohttp", text);
		Assert.Contains("ech=AQIDBA==", text);
	}

	[Fact]
	public void SvcB_EchDohPathAndObliviousHttp_SurviveWireFormatRoundTrip()
	{
		var record = new SvcBRecord(DomainName.Parse("_dns.resolver.example.test"), 3600, 1, DomainName.Parse("doh.example.test"),
			new Dictionary<ServiceBindingParameterKey, ServiceBindingParameterBase>
			{
				// public now, before applications could not create it
				{ ServiceBindingParameterKey.ALPN, new ALPNServiceBindingParameter(new[] { "h2"u8.ToArray() }) },
				{ ServiceBindingParameterKey.ECH, new EchServiceBindingParameter(new byte[] { 0xfe, 0x0d, 0x00 }) },
				// the template is UTF-8 on the wire
				{ ServiceBindingParameterKey.DohPath, new DohPathServiceBindingParameter("/dns-query/ä{?dns}") },
				{ ServiceBindingParameterKey.ObliviousHttp, new ObliviousHttpServiceBindingParameter() }
			});

		var message = new DnsMessage { IsQuery = false };
		message.AnswerRecords.Add(record);

		var parsedRecord = Assert.IsType<SvcBRecord>(Assert.Single(DnsMessage.Parse(message.Encode().ToArraySegment(false)).AnswerRecords));

		Assert.Equal(new byte[] { 0xfe, 0x0d, 0x00 }, Assert.IsType<EchServiceBindingParameter>(parsedRecord.Parameters[ServiceBindingParameterKey.ECH]).EchConfigList);
		Assert.Equal("/dns-query/ä{?dns}", Assert.IsType<DohPathServiceBindingParameter>(parsedRecord.Parameters[ServiceBindingParameterKey.DohPath]).Template);
		Assert.IsType<ObliviousHttpServiceBindingParameter>(parsedRecord.Parameters[ServiceBindingParameterKey.ObliviousHttp]);
		Assert.Equal("h2"u8.ToArray(), Assert.Single(Assert.IsType<ALPNServiceBindingParameter>(parsedRecord.Parameters[ServiceBindingParameterKey.ALPN]).ALPNIdentifier));
	}

	[Fact]
	public void ExtendedDnsError_SurvivesWireFormatRoundTrip_SeveralInOneMessage()
	{
		var message = new DnsMessage { IsQuery = false, ReturnCode = ReturnCode.ServerFailure };
		message.EDnsOptions = new OptRecord(1232,
			new ExtendedDnsErrorOption(ExtendedDnsErrorCode.SignatureExpired, "signature of example.test expired"),
			// the extra text is UTF-8
			new ExtendedDnsErrorOption(ExtendedDnsErrorCode.Blocked, "gesperrt für Kinder"),
			new ExtendedDnsErrorOption((ExtendedDnsErrorCode) 4711));

		var parsed = DnsMessage.Parse(message.Encode().ToArraySegment(false));

		var errors = parsed.EDnsOptions!.Options.OfType<ExtendedDnsErrorOption>().ToList();
		Assert.Equal(3, errors.Count);
		Assert.Equal(ExtendedDnsErrorCode.SignatureExpired, errors[0].InfoCode);
		Assert.Equal("signature of example.test expired", errors[0].ExtraText);
		Assert.Equal("gesperrt für Kinder", errors[1].ExtraText);
		Assert.Equal((ExtendedDnsErrorCode) 4711, errors[2].InfoCode);
		Assert.Equal(String.Empty, errors[2].ExtraText);
		Assert.Equal("SignatureExpired (7): signature of example.test expired", errors[0].ToString());
	}

	[Fact]
	public void ExtendedDnsError_FromTheWire_TrimsNulAndKeepsATooShortOptionAsUnknown()
	{
		// some servers terminate the extra text with a NUL character
		var withNul = ParseResponseWithOption(15, new byte[] { 0x00, 0x06, (byte) 'b', (byte) 'a', (byte) 'd', 0x00 });
		var error = Assert.IsType<ExtendedDnsErrorOption>(Assert.Single(withNul.EDnsOptions!.Options));
		Assert.Equal(ExtendedDnsErrorCode.DnsSecBogus, error.InfoCode);
		Assert.Equal("bad", error.ExtraText);

		// the info code is mandatory, before the option did not exist at all
		var tooShort = ParseResponseWithOption(15, new byte[] { 0x06 });
		Assert.IsType<UnknownOption>(Assert.Single(tooShort.EDnsOptions!.Options));
	}

	[Fact]
	public void CompactAnswersOkFlag_SurvivesWireFormatRoundTrip_IndependentOfTheDnsSecOkFlag()
	{
		var message = new DnsMessage();
		message.EDnsOptions = new OptRecord(1232) { IsDnsSecOk = true, IsCompactAnswersOk = true };

		var parsed = DnsMessage.Parse(message.Encode().ToArraySegment(false)).EDnsOptions!;
		Assert.True(parsed.IsDnsSecOk);
		Assert.True(parsed.IsCompactAnswersOk);
		Assert.Contains("flags: DO CO", parsed.ToString());

		// before, clearing the DO flag cleared all other flags, the version and the extended response code as well
		var options = new OptRecord(1232) { IsCompactAnswersOk = true, Version = 1, IsDnsSecOk = true };
		options.IsDnsSecOk = false;
		Assert.True(options.IsCompactAnswersOk);
		Assert.Equal(1, options.Version);

		options.IsCompactAnswersOk = false;
		Assert.False(options.IsCompactAnswersOk);
		Assert.Equal(1, options.Version);
	}

	private static DnsMessage ParseResponseWithOption(ushort optionType, byte[] optionData)
	{
		var message = new DnsMessage { IsQuery = false };
		message.EDnsOptions = new OptRecord(1232, new UnknownOption((EDnsOptionType) optionType, optionData));
		return DnsMessage.Parse(message.Encode().ToArraySegment(false));
	}

	private static Zone ParseZone(string masterFile)
	{
		// ParseMasterFile(DomainName, string) expects a file name, so pass the zone content as stream
		using var stream = new MemoryStream(System.Text.Encoding.ASCII.GetBytes(masterFile));
		return Zone.ParseMasterFile(DomainName.Parse("example.test"), stream);
	}
}
