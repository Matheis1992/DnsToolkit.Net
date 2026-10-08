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

	private static Zone ParseZone(string masterFile)
	{
		// ParseMasterFile(DomainName, string) expects a file name, so pass the zone content as stream
		using var stream = new MemoryStream(System.Text.Encoding.ASCII.GetBytes(masterFile));
		return Zone.ParseMasterFile(DomainName.Parse("example.test"), stream);
	}
}
