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

namespace DnsToolkit.Net.Tests;

/// <summary>
///   Tests, that the recursive resolver only trusts the data of a server inside of the zone of the server (bailiwick),
///   against one local server, which answers for the root zone, evil.test and bank.test
/// </summary>
public class RecursiveDnsResolverTests
{
	private static readonly DomainName _evilZone = DomainName.Parse("evil.test");
	private static readonly DomainName _evilHost = DomainName.Parse("x.evil.test");
	private static readonly DomainName _bankHost = DomainName.Parse("www.bank.test");
	private static readonly IPAddress _bankAddress = IPAddress.Parse("192.0.2.1");
	private static readonly IPAddress _attackerAddress = IPAddress.Parse("198.51.100.66");

	[Fact]
	public async Task RecordsOfACNameTargetInAnotherZone_AreResolvedSeparately()
	{
		// the server of evil.test answers with an alias to www.bank.test and an address of the attacker for it
		using var server = new ScriptedServer((question, response, queryCount) =>
		{
			if (question.Name.Equals(_evilHost))
			{
				if (queryCount == 1)
				{
					ReferToEvilZone(response);
				}
				else
				{
					response.IsAuthoritiveAnswer = true;
					response.AnswerRecords.Add(new CNameRecord(_evilHost, 3600, _bankHost));
					response.AnswerRecords.Add(new ARecord(_bankHost, 3600, _attackerAddress));
				}
			}
			else
			{
				AnswerBankHost(question, response);
			}
		});
		using var resolver = CreateResolver(server);

		Assert.Equal(new[] { _bankAddress }, (await resolver.ResolveAsync<ARecord>(_bankHost, token: TestToken)).Select(x => x.Address));

		// before, the address of the attacker was returned and replaced the cached address of www.bank.test
		Assert.Equal(new[] { _bankAddress }, (await resolver.ResolveAsync<ARecord>(_evilHost, token: TestToken)).Select(x => x.Address));
		Assert.Equal(new[] { _bankAddress }, (await resolver.ResolveAsync<ARecord>(_bankHost, token: TestToken)).Select(x => x.Address));
	}

	[Fact]
	public async Task RecordsOfACNameTargetInTheSameZone_AreTakenFromTheAnswer()
	{
		var target = DomainName.Parse("target.evil.test");
		var targetAddress = IPAddress.Parse("192.0.2.7");

		using var server = new ScriptedServer((question, response, queryCount) =>
		{
			if (question.Name.Equals(_evilHost))
			{
				if (queryCount == 1)
				{
					ReferToEvilZone(response);
				}
				else
				{
					response.IsAuthoritiveAnswer = true;
					response.AnswerRecords.Add(new CNameRecord(_evilHost, 3600, target));
					response.AnswerRecords.Add(new ARecord(target, 3600, targetAddress));
				}
			}
			else
			{
				// a separate query for the target would get this address
				response.IsAuthoritiveAnswer = true;
				response.AnswerRecords.Add(new ARecord(question.Name, 3600, IPAddress.Parse("192.0.2.99")));
			}
		});
		using var resolver = CreateResolver(server);

		Assert.Equal(new[] { targetAddress }, (await resolver.ResolveAsync<ARecord>(_evilHost, token: TestToken)).Select(x => x.Address));
	}

	[Fact]
	public async Task ReferralToAZoneAboveTheServer_IsIgnored()
	{
		// the server of evil.test refers to name servers of the attacker for the whole top level domain
		using var server = new ScriptedServer((question, response, queryCount) =>
		{
			if (question.Name.Equals(_evilHost))
			{
				if (queryCount == 1)
				{
					ReferToEvilZone(response);
				}
				else
				{
					var attackerServer = DomainName.Parse("ns.attacker.example");
					response.AuthorityRecords.Add(new NsRecord(DomainName.Parse("test"), 3600, attackerServer));
					response.AdditionalRecords.Add(new ARecord(attackerServer, 3600, IPAddress.Parse("127.0.0.2")));
				}
			}
			else
			{
				AnswerBankHost(question, response);
			}
		});
		using var resolver = CreateResolver(server);

		await Assert.ThrowsAnyAsync<Exception>(() => resolver.ResolveAsync<ARecord>(_evilHost, token: TestToken));

		// before, the queries for www.bank.test were sent to the name server of the attacker
		Assert.Equal(new[] { _bankAddress }, (await resolver.ResolveAsync<ARecord>(_bankHost, token: TestToken)).Select(x => x.Address));
	}

	private static readonly DomainName _deepHost = DomainName.Parse("a.b.example.test");

	[Fact]
	public async Task QNameMinimisation_SendsEveryServerOnlyOneLabelBelowItsZone()
	{
		using var server = new ScriptedServer((question, response, _) => AnswerExampleZone(question, response, ReturnCode.NoError));
		using var resolver = CreateResolver(server);

		Assert.Equal(new[] { IPAddress.Parse("192.0.2.10") }, (await resolver.ResolveAsync<ARecord>(_deepHost, token: TestToken)).Select(x => x.Address));

		// the root only gets test, the server of test only example.test, b.example.test exists without a zone cut
		Assert.Equal(new[] { "test. A", "example.test. A", "b.example.test. A", "a.b.example.test. A" }, server.Questions);
	}

	[Fact]
	public async Task QNameMinimisation_Disabled_SendsTheFullName()
	{
		using var server = new ScriptedServer((question, response, _) => AnswerExampleZone(question, response, ReturnCode.NoError));
		using var resolver = CreateResolver(server);
		resolver.IsQNameMinimisationEnabled = false;

		Assert.Single(await resolver.ResolveAsync<ARecord>(_deepHost, token: TestToken));

		Assert.Equal(new[] { "a.b.example.test. A" }, server.Questions);
	}

	[Fact]
	public async Task QNameMinimisation_AfterNxDomainForAnEmptyNonTerminal_SendsTheFullName()
	{
		// some servers answer an empty non-terminal wrongly with NXDOMAIN
		using var server = new ScriptedServer((question, response, _) => AnswerExampleZone(question, response, ReturnCode.NxDomain));
		using var resolver = CreateResolver(server);

		Assert.Equal(new[] { IPAddress.Parse("192.0.2.10") }, (await resolver.ResolveAsync<ARecord>(_deepHost, token: TestToken)).Select(x => x.Address));
		Assert.Equal(new[] { "test. A", "example.test. A", "b.example.test. A", "a.b.example.test. A" }, server.Questions);
	}

	[Fact]
	public async Task QNameMinimisation_AfterACNameForAnIntermediateName_SendsTheFullName()
	{
		using var server = new ScriptedServer((question, response, _) =>
		{
			if (question.Name.Equals(DomainName.Parse("b.example.test")))
			{
				response.IsAuthoritiveAnswer = true;
				response.AnswerRecords.Add(new CNameRecord(question.Name, 3600, DomainName.Parse("elsewhere.example.test")));
			}
			else
			{
				AnswerExampleZone(question, response, ReturnCode.NoError);
			}
		});
		using var resolver = CreateResolver(server);

		Assert.Single(await resolver.ResolveAsync<ARecord>(_deepHost, token: TestToken));
		Assert.Equal(new[] { "test. A", "example.test. A", "b.example.test. A", "a.b.example.test. A" }, server.Questions);
	}

	[Fact]
	public async Task QNameMinimisation_OfANameWithManyLabels_IsLimited()
	{
		var name = DomainName.Parse("l1.l2.l3.l4.l5.l6.l7.l8.l9.l10.l11.l12.l13.test");
		using var server = new ScriptedServer((question, response, _) =>
		{
			if (question.Name.Equals(DomainName.Parse("test")))
			{
				Refer(response, DomainName.Parse("test"));
				return;
			}

			response.IsAuthoritiveAnswer = true;
			if (question.Name.Equals(name))
				response.AnswerRecords.Add(new ARecord(name, 3600, IPAddress.Parse("192.0.2.11")));
			else
				response.AuthorityRecords.Add(new SoaRecord(DomainName.Parse("test"), 3600, DomainName.Parse("ns.test"), DomainName.Parse("hostmaster.test"), 1, 3600, 600, 86400, 300));
		});
		using var resolver = CreateResolver(server);

		Assert.Single(await resolver.ResolveAsync<ARecord>(name, token: TestToken));

		// not one query per label: after 10 minimised queries, the full name is sent
		Assert.Equal(QNameMinimiser.MAX_MINIMISED_QUERIES + 1, server.Questions.Count);
		Assert.Equal("l1.l2.l3.l4.l5.l6.l7.l8.l9.l10.l11.l12.l13.test. A", server.Questions.Last());
	}

	/// <summary>
	///   The zones test and example.test, in which b.example.test exists without records of the type A
	/// </summary>
	private static void AnswerExampleZone(DnsQuestion question, DnsMessage response, ReturnCode returnCodeOfIntermediateName)
	{
		if (question.Name.Equals(DomainName.Parse("test")))
		{
			Refer(response, DomainName.Parse("test"));
		}
		else if (question.Name.Equals(DomainName.Parse("example.test")))
		{
			Refer(response, DomainName.Parse("example.test"));
		}
		else if (question.Name.Equals(DomainName.Parse("b.example.test")))
		{
			response.IsAuthoritiveAnswer = true;
			response.ReturnCode = returnCodeOfIntermediateName;
			response.AuthorityRecords.Add(new SoaRecord(DomainName.Parse("example.test"), 3600, DomainName.Parse("ns.example.test"), DomainName.Parse("hostmaster.example.test"), 1, 3600, 600, 86400, 300));
		}
		else
		{
			response.IsAuthoritiveAnswer = true;
			response.AnswerRecords.Add(new ARecord(question.Name, 3600, IPAddress.Parse("192.0.2.10")));
		}
	}

	/// <summary>
	///   A referral to the zone, whose name server is the same local server
	/// </summary>
	private static void Refer(DnsMessage response, DomainName zone)
	{
		var nameServer = DomainName.Parse("ns." + zone);
		response.AuthorityRecords.Add(new NsRecord(zone, 3600, nameServer));
		response.AdditionalRecords.Add(new ARecord(nameServer, 3600, IPAddress.Loopback));
	}

	private static RecursiveDnsResolver CreateResolver(ScriptedServer server)
	{
		return new RecursiveDnsResolver(new LoopbackHintStore(), new IClientTransport[] { new UdpClientTransport(server.Port) })
		{
			QueryTimeout = 1000
		};
	}

	/// <summary>
	///   A referral of the root server to the server of evil.test, which is the same local server
	/// </summary>
	private static void ReferToEvilZone(DnsMessage response)
	{
		var nameServer = DomainName.Parse("ns.evil.test");
		response.AuthorityRecords.Add(new NsRecord(_evilZone, 3600, nameServer));
		response.AdditionalRecords.Add(new ARecord(nameServer, 3600, IPAddress.Loopback));
	}

	private static void AnswerBankHost(DnsQuestion question, DnsMessage response)
	{
		response.IsAuthoritiveAnswer = true;

		if (question.Name.Equals(_bankHost) && (question.RecordType == RecordType.A))
			response.AnswerRecords.Add(new ARecord(_bankHost, 3600, _bankAddress));
		else
			response.ReturnCode = ReturnCode.NxDomain;
	}

	private sealed class LoopbackHintStore : IResolverHintStore
	{
		public IReadOnlyList<IPAddress> RootServers { get; } = new[] { IPAddress.Loopback };

		public IReadOnlyList<DsRecord> RootKeys { get; } = Array.Empty<DsRecord>();
	}

	/// <summary>
	///   A local server, which answers with the given callback. It gets the number of the queries for the name so far,
	///   including the current one.
	/// </summary>
	private sealed class ScriptedServer : IDisposable
	{
		private readonly DnsServer _server;
		private readonly Action<DnsQuestion, DnsMessage, int> _answer;
		private readonly Dictionary<DomainName, int> _queryCounts = new();
		private readonly List<string> _questions = new();

		public int Port { get; }

		/// <summary>
		///   The name and type of every query so far, in the order of their arrival
		/// </summary>
		public List<string> Questions
		{
			get
			{
				lock (_queryCounts)
					return _questions.ToList();
			}
		}

		public ScriptedServer(Action<DnsQuestion, DnsMessage, int> answer)
		{
			_answer = answer;

			// A free port may be taken by another test (process) before the server binds it, so retry with other ports
			for (var attempt = 1;; attempt++)
			{
				Port = LocalDnsServer.GetFreePort();
				_server = new DnsServer(new UdpServerTransport(new IPEndPoint(IPAddress.Loopback, Port)));
				_server.QueryReceived += AnswerQuery;

				try
				{
					_server.Start();
					return;
				}
				catch (SocketException) when (attempt < 10)
				{
					((IDisposable) _server).Dispose();
				}
			}
		}

		private Task AnswerQuery(object sender, QueryReceivedEventArgs e)
		{
			var query = (DnsMessage) e.Query;
			var question = query.Questions[0];
			var response = query.CreateResponseInstance();

			int queryCount;
			lock (_queryCounts)
			{
				_queryCounts.TryGetValue(question.Name, out queryCount);
				_queryCounts[question.Name] = ++queryCount;
				_questions.Add(question.Name + " " + question.RecordType.ToShortString());
			}

			_answer(question, response, queryCount);

			e.Response = response;
			return Task.CompletedTask;
		}

		public void Dispose()
		{
			_server.Stop();
			((IDisposable) _server).Dispose();
		}
	}
}
