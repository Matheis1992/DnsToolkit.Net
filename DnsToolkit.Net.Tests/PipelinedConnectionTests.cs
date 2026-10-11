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

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Threading.Channels;
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

/// <summary>
///   Tests the pooled connections of TCP and TLS with a simulated connection, so the order of sending and receiving is controlled exactly
/// </summary>
public class PipelinedConnectionTests
{
	private static readonly DomainName _zone = DomainName.Parse("example.test");

	[Fact]
	public async Task ResponseReadBeforeTheClientWaitsForIt_IsDelivered()
	{
		var transport = new SimulatedTransport(query => query.Questions[0].Name.Labels[0] == "fast" ? new[] { Answer(query) } : Array.Empty<DnsMessage>());
		using var client = new DnsClient(new[] { IPAddress.Loopback }, new IClientTransport[] { transport }, true, 1000);

		// a query which is never answered keeps the receive loop of the pooled connection running
		var slow = client.ResolveAsync(DomainName.Parse("slow.example.test"));
		Assert.True(await transport.Connection.WaitForWaitingReceiveLoopAsync(TimeSpan.FromSeconds(5)), "The receive loop did not start");

		// The response to this query is read by the running receive loop already while the query is sent,
		// so before the client waits for the response. It used to be dropped, as no receiver was registered yet.
		var stopwatch = Stopwatch.StartNew();
		var fast = await client.ResolveAsync(DomainName.Parse("fast.example.test"));

		Assert.NotNull(fast);
		Assert.Contains(fast!.AnswerRecords.OfType<ARecord>(), a => a.Address.Equals(IPAddress.Parse("192.0.2.1")));
		Assert.InRange(stopwatch.Elapsed, TimeSpan.Zero, TimeSpan.FromMilliseconds(900));
		Assert.Equal(1, transport.ConnectCount);

		Assert.Null(await slow);
	}

	[Fact]
	public async Task ZoneTransferMessages_ReadBeforeTheClientWaitsForThem_AreDelivered()
	{
		var transport = new SimulatedTransport(query => query.Questions[0].RecordType == RecordType.Axfr
			? new[] { ZoneTransferMessage(query, Soa(), A("a")), ZoneTransferMessage(query, A("b")), ZoneTransferMessage(query, A("c"), Soa()) }
			: Array.Empty<DnsMessage>());
		using var client = new DnsClient(new[] { IPAddress.Loopback }, new IClientTransport[] { transport }, true, 1000);

		// a query which is never answered keeps the receive loop of the pooled connection running
		var slow = client.ResolveAsync(DomainName.Parse("slow.example.test"));
		Assert.True(await transport.Connection.WaitForWaitingReceiveLoopAsync(TimeSpan.FromSeconds(5)), "The receive loop did not start");

		// All messages of the zone transfer are read by the receive loop while the query is sent, so the follow-up
		// messages arrive before the client asks for them. They used to be dropped, as only the first one had a receiver.
		var stopwatch = Stopwatch.StartNew();
		var response = await client.SendMessageAsync(ZoneTransferQuery());

		Assert.NotNull(response);
		Assert.Equal(new[] { RecordType.Soa, RecordType.A, RecordType.A, RecordType.A, RecordType.Soa }, response!.AnswerRecords.Select(r => r.RecordType));
		Assert.InRange(stopwatch.Elapsed, TimeSpan.Zero, TimeSpan.FromMilliseconds(900));

		Assert.Null(await slow);
	}

	[Fact]
	public async Task QueryTimeout_DoesNotAbortOtherQueriesOnTheSameConnection()
	{
		var transport = new ControlledTransport();
		using var client = new DnsClient(new[] { IPAddress.Loopback }, new IClientTransport[] { transport }, true, 1000);

		// the slow query opens the pooled connection and is never answered
		var slow = client.ResolveAsync(DomainName.Parse("slow.example.test"));
		Assert.True(await transport.Connection.WaitForQueryAsync("slow", TimeSpan.FromSeconds(5)), "The slow query was not sent");

		// the fast query uses the same connection, it is answered only after the slow query timed out
		await Task.Delay(500);
		var fast = client.ResolveAsync(DomainName.Parse("fast.example.test"));
		Assert.True(await transport.Connection.WaitForQueryAsync("fast", TimeSpan.FromSeconds(5)), "The fast query was not sent");

		Assert.True(await Task.WhenAny(slow, Task.Delay(TimeSpan.FromSeconds(5))) == slow, "The slow query did not time out");
		Assert.Null(await slow);

		transport.Connection.Answer("fast");

		Assert.True(await Task.WhenAny(fast, Task.Delay(TimeSpan.FromSeconds(5))) == fast, "The fast query was not answered");
		var fastResponse = await fast;
		Assert.NotNull(fastResponse);
		Assert.Single(fastResponse!.AnswerRecords);
		Assert.Equal(1, transport.ConnectCount);
		Assert.False(transport.Connection.IsFaulty);
	}

	private static DnsMessage Answer(DnsMessage query)
	{
		var response = query.CreateResponseInstance();
		response.AnswerRecords.Add(new ARecord(query.Questions[0].Name, 60, IPAddress.Parse("192.0.2.1")));
		return response;
	}

	private static DnsMessage ZoneTransferQuery()
	{
		var query = new DnsMessage();
		query.Questions.Add(new DnsQuestion(_zone, RecordType.Axfr, RecordClass.INet));
		return query;
	}

	private static DnsMessage ZoneTransferMessage(DnsMessage query, params DnsRecordBase[] records)
	{
		var response = query.CreateResponseInstance();
		response.AnswerRecords.AddRange(records);
		return response;
	}

	private static SoaRecord Soa() => new(_zone, 60, DomainName.Parse("ns.example.test"), DomainName.Parse("hostmaster.example.test"), 1, 3600, 600, 86400, 60);

	private static ARecord A(string label) => new(DomainName.Parse(label + ".example.test"), 60, IPAddress.Parse("192.0.2.1"));

	/// <summary>
	///   A pipelined transport with one simulated connection
	/// </summary>
	private sealed class SimulatedTransport : PipelinedClientTransportBase
	{
		private int _connectCount;

		public SimulatedTransport(Func<DnsMessage, IReadOnlyList<DnsMessage>> respond)
			: base(53)
		{
			Connection = new SimulatedConnection(this, respond);
		}

		public SimulatedConnection Connection { get; }

		public int ConnectCount => Volatile.Read(ref _connectCount);

		public override ushort MaximumAllowedQuerySize => UInt16.MaxValue;

		protected override Task<IPipelineableClientConnection?> ConnectInternalAsync(DnsClientEndpointInfo endpointInfo, int queryTimeout, CancellationToken token)
		{
			Interlocked.Increment(ref _connectCount);
			return Task.FromResult<IPipelineableClientConnection?>(Connection);
		}
	}

	/// <summary>
	///   A pipelined transport with one connection, whose responses are sent by the test
	/// </summary>
	private sealed class ControlledTransport : PipelinedClientTransportBase
	{
		private int _connectCount;

		public ControlledTransport()
			: base(53)
		{
			Connection = new ControlledConnection(this);
		}

		public ControlledConnection Connection { get; }

		public int ConnectCount => Volatile.Read(ref _connectCount);

		public override ushort MaximumAllowedQuerySize => UInt16.MaxValue;

		protected override Task<IPipelineableClientConnection?> ConnectInternalAsync(DnsClientEndpointInfo endpointInfo, int queryTimeout, CancellationToken token)
		{
			Interlocked.Increment(ref _connectCount);
			return Task.FromResult<IPipelineableClientConnection?>(Connection);
		}
	}

	/// <summary>
	///   Records the sent queries by the first label of their name and answers them, when the test says so
	/// </summary>
	private sealed class ControlledConnection : IPipelineableClientConnection
	{
		private readonly Channel<DnsReceivedRawPackage> _responses = Channel.CreateUnbounded<DnsReceivedRawPackage>();
		private readonly ConcurrentDictionary<string, TaskCompletionSource<DnsMessage>> _queries = new();

		public ControlledConnection(IClientTransport transport)
		{
			Transport = transport;
		}

		public IClientTransport Transport { get; }

		public bool IsAlive => !IsFaulty;

		public bool IsFaulty { get; private set; }

		private TaskCompletionSource<DnsMessage> GetQuery(string label)
			=> _queries.GetOrAdd(label, _ => new TaskCompletionSource<DnsMessage>(TaskCreationOptions.RunContinuationsAsynchronously));

		public async Task<bool> WaitForQueryAsync(string label, TimeSpan timeout)
		{
			var query = GetQuery(label).Task;
			return await Task.WhenAny(query, Task.Delay(timeout)) == query;
		}

		public void Answer(string label)
		{
			var response = PipelinedConnectionTests.Answer(GetQuery(label).Task.Result);
			_responses.Writer.TryWrite(new DnsReceivedRawPackage(response.Encode().ToArraySegment(true).ToArray(), new IPEndPoint(IPAddress.Loopback, 53), new IPEndPoint(IPAddress.Loopback, 50000)));
		}

		public Task<bool> SendAsync(DnsRawPackage package, CancellationToken token = default)
		{
			var query = DnsMessage.Parse(package.ToArraySegment(false));
			GetQuery(query.Questions[0].Name.Labels[0]).TrySetResult(query);
			return Task.FromResult(true);
		}

		public async Task<DnsReceivedRawPackage?> ReceiveAsync(CancellationToken token = default)
		{
			try
			{
				return await _responses.Reader.ReadAsync(token);
			}
			catch (ChannelClosedException)
			{
				return null;
			}
		}

		public Task<DnsReceivedRawPackage?> ReceiveAsync(DnsMessageIdentification identification, CancellationToken token = default)
			=> throw new NotSupportedException("The pooled connection uses the receive loop");

		public void RestartIdleTimeout(TimeSpan? timeout) { }

		public void MarkFaulty() => IsFaulty = true;

		public void Dispose() => MarkFaulty();
	}

	/// <summary>
	///   Answers the queries with the given messages. The responses are delivered while sending, and sending completes only after
	///   the receive loop read all of them, so the responses are always read before the client waits for them.
	/// </summary>
	private sealed class SimulatedConnection : IPipelineableClientConnection
	{
		private readonly Func<DnsMessage, IReadOnlyList<DnsMessage>> _respond;
		private readonly ConcurrentQueue<(DnsReceivedRawPackage Package, TaskCompletionSource<bool> Read)> _responses = new();
		private readonly SemaphoreSlim _available = new(0);
		private readonly TaskCompletionSource<bool> _receiveLoopWaiting = new(TaskCreationOptions.RunContinuationsAsynchronously);

		public SimulatedConnection(IClientTransport transport, Func<DnsMessage, IReadOnlyList<DnsMessage>> respond)
		{
			Transport = transport;
			_respond = respond;
		}

		public IClientTransport Transport { get; }

		public bool IsAlive => !IsFaulty;

		public bool IsFaulty { get; private set; }

		public async Task<bool> WaitForWaitingReceiveLoopAsync(TimeSpan timeout)
		{
			return await Task.WhenAny(_receiveLoopWaiting.Task, Task.Delay(timeout)) == _receiveLoopWaiting.Task;
		}

		public async Task<bool> SendAsync(DnsRawPackage package, CancellationToken token = default)
		{
			var query = DnsMessage.Parse(package.ToArraySegment(false));
			var reads = new List<Task>();

			foreach (var response in _respond(query))
			{
				var responsePackage = new DnsReceivedRawPackage(response.Encode().ToArraySegment(true).ToArray(), new IPEndPoint(IPAddress.Loopback, 53), new IPEndPoint(IPAddress.Loopback, 50000));
				var read = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
				reads.Add(read.Task);
				_responses.Enqueue((responsePackage, read));
				_available.Release();
			}

			// sending completes only after the receive loop read all responses
			await Task.WhenAny(Task.WhenAll(reads), Task.Delay(TimeSpan.FromSeconds(5)));
			return true;
		}

		public async Task<DnsReceivedRawPackage?> ReceiveAsync(CancellationToken token = default)
		{
			_receiveLoopWaiting.TrySetResult(true);

			try
			{
				await _available.WaitAsync(token);
			}
			catch (OperationCanceledException)
			{
				return null;
			}

			_responses.TryDequeue(out var response);
			response.Read.TrySetResult(true);
			return response.Package;
		}

		public Task<DnsReceivedRawPackage?> ReceiveAsync(DnsMessageIdentification identification, CancellationToken token = default)
			=> throw new NotSupportedException("The pooled connection uses the receive loop");

		public void RestartIdleTimeout(TimeSpan? timeout) { }

		public void MarkFaulty() => IsFaulty = true;

		public void Dispose() => MarkFaulty();
	}
}
