using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

/// <summary>
///   Tests the pooled connections of TCP and TLS with a simulated connection, so the order of sending and receiving is controlled exactly
/// </summary>
public class PipelinedConnectionTests
{
	[Fact]
	public async Task ResponseReadBeforeTheClientWaitsForIt_IsDelivered()
	{
		var transport = new SimulatedTransport(answer: query => query.Questions[0].Name.Labels[0] == "fast");
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

	/// <summary>
	///   A pipelined transport with one simulated connection
	/// </summary>
	private sealed class SimulatedTransport : PipelinedClientTransportBase
	{
		private int _connectCount;

		public SimulatedTransport(Func<DnsMessage, bool> answer)
			: base(53)
		{
			Connection = new SimulatedConnection(this, answer);
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
	///   Answers the selected queries. The response is delivered while sending, and sending completes only after
	///   the receive loop read the response, so the response is always read before the client waits for it.
	/// </summary>
	private sealed class SimulatedConnection : IPipelineableClientConnection
	{
		private readonly Func<DnsMessage, bool> _answer;
		private readonly ConcurrentQueue<(DnsReceivedRawPackage Package, TaskCompletionSource<bool> Read)> _responses = new();
		private readonly SemaphoreSlim _available = new(0);
		private readonly TaskCompletionSource<bool> _receiveLoopWaiting = new(TaskCreationOptions.RunContinuationsAsynchronously);

		public SimulatedConnection(IClientTransport transport, Func<DnsMessage, bool> answer)
		{
			Transport = transport;
			_answer = answer;
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
			if (!_answer(query))
				return true;

			var response = query.CreateResponseInstance();
			response.AnswerRecords.Add(new ARecord(query.Questions[0].Name, 60, IPAddress.Parse("192.0.2.1")));
			var responsePackage = new DnsReceivedRawPackage(response.Encode().ToArraySegment(true).ToArray(), new IPEndPoint(IPAddress.Loopback, 53), new IPEndPoint(IPAddress.Loopback, 50000));

			var read = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
			_responses.Enqueue((responsePackage, read));
			_available.Release();

			// sending completes only after the receive loop read the response
			await Task.WhenAny(read.Task, Task.Delay(TimeSpan.FromSeconds(5)));
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
