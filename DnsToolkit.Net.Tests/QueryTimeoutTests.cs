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

using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

/// <summary>
///   Tests the query timeout of the client with simulated connections, which answer exactly as scripted
/// </summary>
public class QueryTimeoutTests
{
	private const int _QUERY_TIMEOUT = 600;

	private static readonly DomainName _name = DomainName.Parse("host.example.test");
	private static readonly DomainName _zone = DomainName.Parse("example.test");

	[Fact]
	public async Task UnansweredQuery_ReturnsNull_AfterQueryTimeout()
	{
		var transport = new ScriptedTransport(_ => Array.Empty<(TimeSpan, DnsMessage)>());
		using var client = new DnsClient(new[] { IPAddress.Loopback }, new IClientTransport[] { transport }, true, _QUERY_TIMEOUT);

		// no cancellation token, only the query timeout of the client
		var stopwatch = Stopwatch.StartNew();
		var resolve = client.ResolveAsync(_name);

		Assert.True(await Task.WhenAny(resolve, Task.Delay(TimeSpan.FromSeconds(10))) == resolve, "The query did not complete, although it timed out");
		Assert.Null(await resolve);
		Assert.InRange(stopwatch.Elapsed, TimeSpan.FromMilliseconds(_QUERY_TIMEOUT - 100), TimeSpan.FromSeconds(5));
		Assert.True(transport.Connection!.IsReceiveCanceled, "The receive was not canceled");
	}

	[Fact]
	public async Task TimeoutOfZero_MeansNoTimeout()
	{
		// like the timeouts of sockets and of the client, before the connects of TCP and UDP timed out immediately
		var completion = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
		var waiting = completion.Task.WithTimeout(0);

		await Task.Delay(100);
		Assert.False(waiting.IsCompleted, "The wait timed out immediately");

		completion.SetResult(1);
		Assert.Equal(1, await waiting);
	}

	[Fact]
	public async Task QueryTimeout_DoesNotMarkConnectionFaulty()
	{
		// a pooled connection is shared by all queries to a server, so the timeout of one query must not close it
		var transport = new ScriptedTransport(_ => Array.Empty<(TimeSpan, DnsMessage)>());
		using var client = new DnsClient(new[] { IPAddress.Loopback }, new IClientTransport[] { transport }, true, _QUERY_TIMEOUT);

		Assert.Null(await client.ResolveAsync(_name));

		Assert.True(transport.Connection!.IsReceiveCanceled, "The receive was not canceled");
		Assert.False(transport.Connection.IsFaulty, "The connection was marked faulty because of the timeout of one query");
	}

	[Fact]
	public async Task CallerCancellation_DoesNotMarkConnectionFaulty()
	{
		var transport = new ScriptedTransport(_ => Array.Empty<(TimeSpan, DnsMessage)>());
		using var client = new DnsClient(new[] { IPAddress.Loopback }, new IClientTransport[] { transport }, true, 30000);
		using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));

		var stopwatch = Stopwatch.StartNew();
		DnsMessage? response = null;
		try
		{
			response = await client.ResolveAsync(_name, token: cts.Token);
		}
		catch (OperationCanceledException)
		{
			// expected as well
		}

		Assert.Null(response);
		Assert.InRange(stopwatch.Elapsed, TimeSpan.Zero, TimeSpan.FromSeconds(5));
		Assert.True(transport.Connection!.IsReceiveCanceled, "The receive was not canceled");
		Assert.False(transport.Connection.IsFaulty, "The connection was marked faulty because the caller canceled one query");
	}

	[Fact]
	public async Task MultiMessageResponse_RestartsTimeoutForEveryMessage()
	{
		// every message arrives within the timeout, but the whole zone transfer takes longer than the timeout
		var interval = TimeSpan.FromMilliseconds(_QUERY_TIMEOUT * 0.6);
		var transport = new ScriptedTransport(query => new[]
		{
			(interval, ZoneTransferMessage(query, Soa(), A("a"))),
			(interval, ZoneTransferMessage(query, A("b"))),
			(interval, ZoneTransferMessage(query, A("c"), Soa()))
		});
		using var client = new DnsClient(new[] { IPAddress.Loopback }, new IClientTransport[] { transport }, true, _QUERY_TIMEOUT);

		var stopwatch = Stopwatch.StartNew();
		var response = await client.SendMessageAsync(ZoneTransferQuery());

		Assert.NotNull(response);
		Assert.True(stopwatch.Elapsed > TimeSpan.FromMilliseconds(_QUERY_TIMEOUT), "The zone transfer was faster than the timeout, so the test does not check the restart");
		Assert.Equal(new[] { RecordType.Soa, RecordType.A, RecordType.A, RecordType.A, RecordType.Soa }, response!.AnswerRecords.Select(r => r.RecordType));
	}

	[Fact]
	public async Task MultiMessageResponse_TimesOut_WhenNextMessageIsMissing()
	{
		// the zone transfer starts, but its last message never arrives
		var transport = new ScriptedTransport(query => new[] { (TimeSpan.Zero, ZoneTransferMessage(query, Soa(), A("a"))) });
		using var client = new DnsClient(new[] { IPAddress.Loopback }, new IClientTransport[] { transport }, true, _QUERY_TIMEOUT);

		var send = client.SendMessageAsync(ZoneTransferQuery());

		Assert.True(await Task.WhenAny(send, Task.Delay(TimeSpan.FromSeconds(10))) == send, "The zone transfer did not complete, although its next message timed out");
		Assert.Null(await send);
	}

	[Fact]
	public async Task CallerCancellation_WhileWaitingForTheWriteOfAnotherQuery_DoesNotMarkConnectionFaulty()
	{
		// The queries share the pooled TCP connection. The write of the first one blocks like on a full send buffer, until
		// the second query was canceled, while it waited for its turn to write.
		using var server = new LocalDnsServer(new[] { new ARecord(_name, 60, IPAddress.Parse("192.0.2.1")) });
		var transport = new GatedWriteTransport(server.Port);
		using var client = new DnsClient(new[] { IPAddress.Loopback }, new IClientTransport[] { transport }, true, 10000);

		var first = client.ResolveAsync(_name);
		await transport.FirstWriteStarted;

		using (var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200)))
		{
			try
			{
				Assert.Null(await client.ResolveAsync(_name, token: cts.Token));
			}
			catch (OperationCanceledException)
			{
				// expected as well
			}
		}

		transport.ReleaseWrites();
		Assert.NotNull(await first);

		// before, the canceled query marked the shared connection faulty, so the next query opened a new one
		Assert.NotNull(await client.ResolveAsync(_name));
		Assert.Equal(2, transport.Streams[0].WriteCount);
	}

	[Fact]
	public async Task HangingStreamSetup_IsLimitedByQueryTimeout_AndClosesTheConnection()
	{
		// Stands in for a TLS server which accepts the connection, but never answers the handshake.
		// The stream setup is shared by all queries to the server, so the transport itself has to limit it.
		var listener = new TcpListener(IPAddress.Loopback, 0);
		listener.Start();
		try
		{
			var transport = new HangingSetupTransport(((IPEndPoint) listener.LocalEndpoint).Port);
			using var client = new DnsClient(new[] { IPAddress.Loopback }, new IClientTransport[] { transport }, true, _QUERY_TIMEOUT);

			var stopwatch = Stopwatch.StartNew();
			var resolve = client.ResolveAsync(_name);
			using var accepted = await listener.AcceptTcpClientAsync();

			Assert.True(await Task.WhenAny(resolve, Task.Delay(TimeSpan.FromSeconds(10))) == resolve, "The query did not complete, although the stream setup timed out");
			Assert.Null(await resolve);
			Assert.InRange(stopwatch.Elapsed, TimeSpan.FromMilliseconds(_QUERY_TIMEOUT - 100), TimeSpan.FromSeconds(5));
			Assert.True(transport.IsSetupCanceled, "The stream setup was not canceled");

			// the connection with the failed setup is closed instead of being left to the garbage collector
			Assert.True(await TransportTests.WaitForRemoteCloseAsync(accepted, TimeSpan.FromSeconds(5)), "The connection was not closed after the stream setup timed out");
		}
		finally
		{
			listener.Stop();
		}
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
	///   A transport with one connection, which answers every query with the scripted messages
	/// </summary>
	private sealed class ScriptedTransport : IClientTransport
	{
		private readonly Func<DnsMessage, IEnumerable<(TimeSpan Delay, DnsMessage Message)>> _script;

		public ScriptedTransport(Func<DnsMessage, IEnumerable<(TimeSpan Delay, DnsMessage Message)>> script)
		{
			_script = script;
		}

		public ScriptedConnection? Connection { get; private set; }

		public ushort MaximumAllowedQuerySize => UInt16.MaxValue;
		public bool SupportsReliableTransfer => true;
		public bool SupportsMulticastTransfer => false;
		public bool SupportsPooledConnections => false;

		public Task<IClientConnection?> ConnectAsync(DnsClientEndpointInfo endpointInfo, int queryTimeout, CancellationToken token = default)
		{
			Connection = new ScriptedConnection(this, _script);
			return Task.FromResult<IClientConnection?>(Connection);
		}

		public Task<IClientConnection?> GetPooledConnectionAsync(DnsClientEndpointInfo endpointInfo, CancellationToken token = default)
			=> Task.FromResult<IClientConnection?>(null);

		public void Dispose() { }
	}

	/// <summary>
	///   Delivers the scripted messages, each after its delay. Without further messages it waits until the receive
	///   is canceled and throws then, like a pooled connection.
	/// </summary>
	private sealed class ScriptedConnection : IClientConnection
	{
		private readonly Func<DnsMessage, IEnumerable<(TimeSpan Delay, DnsMessage Message)>> _script;
		private readonly Queue<(TimeSpan Delay, DnsMessage Message)> _messages = new();

		public ScriptedConnection(IClientTransport transport, Func<DnsMessage, IEnumerable<(TimeSpan Delay, DnsMessage Message)>> script)
		{
			Transport = transport;
			_script = script;
		}

		public IClientTransport Transport { get; }

		public bool IsFaulty { get; private set; }

		public bool IsReceiveCanceled { get; private set; }

		public Task<bool> SendAsync(DnsRawPackage package, CancellationToken token = default)
		{
			foreach (var message in _script(DnsMessage.Parse(package.ToArraySegment(false))))
				_messages.Enqueue(message);

			return Task.FromResult(true);
		}

		public async Task<DnsReceivedRawPackage?> ReceiveAsync(DnsMessageIdentification identification, CancellationToken token = default)
		{
			try
			{
				if (_messages.Count == 0)
					await Task.Delay(Timeout.Infinite, token);

				var (delay, message) = _messages.Dequeue();
				await Task.Delay(delay, token);
				return new DnsReceivedRawPackage(message.Encode().ToArraySegment(true).ToArray(), new IPEndPoint(IPAddress.Loopback, 53), new IPEndPoint(IPAddress.Loopback, 50000));
			}
			catch (OperationCanceledException)
			{
				IsReceiveCanceled = true;
				throw;
			}
		}

		public void RestartIdleTimeout(TimeSpan? timeout) { }

		public void MarkFaulty() => IsFaulty = true;

		public void Dispose() { }
	}

	/// <summary>
	///   A TCP transport, whose writes wait until they are released
	/// </summary>
	private sealed class GatedWriteTransport : TcpClientTransportBase<GatedWriteTransport>
	{
		private readonly TaskCompletionSource<bool> _firstWriteStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
		private readonly TaskCompletionSource<bool> _writesReleased = new(TaskCreationOptions.RunContinuationsAsynchronously);
		private readonly List<GatedWriteStream> _streams = new();

		public GatedWriteTransport(int port)
			: base(port) { }

		public Task FirstWriteStarted => _firstWriteStarted.Task;

		public IReadOnlyList<GatedWriteStream> Streams
		{
			get
			{
				lock (_streams)
					return _streams.ToList();
			}
		}

		public void ReleaseWrites() => _writesReleased.TrySetResult(true);

		protected override Task<Stream?> GetStreamAsync(TcpClient client, CancellationToken token)
		{
			var stream = new GatedWriteStream(client.GetStream(), this);

			lock (_streams)
				_streams.Add(stream);

			return Task.FromResult<Stream?>(stream);
		}

		public sealed class GatedWriteStream : Stream
		{
			private readonly Stream _inner;
			private readonly GatedWriteTransport _transport;
			private int _writeCount;

			public GatedWriteStream(Stream inner, GatedWriteTransport transport)
			{
				_inner = inner;
				_transport = transport;
			}

			public int WriteCount => Volatile.Read(ref _writeCount);

			public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
			{
				Interlocked.Increment(ref _writeCount);
				_transport._firstWriteStarted.TrySetResult(true);

				// like a socket with a full send buffer, it ignores the cancellation token
				await _transport._writesReleased.Task;
				await _inner.WriteAsync(buffer, offset, count, cancellationToken);
			}

			public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => _inner.ReadAsync(buffer, offset, count, cancellationToken);
			public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
			public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer, offset, count, default).GetAwaiter().GetResult();
			public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);
			public override void Flush() => _inner.Flush();

			protected override void Dispose(bool disposing)
			{
				if (disposing)
					_inner.Dispose();
				base.Dispose(disposing);
			}

			public override bool CanRead => true;
			public override bool CanSeek => false;
			public override bool CanWrite => true;
			public override long Length => throw new NotSupportedException();
			public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
			public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
			public override void SetLength(long value) => throw new NotSupportedException();
		}
	}

	/// <summary>
	///   A TCP transport whose stream setup never completes, until it is canceled
	/// </summary>
	private sealed class HangingSetupTransport : TcpClientTransportBase<HangingSetupTransport>
	{
		public HangingSetupTransport(int port)
			: base(port) { }

		public bool IsSetupCanceled { get; private set; }

		protected override async Task<Stream?> GetStreamAsync(TcpClient client, CancellationToken token)
		{
			try
			{
				await Task.Delay(Timeout.Infinite, token);
				return null;
			}
			catch (OperationCanceledException)
			{
				IsSetupCanceled = true;
				throw;
			}
		}
	}
}
