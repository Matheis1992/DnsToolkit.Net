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
using System.Net.Security;
using DnsToolkit.Net.Dns;
using DnsToolkit.Net.Spf;

namespace DnsToolkit.Net.Tests;

/// <summary>
///   The library does not continue on the synchronization context of its caller. Otherwise a caller, which waits
///   synchronously on a thread with a synchronization context, like a UI thread, deadlocks: the continuations are posted
///   to the context of the waiting thread, which never runs them.
/// </summary>
public class SynchronizationContextTests
{
	private static readonly RemoteCertificateValidationCallback _acceptAnyCertificate = (_, _, _, _) => true;
	private static readonly DomainName _zone = DomainName.Parse("example.test");
	private static readonly DomainName _host = DomainName.Parse("host.example.test");

	private static readonly DnsRecordBase[] _records =
	{
		new ARecord(_host, 3600, IPAddress.Parse("192.0.2.1")),
		new TxtRecord(_zone, 3600, "v=spf1 ip4:192.0.2.0/24 -all"),
	};

	public static TheoryData<string> Transports => new() { "udp", "tcp", "tls" };

	[Theory]
	[MemberData(nameof(Transports))]
	public async Task DnsClient_ResolveAsync(string transport)
	{
		using var server = new LocalDnsServer(_records);
		using var client = server.CreateClient(transport switch
		{
			"udp" => new UdpClientTransport(server.Port),
			"tcp" => new TcpClientTransport(server.Port),
			_ => new TlsClientTransport("localhost", remoteCertificateValidationCallback: _acceptAnyCertificate, port: server.TlsPort),
		});

		var response = await RunOnBlockedContextAsync(() => client.ResolveAsync(_host));

		Assert.Single(response!.AnswerRecords);
	}

	[Fact]
	public async Task DnsStubResolver_ResolveAsync()
	{
		using var server = new LocalDnsServer(_records);
		using IDnsResolver resolver = new DnsStubResolver(server.CreateClient(new UdpClientTransport(server.Port)));

		var addresses = await RunOnBlockedContextAsync(() => resolver.ResolveHostAsync(_host));

		Assert.Equal(IPAddress.Parse("192.0.2.1"), Assert.Single(addresses));
	}

	[Fact]
	public async Task SpfValidator_CheckHostAsync()
	{
		using var server = new LocalDnsServer(_records);
		var validator = new SpfValidator { DnsResolver = new DnsStubResolver(server.CreateClient(new UdpClientTransport(server.Port))) };

		var result = await RunOnBlockedContextAsync(() => validator.CheckHostAsync(IPAddress.Parse("192.0.2.1"), _zone, "user@example.test"));

		Assert.Equal(SpfQualifier.Pass, result.Result);
	}

	[Fact]
	public async Task DnsSecValidator_ValidateAsync()
	{
		var key = DnsKeyRecord.CreateSigningKey(_zone, RecordClass.INet, 3600, DnsKeyFlags.Zone, 3, DnsSecAlgorithm.Ed25519);
		var record = new ARecord(_host, 3600, IPAddress.Parse("192.0.2.1"));
		var message = new DnsMessage();
		message.AnswerRecords.Add(record);
		message.AnswerRecords.Add(new RrSigRecord(new List<DnsRecordBase> { record }, key, DateTime.Now.AddDays(-1), DateTime.Now.AddDays(1)));

		var validator = new DnsSecValidator<object?>(new AsyncKeyResolver(key), new EmptyHintStore());

		var result = await RunOnBlockedContextAsync(() => validator.ValidateAsync(_host, RecordType.A, RecordClass.INet, message, new List<ARecord> { record }, null, default));

		Assert.Equal(DnsSecValidationResult.Signed, result);
	}

	[Fact]
	public async Task DnsServer_StopAsync()
	{
		var server = new DnsServer(new UdpServerTransport(new IPEndPoint(IPAddress.Loopback, 0)));
		server.Start();

		await RunOnBlockedContextAsync(() => server.StopAsync());

		((IDisposable) server).Dispose();
	}

	/// <summary>
	///   Starts the operation on a thread with a synchronization context, which never runs the continuations posted to it,
	///   like the one of a UI thread, which waits for the operation
	/// </summary>
	private static async Task<T> RunOnBlockedContextAsync<T>(Func<Task<T>> operation)
	{
		Task<T>? task = null;
		Func<Task> start = () => task = operation();
		await RunOnBlockedContextAsync(start);
		return await task!;
	}

	private static async Task RunOnBlockedContextAsync(Func<Task> operation)
	{
		var context = new BlockedSynchronizationContext();
		var previous = SynchronizationContext.Current;

		Task task;
		SynchronizationContext.SetSynchronizationContext(context);
		try
		{
			task = operation();
		}
		finally
		{
			SynchronizationContext.SetSynchronizationContext(previous);
		}

		var completed = await Task.WhenAny(task, Task.Delay(TimeSpan.FromSeconds(10))) == task;

		Assert.True(completed && (context.PostCount == 0), $"{context.PostCount} continuations were posted to the synchronization context of the caller");
		await task;
	}

	private sealed class BlockedSynchronizationContext : SynchronizationContext
	{
		private int _postCount;

		public int PostCount => Volatile.Read(ref _postCount);

		public override void Post(SendOrPostCallback d, object? state) => Interlocked.Increment(ref _postCount);

		public override void Send(SendOrPostCallback d, object? state) => throw new NotSupportedException("The thread is blocked");
	}

	/// <summary>
	///   Returns the key of the zone after a real asynchronous wait, which does not capture the synchronization context itself
	/// </summary>
	private sealed class AsyncKeyResolver : IInternalDnsSecResolver<object?>
	{
		private readonly DnsKeyRecord _key;

		public AsyncKeyResolver(DnsKeyRecord key)
		{
			_key = key;
		}

		public Task<DnsMessage?> ResolveMessageAsync(DomainName name, RecordType recordType, RecordClass recordClass, object? state, CancellationToken token)
			=> throw new NotSupportedException();

		public async Task<DnsSecResult<TRecord>> ResolveSecureAsync<TRecord>(DomainName name, RecordType recordType, RecordClass recordClass, object? state, CancellationToken token)
			where TRecord : DnsRecordBase
		{
			await Task.Delay(1, token).ConfigureAwait(false);
			return new DnsSecResult<TRecord>(new List<TRecord> { (TRecord) (DnsRecordBase) _key }, DnsSecValidationResult.Signed);
		}
	}

	private sealed class EmptyHintStore : IResolverHintStore
	{
		public IReadOnlyList<IPAddress> RootServers { get; } = Array.Empty<IPAddress>();

		public IReadOnlyList<DsRecord> RootKeys { get; } = Array.Empty<DsRecord>();
	}
}
