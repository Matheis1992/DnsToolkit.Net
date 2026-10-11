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

public class ConnectionPoolTests
{
	private static readonly IPAddress _server = IPAddress.Parse("192.0.2.53");
	private static readonly IPAddress _otherServer = IPAddress.Parse("192.0.2.54");

	[Fact]
	public async Task ConcurrentQueries_ShareOneConnect()
	{
		var pool = new ConnectionPool<FakeConnection>();
		var pending = NewConnect();
		var connectCalls = 0;
		Func<Task<FakeConnection?>> connect = () =>
		{
			Interlocked.Increment(ref connectCalls);
			return pending.Task;
		};

		var first = pool.GetOrConnectAsync(_server, connect, default);
		var second = pool.GetOrConnectAsync(_server, connect, default);
		var connection = new FakeConnection();
		pending.SetResult(connection);

		Assert.Same(connection, await first);
		Assert.Same(connection, await second);
		Assert.Equal(1, connectCalls);
	}

	[Fact]
	public async Task GetOrConnect_ReplacesAPooledConnection_WhichWasClosedMeanwhile()
	{
		// e.g. closed by its idle timeout or draining after a keepalive of 0
		var pool = new ConnectionPool<FakeConnection>();
		var closed = new FakeConnection();
		Assert.Same(closed, await pool.GetOrConnectAsync(_server, () => Task.FromResult<FakeConnection?>(closed), default));
		closed.IsAlive = false;

		// before, the closed connection was returned, so the query failed instead of connecting again
		var fresh = new FakeConnection();
		Assert.Same(fresh, await pool.GetOrConnectAsync(_server, () => Task.FromResult<FakeConnection?>(fresh), default));
		Assert.Same(fresh, await pool.GetPooledAsync(_server, default));
	}

	[Fact]
	public async Task GetOrConnect_ReturnsNull_WhenTheOwnNewConnectionIsClosedAlready()
	{
		// e.g. a server, which closes every connection at once, is not connected again and again
		var pool = new ConnectionPool<FakeConnection>();
		var connectCalls = 0;

		var connection = await pool.GetOrConnectAsync(_server, () =>
		{
			Interlocked.Increment(ref connectCalls);
			return Task.FromResult<FakeConnection?>(new FakeConnection { IsAlive = false });
		}, default);

		Assert.Null(connection);
		Assert.Equal(1, connectCalls);
		Assert.Equal(0, pool.Count);
	}

	[Fact]
	public async Task Remove_DoesNotWaitForAPendingConnect()
	{
		var pool = new ConnectionPool<FakeConnection>();
		var pending = NewConnect();
		var connecting = pool.GetOrConnectAsync(_server, () => pending.Task, default);

		try
		{
			// reading the result of the pending connect inside the lock would block until it is established
			var remove = Task.Run(() => pool.Remove(_server, new FakeConnection()));

			await CompletesWithinAsync(remove, TimeSpan.FromSeconds(2));
			Assert.Equal(1, pool.Count);
		}
		finally
		{
			pending.SetResult(null);
			await connecting;
		}
	}

	[Fact]
	public async Task GetPooled_WaitsForAPendingConnect_WithoutBlockingThePool()
	{
		var pool = new ConnectionPool<FakeConnection>();
		var pending = NewConnect();
		var connecting = pool.GetOrConnectAsync(_server, () => pending.Task, default);
		var connection = new FakeConnection();

		try
		{
			// on another thread, so the test fails instead of hanging, if it blocks
			var pooled = Task.Run(() => pool.GetPooledAsync(_server, default));
			await Task.Delay(100);

			// the pool can be used for other servers meanwhile
			var other = new FakeConnection();
			await CompletesWithinAsync(Task.Run(() => pool.GetOrConnectAsync(_otherServer, () => Task.FromResult<FakeConnection?>(other), default)), TimeSpan.FromSeconds(2));
			Assert.False(pooled.IsCompleted);

			pending.SetResult(connection);

			Assert.Same(connection, await pooled);
			Assert.Same(connection, await connecting);
		}
		finally
		{
			pending.TrySetResult(connection);
		}
	}

	[Fact]
	public async Task GetPooled_ReturnsNull_WhenThePoolHasNoConnectionToTheServer()
	{
		var pool = new ConnectionPool<FakeConnection>();

		Assert.Null(await pool.GetPooledAsync(_server, default));
	}

	[Fact]
	public async Task GetPooled_RemovesAnUnusableConnection_WithoutClosingIt()
	{
		var pool = new ConnectionPool<FakeConnection>();
		var connection = new FakeConnection();
		await pool.GetOrConnectAsync(_server, () => Task.FromResult<FakeConnection?>(connection), default);

		// e.g. the server asked to close it, but the responses to the queries in progress are still received
		connection.IsAlive = false;

		Assert.Null(await pool.GetPooledAsync(_server, default));
		Assert.Equal(0, connection.MarkFaultyCalls);
		Assert.Equal(0, pool.Count);
	}

	[Fact]
	public async Task FailedConnect_IsNotKept_SoTheNextQueryConnectsAgain()
	{
		var pool = new ConnectionPool<FakeConnection>();
		var connectCalls = 0;

		Assert.Null(await pool.GetOrConnectAsync(_server, () =>
		{
			Interlocked.Increment(ref connectCalls);
			return Task.FromResult<FakeConnection?>(null);
		}, default));
		Assert.Equal(0, pool.Count);

		await Assert.ThrowsAsync<IOException>(() => pool.GetOrConnectAsync(_server, () =>
		{
			Interlocked.Increment(ref connectCalls);
			return Task.FromException<FakeConnection?>(new IOException());
		}, default));
		Assert.Equal(0, pool.Count);

		var connection = new FakeConnection();
		Assert.Same(connection, await pool.GetOrConnectAsync(_server, () =>
		{
			Interlocked.Increment(ref connectCalls);
			return Task.FromResult<FakeConnection?>(connection);
		}, default));
		Assert.Equal(3, connectCalls);
	}

	[Fact]
	public async Task Remove_KeepsANewerConnectionToTheServer()
	{
		var pool = new ConnectionPool<FakeConnection>();
		var old = new FakeConnection();
		await pool.GetOrConnectAsync(_server, () => Task.FromResult<FakeConnection?>(old), default);
		pool.Remove(_server, old);

		var current = new FakeConnection();
		await pool.GetOrConnectAsync(_server, () => Task.FromResult<FakeConnection?>(current), default);

		// e.g. the old connection reports late, that it was closed
		pool.Remove(_server, old);

		Assert.Same(current, await pool.GetPooledAsync(_server, default));
	}

	[Fact]
	public async Task CallerCancellation_DoesNotCancelTheSharedConnect()
	{
		var pool = new ConnectionPool<FakeConnection>();
		var pending = NewConnect();
		var connectCalls = 0;
		Func<Task<FakeConnection?>> connect = () =>
		{
			Interlocked.Increment(ref connectCalls);
			return pending.Task;
		};

		using var cts = new CancellationTokenSource();
		var canceled = pool.GetOrConnectAsync(_server, connect, cts.Token);
		var waiting = pool.GetOrConnectAsync(_server, connect, default);
		cts.Cancel();

		await Assert.ThrowsAnyAsync<OperationCanceledException>(() => canceled);

		var connection = new FakeConnection();
		pending.SetResult(connection);

		Assert.Same(connection, await waiting);
		Assert.Same(connection, await pool.GetPooledAsync(_server, default));
		Assert.Equal(1, connectCalls);
	}

	[Fact]
	public async Task Clear_ClosesAllConnections_PendingOnesOnceTheyAreEstablished()
	{
		var pool = new ConnectionPool<FakeConnection>();
		var established = new FakeConnection();
		await pool.GetOrConnectAsync(_server, () => Task.FromResult<FakeConnection?>(established), default);
		var pending = NewConnect();
		var connecting = pool.GetOrConnectAsync(_otherServer, () => pending.Task, default);

		pool.Clear();

		Assert.Equal(0, pool.Count);
		Assert.True(await established.WaitForMarkFaultyAsync(TimeSpan.FromSeconds(2)), "The established connection was not closed");

		var late = new FakeConnection();
		pending.SetResult(late);
		await connecting;
		Assert.True(await late.WaitForMarkFaultyAsync(TimeSpan.FromSeconds(2)), "The connection established after clearing was not closed");
	}

	private static TaskCompletionSource<FakeConnection?> NewConnect() => new(TaskCreationOptions.RunContinuationsAsynchronously);

	private static async Task CompletesWithinAsync(Task task, TimeSpan timeout)
	{
		Assert.True(await Task.WhenAny(task, Task.Delay(timeout)) == task, $"The task did not complete within {timeout}");
		await task;
	}

	private sealed class FakeConnection : IPooledConnection
	{
		private readonly TaskCompletionSource<bool> _markedFaulty = new(TaskCreationOptions.RunContinuationsAsynchronously);
		private int _markFaultyCalls;

		public bool IsAlive { get; set; } = true;

		public int MarkFaultyCalls => Volatile.Read(ref _markFaultyCalls);

		public void MarkFaulty()
		{
			Interlocked.Increment(ref _markFaultyCalls);
			IsAlive = false;
			_markedFaulty.TrySetResult(true);
		}

		public async Task<bool> WaitForMarkFaultyAsync(TimeSpan timeout)
		{
			return await Task.WhenAny(_markedFaulty.Task, Task.Delay(timeout)) == _markedFaulty.Task;
		}
	}
}
