#if NETFRAMEWORK
using System.Net;
using System.Net.Sockets;

namespace DnsToolkit.Net.Tests;

/// <summary>
///   The polyfills only exist in the netstandard2.0 build, which is used by the net48 test run
/// </summary>
public class NetStandardPolyfillTests
{
	[Fact]
	public void WaitAsync_WithoutTimeoutAndToken_ReturnsSameTask()
	{
		var task = new TaskCompletionSource<int>().Task;

		Assert.Same(task, NetStandardPolyfills.WaitAsync(task, Timeout.InfiniteTimeSpan, CancellationToken.None));
	}

	[Fact]
	public async Task WaitAsync_ReturnsResult()
	{
		var tcs = new TaskCompletionSource<int>();
		var wait = NetStandardPolyfills.WaitAsync(tcs.Task, TimeSpan.FromSeconds(5), CancellationToken.None);

		tcs.SetResult(42);

		Assert.Equal(42, await wait);
	}

	[Fact]
	public async Task WaitAsync_PropagatesException()
	{
		var tcs = new TaskCompletionSource<int>();
		var wait = NetStandardPolyfills.WaitAsync(tcs.Task, TimeSpan.FromSeconds(5), CancellationToken.None);

		tcs.SetException(new InvalidOperationException("failed"));

		await Assert.ThrowsAsync<InvalidOperationException>(() => wait);
	}

	[Fact]
	public async Task WaitAsync_ThrowsTimeoutException()
	{
		var task = new TaskCompletionSource<int>().Task;

		await Assert.ThrowsAsync<TimeoutException>(() => NetStandardPolyfills.WaitAsync(task, TimeSpan.FromMilliseconds(50), CancellationToken.None));
	}

	[Fact]
	public async Task WaitAsync_ThrowsOperationCanceledException()
	{
		var task = new TaskCompletionSource<int>().Task;
		using var cts = new CancellationTokenSource(50);

		await Assert.ThrowsAnyAsync<OperationCanceledException>(() => NetStandardPolyfills.WaitAsync(task, cts.Token));
	}

	[Fact]
	public void TryAdd_AddsOnlyNewKeys()
	{
		var dictionary = new Dictionary<string, int>();

		Assert.True(NetStandardPolyfills.TryAdd(dictionary, "a", 1));
		Assert.False(NetStandardPolyfills.TryAdd(dictionary, "a", 2));
		Assert.Equal(1, dictionary["a"]);
	}

	[Fact]
	public void Remove_ReturnsRemovedValue()
	{
		var dictionary = new Dictionary<string, int> { ["a"] = 1 };

		Assert.True(NetStandardPolyfills.Remove(dictionary, "a", out var value));
		Assert.Equal(1, value);
		Assert.False(NetStandardPolyfills.Remove(dictionary, "a", out _));
		Assert.Empty(dictionary);
	}

	[Fact]
	public void Slice_ReturnsSubSegment()
	{
		var segment = new ArraySegment<byte>(new byte[] { 0, 1, 2, 3, 4, 5 }, 1, 4);

		Assert.Equal(new byte[] { 2, 3, 4 }, NetStandardPolyfills.Slice(segment, 1).ToArray());
		Assert.Equal(new byte[] { 2, 3 }, NetStandardPolyfills.Slice(segment, 1, 2).ToArray());
		Assert.Empty(NetStandardPolyfills.Slice(segment, 4).ToArray());
	}

	[Theory]
	[InlineData(5, 0)]
	[InlineData(1, 4)]
	[InlineData(-1, 1)]
	public void Slice_ThrowsOutsideOfSegment(int index, int count)
	{
		var segment = new ArraySegment<byte>(new byte[] { 0, 1, 2, 3, 4, 5 }, 1, 4);

		Assert.Throws<ArgumentOutOfRangeException>(() => NetStandardPolyfills.Slice(segment, index, count));
	}

	[Fact]
	public async Task AcceptTcpClientAsync_Cancelled_ClosesClientAcceptedLater()
	{
		var listener = new TcpListener(IPAddress.Loopback, 0);
		listener.Start();
		try
		{
			using (var cts = new CancellationTokenSource(100))
			{
				await Assert.ThrowsAnyAsync<OperationCanceledException>(() => NetStandardPolyfills.AcceptTcpClientAsync(listener, cts.Token));
			}

			// The still pending accept picks up this connection and has to close it
			using var client = new TcpClient();
			await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint) listener.LocalEndpoint).Port);

			Assert.True(await TransportTests.WaitForRemoteCloseAsync(client, TimeSpan.FromSeconds(5)), "The late accepted connection was not closed");
		}
		finally
		{
			listener.Stop();
		}
	}
}
#endif
