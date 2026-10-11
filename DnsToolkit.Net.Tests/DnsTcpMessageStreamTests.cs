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
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

public class DnsTcpMessageStreamTests
{
	private static readonly TimeSpan _infinite = Timeout.InfiniteTimeSpan;

	[Fact]
	public async Task ReadsMessage_DeliveredByteByByte()
	{
		var message = Message(1, 20);
		using var stream = new ScriptedReadStream(message, chunkSize: 1);
		using var messageStream = new DnsTcpMessageStream(stream);

		Assert.Equal(message, await messageStream.ReadMessageAsync(_infinite, _infinite, default));
		Assert.Null(await messageStream.ReadMessageAsync(_infinite, _infinite, default));
	}

	[Fact]
	public async Task ReadsSeveralMessages_DeliveredInOneRead()
	{
		var messages = new[] { Message(1, 10), Message(2, 0), Message(3, 300) };
		using var stream = new ScriptedReadStream(messages.SelectMany(m => m).ToArray(), chunkSize: 4096);
		using var messageStream = new DnsTcpMessageStream(stream);

		foreach (var message in messages)
			Assert.Equal(message, await messageStream.ReadMessageAsync(_infinite, _infinite, default));

		Assert.Null(await messageStream.ReadMessageAsync(_infinite, _infinite, default));
	}

	[Fact]
	public async Task ReturnsNull_WhenStreamEndsWithinMessage()
	{
		using var stream = new ScriptedReadStream(Message(1, 20).Take(10).ToArray(), chunkSize: 3);
		using var messageStream = new DnsTcpMessageStream(stream);

		Assert.Null(await messageStream.ReadMessageAsync(_infinite, _infinite, default));
	}

	[Fact]
	public async Task FirstByteTimeout_ReturnsNull_AndKeepsStreamOpen()
	{
		// a connection on which the client never sends anything
		using var stream = new ScriptedReadStream(Array.Empty<byte>(), chunkSize: 1, blockAtEnd: true);
		using var messageStream = new DnsTcpMessageStream(stream);

		var stopwatch = Stopwatch.StartNew();
		Assert.Null(await messageStream.ReadMessageAsync(TimeSpan.FromMilliseconds(200), _infinite, default));

		Assert.InRange(stopwatch.Elapsed, TimeSpan.FromMilliseconds(150), TimeSpan.FromSeconds(3));

		// the responses to the queries in progress can still be written, before the stream is closed
		Assert.False(stream.IsDisposed);

		// the abandoned read is still pending, before a second read failed with an exception of the pipe reader
		await Assert.ThrowsAsync<InvalidOperationException>(() => messageStream.ReadMessageAsync(_infinite, _infinite, default));
	}

	[Fact]
	public async Task IdleToken_EndsTheWaitForTheNextMessage_LikeTheFirstByteTimeout()
	{
		using var stream = new ScriptedReadStream(Array.Empty<byte>(), chunkSize: 1, blockAtEnd: true);
		using var messageStream = new DnsTcpMessageStream(stream);
		using var idleCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));

		Assert.Null(await messageStream.ReadMessageAsync(_infinite, idleCts.Token, _infinite, default));
		Assert.False(stream.IsDisposed);
	}

	[Fact]
	public async Task IdleToken_DoesNotLimitMessageOnceStarted()
	{
		// the message starts immediately, but takes about 700 ms in total
		var message = Message(1, 5);
		using var stream = new ScriptedReadStream(message, chunkSize: 1, chunkDelay: TimeSpan.FromMilliseconds(100));
		using var messageStream = new DnsTcpMessageStream(stream);
		using var idleCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));

		Assert.Equal(message, await messageStream.ReadMessageAsync(_infinite, idleCts.Token, TimeSpan.FromSeconds(5), default));
	}

	[Fact]
	public async Task MessageTimeout_AppliesOnceMessageStarted()
	{
		// the client sends the start of a message and then stops
		using var stream = new ScriptedReadStream(Message(1, 20).Take(5).ToArray(), chunkSize: 5, blockAtEnd: true);
		using var messageStream = new DnsTcpMessageStream(stream);

		var stopwatch = Stopwatch.StartNew();
		await Assert.ThrowsAnyAsync<OperationCanceledException>(() => messageStream.ReadMessageAsync(_infinite, TimeSpan.FromMilliseconds(200), default));

		Assert.InRange(stopwatch.Elapsed, TimeSpan.FromMilliseconds(150), TimeSpan.FromSeconds(3));
		Assert.True(stream.IsDisposed);
	}

	[Fact]
	public async Task FirstByteTimeout_DoesNotLimitMessageOnceStarted()
	{
		// the message starts immediately, but takes about 700 ms in total, longer than the first byte timeout
		var message = Message(1, 5);
		using var stream = new ScriptedReadStream(message, chunkSize: 1, chunkDelay: TimeSpan.FromMilliseconds(100));
		using var messageStream = new DnsTcpMessageStream(stream);

		Assert.Equal(message, await messageStream.ReadMessageAsync(TimeSpan.FromMilliseconds(300), TimeSpan.FromSeconds(5), default));
	}

	[Fact]
	public async Task Cancellation_ClosesStream()
	{
		using var stream = new ScriptedReadStream(Array.Empty<byte>(), chunkSize: 1, blockAtEnd: true);
		using var messageStream = new DnsTcpMessageStream(stream);
		using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

		await Assert.ThrowsAnyAsync<OperationCanceledException>(() => messageStream.ReadMessageAsync(_infinite, _infinite, cts.Token));

		Assert.True(stream.IsDisposed);
	}

	[Fact]
	public async Task ConcurrentWrites_AreSerialized()
	{
		using var stream = new ConcurrencyDetectingStream();
		using var messageStream = new DnsTcpMessageStream(stream);

		var messages = Enumerable.Range(0, 50).Select(i => Message((byte) i, 100)).ToList();
		await Task.WhenAll(messages.Select(m => Task.Run(() => messageStream.WriteMessageAsync(new ArraySegment<byte>(m), default))));

		Assert.False(stream.ConcurrentWriteDetected, "Two writes were running at the same time");

		// every message must be written in one piece
		using var reader = new DnsTcpMessageStream(new ScriptedReadStream(stream.GetWrittenData(), chunkSize: 4096));
		var received = new List<byte[]>();
		byte[]? message;
		while ((message = await reader.ReadMessageAsync(_infinite, _infinite, default)) != null)
			received.Add(message);

		Assert.Equal(messages.Count, received.Count);
		Assert.All(received, m => Assert.Contains(messages, expected => expected.SequenceEqual(m)));
	}

	[Fact]
	public async Task CancellationWhileWaitingForAnotherWrite_KeepsStreamUsable()
	{
		using var stream = new BlockingWriteStream();
		using var messageStream = new DnsTcpMessageStream(stream);

		var first = messageStream.WriteMessageAsync(new ArraySegment<byte>(Message(1, 10)), default);
		await stream.WriteStarted;

		using (var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100)))
			await Assert.ThrowsAnyAsync<OperationCanceledException>(() => messageStream.WriteMessageAsync(new ArraySegment<byte>(Message(2, 10)), cts.Token));

		// nothing of the canceled message was written, so the stream stays usable
		stream.Release();
		await first;
		await messageStream.WriteMessageAsync(new ArraySegment<byte>(Message(3, 10)), default);

		Assert.False(messageStream.IsDisposed);
		Assert.Equal(Message(1, 10).Concat(Message(3, 10)), stream.GetWrittenData());
	}

	[Fact]
	public async Task CancellationDuringTheWrite_ClosesStream()
	{
		using var stream = new BlockingWriteStream();
		using var messageStream = new DnsTcpMessageStream(stream);
		using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

		await Assert.ThrowsAnyAsync<OperationCanceledException>(() => messageStream.WriteMessageAsync(new ArraySegment<byte>(Message(1, 10)), cts.Token));

		// a partially written message would corrupt the stream for the following messages
		Assert.True(messageStream.IsDisposed);
		Assert.True(stream.IsDisposed);
	}

	/// <summary>
	///   A message with length header, whose payload consists of the given marker byte
	/// </summary>
	private static byte[] Message(byte marker, int payloadLength)
	{
		var message = new byte[payloadLength + 2];
		message[0] = (byte) (payloadLength >> 8);
		message[1] = (byte) payloadLength;
		for (var i = 2; i < message.Length; i++)
			message[i] = marker;
		return message;
	}

	/// <summary>
	///   Delivers the data in chunks of the given size. At the end it either signals the end of the stream or,
	///   like a socket waiting for data, blocks until it is disposed. Like NetworkStream on .NET Framework, it ignores the cancellation token.
	/// </summary>
	private sealed class ScriptedReadStream : Stream
	{
		private readonly byte[] _data;
		private readonly int _chunkSize;
		private readonly bool _blockAtEnd;
		private readonly TimeSpan _chunkDelay;
		private readonly TaskCompletionSource<bool> _disposed = new(TaskCreationOptions.RunContinuationsAsynchronously);
		private int _position;

		public ScriptedReadStream(byte[] data, int chunkSize, bool blockAtEnd = false, TimeSpan chunkDelay = default)
		{
			_data = data;
			_chunkSize = chunkSize;
			_blockAtEnd = blockAtEnd;
			_chunkDelay = chunkDelay;
		}

		public bool IsDisposed => _disposed.Task.IsCompleted;

		public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			if (IsDisposed)
				throw new ObjectDisposedException(nameof(ScriptedReadStream));

			if (_position < _data.Length)
			{
				if (_chunkDelay > TimeSpan.Zero && _position > 0)
					await Task.Delay(_chunkDelay);
				else
					await Task.Yield();

				var length = Math.Min(Math.Min(count, _chunkSize), _data.Length - _position);
				Buffer.BlockCopy(_data, _position, buffer, offset, length);
				_position += length;
				return length;
			}

			if (!_blockAtEnd)
				return 0;

			await _disposed.Task;
			throw new ObjectDisposedException(nameof(ScriptedReadStream));
		}

		public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer, offset, count, default).GetAwaiter().GetResult();

		protected override void Dispose(bool disposing)
		{
			_disposed.TrySetResult(true);
			base.Dispose(disposing);
		}

		public override bool CanRead => true;
		public override bool CanSeek => false;
		public override bool CanWrite => false;
		public override long Length => throw new NotSupportedException();
		public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
		public override void Flush() { }
		public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
		public override void SetLength(long value) => throw new NotSupportedException();
		public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
	}

	/// <summary>
	///   Blocks the writes like a socket with a full send buffer, until they are released or canceled, and records the written data
	/// </summary>
	private sealed class BlockingWriteStream : Stream
	{
		private readonly TaskCompletionSource<bool> _writeStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
		private readonly TaskCompletionSource<bool> _released = new(TaskCreationOptions.RunContinuationsAsynchronously);
		private readonly MemoryStream _written = new();

		public Task WriteStarted => _writeStarted.Task;

		public bool IsDisposed { get; private set; }

		public void Release() => _released.TrySetResult(true);

		public byte[] GetWrittenData()
		{
			lock (_written)
				return _written.ToArray();
		}

		public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			_writeStarted.TrySetResult(true);

			var canceled = Task.Delay(Timeout.Infinite, cancellationToken);
			if (await Task.WhenAny(_released.Task, canceled) == canceled)
				await canceled;

			lock (_written)
				_written.Write(buffer, offset, count);
		}

		public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer, offset, count, default).GetAwaiter().GetResult();

		public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

		protected override void Dispose(bool disposing)
		{
			IsDisposed = true;
			base.Dispose(disposing);
		}

		public override bool CanRead => false;
		public override bool CanSeek => false;
		public override bool CanWrite => true;
		public override long Length => throw new NotSupportedException();
		public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
		public override void Flush() { }
		public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
		public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
		public override void SetLength(long value) => throw new NotSupportedException();
	}

	/// <summary>
	///   Records the written data and whether two writes were running at the same time, which e.g. SslStream does not allow
	/// </summary>
	private sealed class ConcurrencyDetectingStream : Stream
	{
		private readonly MemoryStream _written = new();
		private int _activeWrites;

		public bool ConcurrentWriteDetected { get; private set; }

		public byte[] GetWrittenData()
		{
			lock (_written)
				return _written.ToArray();
		}

		public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
		{
			if (Interlocked.Increment(ref _activeWrites) > 1)
				ConcurrentWriteDetected = true;

			try
			{
				// write in two parts with a pause in between, so interleaved writes would corrupt the data
				var half = count / 2;
				lock (_written)
					_written.Write(buffer, offset, half);
				await Task.Delay(1);
				lock (_written)
					_written.Write(buffer, offset + half, count - half);
			}
			finally
			{
				Interlocked.Decrement(ref _activeWrites);
			}
		}

		public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer, offset, count, default).GetAwaiter().GetResult();

		public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

		public override bool CanRead => false;
		public override bool CanSeek => false;
		public override bool CanWrite => true;
		public override long Length => throw new NotSupportedException();
		public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
		public override void Flush() { }
		public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
		public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
		public override void SetLength(long value) => throw new NotSupportedException();
	}
}
