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

using System.Buffers;
using System.IO.Pipelines;

namespace DnsToolkit.Net.Dns;

/// <summary>
///   Reads and writes DNS messages with the two byte length prefix used by TCP and TLS (RFC 1035 4.2.2, RFC 7766).
///   A message may arrive in any number of reads and several messages may arrive in one read.
///   Writes are serialized, as streams like SslStream do not allow concurrent writes.
/// </summary>
internal sealed class DnsTcpMessageStream : IDisposable
{
	private readonly Stream _stream;
	private readonly PipeReader _reader;
	private readonly SemaphoreSlim _writeLock = new(1, 1);
	private int _isDisposed;

	public DnsTcpMessageStream(Stream stream)
	{
		_stream = stream;
		_reader = PipeReader.Create(stream, new StreamPipeReaderOptions(leaveOpen: true));
	}

	/// <summary>
	///   Reads the next message
	/// </summary>
	/// <param name="firstByteTimeout">The time to wait for the start of the message, e.g. the keep alive of an idle connection</param>
	/// <param name="messageTimeout">The time to receive the rest of the message, after it started</param>
	/// <param name="token">The token to monitor cancellation requests</param>
	/// <returns>
	///   The message including the length header, or null if the stream ended or no message started within the first byte
	///   timeout. After the first byte timeout, the stream stays open for writing, e.g. the responses to the queries in
	///   progress, but must not be read anymore.
	/// </returns>
	/// <exception cref="OperationCanceledException">
	///   On the message timeout or cancellation. The stream is closed then, as a partially read message cannot be continued.
	/// </exception>
	public async Task<byte[]?> ReadMessageAsync(TimeSpan firstByteTimeout, TimeSpan messageTimeout, CancellationToken token)
	{
		using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token);

		// Not all streams observe the token (e.g. NetworkStream on .NET Framework), closing the stream aborts the read in any case
		using var registration = timeoutCts.Token.Register(Dispose);

		// The first byte timeout does not cancel the read, as canceling closes the stream
		using var firstByteTimeoutCts = new CancellationTokenSource();
		var firstByteTimeoutTask = firstByteTimeout == Timeout.InfiniteTimeSpan ? null : Task.Delay(firstByteTimeout, firstByteTimeoutCts.Token);

		var isMessageStarted = false;

		try
		{
			while (true)
			{
				var read = _reader.ReadAsync(timeoutCts.Token);

				ReadResult result;
				if (!isMessageStarted && (firstByteTimeoutTask != null) && !read.IsCompleted)
				{
					var readTask = read.AsTask();
					if (await Task.WhenAny(readTask, firstByteTimeoutTask).ConfigureAwait(false) == firstByteTimeoutTask)
					{
						// The read ends, when the stream is disposed
						_ = readTask.ContinueWith(t => t.Exception, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
						return null;
					}

					result = await readTask.ConfigureAwait(false);
				}
				else
				{
					result = await read.ConfigureAwait(false);
				}

				var buffer = result.Buffer;

				if (TryReadMessage(ref buffer, out var message))
				{
					_reader.AdvanceTo(buffer.Start);
					return message;
				}

				if (result.IsCompleted)
				{
					// end of the stream, a partially received message is dropped
					_reader.AdvanceTo(buffer.End);
					return null;
				}

				if (!isMessageStarted && (buffer.Length > 0))
				{
					isMessageStarted = true;
					timeoutCts.CancelAfter(messageTimeout);
				}

				// all data is examined, but not enough for a complete message
				_reader.AdvanceTo(buffer.Start, buffer.End);
			}
		}
		catch (Exception) when (timeoutCts.IsCancellationRequested)
		{
			// the stream was closed by the timeout or cancellation, which may result in other exceptions than OperationCanceledException
			throw new OperationCanceledException(timeoutCts.Token);
		}
		finally
		{
			firstByteTimeoutCts.Cancel();
		}
	}

	/// <summary>
	///   Writes a message
	/// </summary>
	/// <param name="messageWithLengthHeader">The message including the length header</param>
	/// <param name="token">The token to monitor cancellation requests</param>
	/// <exception cref="OperationCanceledException">
	///   On cancellation. If the message was canceled while it waited for the other messages, the stream stays usable.
	///   Otherwise it is closed like on any other error of the write, as a partially written message corrupts the stream.
	/// </exception>
	public async Task WriteMessageAsync(ArraySegment<byte> messageWithLengthHeader, CancellationToken token)
	{
		await _writeLock.WaitAsync(token).ConfigureAwait(false);
		try
		{
			await _stream.WriteAsync(messageWithLengthHeader.Array!, messageWithLengthHeader.Offset, messageWithLengthHeader.Count, token).ConfigureAwait(false);
			await _stream.FlushAsync(token).ConfigureAwait(false);
		}
		catch
		{
			Dispose();
			throw;
		}
		finally
		{
			_writeLock.Release();
		}
	}

	private static bool TryReadMessage(ref ReadOnlySequence<byte> buffer, out byte[]? message)
	{
		message = null;

		if (buffer.Length < DnsRawPackage.LENGTH_HEADER_LENGTH)
			return false;

		Span<byte> header = stackalloc byte[DnsRawPackage.LENGTH_HEADER_LENGTH];
		buffer.Slice(0, DnsRawPackage.LENGTH_HEADER_LENGTH).CopyTo(header);
		var messageLength = DnsRawPackage.LENGTH_HEADER_LENGTH + ((header[0] << 8) | header[1]);

		if (buffer.Length < messageLength)
			return false;

		message = buffer.Slice(0, messageLength).ToArray();
		buffer = buffer.Slice(messageLength);
		return true;
	}

	public bool IsDisposed => Volatile.Read(ref _isDisposed) == 1;

	/// <summary>
	///   Closes the stream, which also aborts a pending read
	/// </summary>
	public void Dispose()
	{
		if (Interlocked.Exchange(ref _isDisposed, 1) == 1)
			return;

		// The pipe reader is not completed here, as a pending read may still use its buffers. They are left to the garbage collector.
		_stream.TryDispose();
	}

	/// <summary>
	///   Converts a timeout in milliseconds, where 0 or less means no timeout like the timeouts of sockets
	/// </summary>
	public static TimeSpan ToTimeout(int milliseconds)
	{
		return milliseconds > 0 ? TimeSpan.FromMilliseconds(milliseconds) : Timeout.InfiniteTimeSpan;
	}
}
