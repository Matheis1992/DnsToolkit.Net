#region Copyright and License
// Copyright 2010..2024 Alexander Reinert
//
// This file is part of the ARSoft.Tools.Net - C# DNS client/server and SPF Library (https://github.com/alexreinert/ARSoft.Tools.Net)
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

#if NETSTANDARD2_0
using System.Net;
using System.Net.Sockets;

namespace DnsToolkit.Net;

/// <summary>
///   Shims for APIs which are available in .NET Core 2.1+ but missing in .NET Standard 2.0
/// </summary>
internal static class NetStandardPolyfills
{
	#region Task
	public static Task WaitAsync(this Task task, CancellationToken token)
	{
		return task.WaitAsync(Timeout.InfiniteTimeSpan, token);
	}

	public static async Task WaitAsync(this Task task, TimeSpan timeout, CancellationToken token)
	{
		if (!task.IsCompleted)
		{
			using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);

			if (await Task.WhenAny(task, Task.Delay(timeout, cts.Token)).ConfigureAwait(false) != task)
			{
				token.ThrowIfCancellationRequested();
				throw new TimeoutException();
			}

			cts.Cancel();
		}

		await task.ConfigureAwait(false);
	}

	public static Task<T> WaitAsync<T>(this Task<T> task, CancellationToken token)
	{
		return task.WaitAsync(Timeout.InfiniteTimeSpan, token);
	}

	public static async Task<T> WaitAsync<T>(this Task<T> task, TimeSpan timeout, CancellationToken token)
	{
		await ((Task) task).WaitAsync(timeout, token).ConfigureAwait(false);
		return task.Result;
	}

	public static CancellationTokenRegistration Register(this CancellationToken token, Action<object?, CancellationToken> callback, object? state)
	{
		return token.Register(s => callback(s, token), state);
	}
	#endregion

	#region Collections
	public static bool TryAdd<TKey, TValue>(this Dictionary<TKey, TValue> dictionary, TKey key, TValue value)
		where TKey : notnull
	{
		if (dictionary.ContainsKey(key))
			return false;

		dictionary.Add(key, value);
		return true;
	}

	public static bool Remove<TKey, TValue>(this Dictionary<TKey, TValue> dictionary, TKey key, out TValue? value)
		where TKey : notnull
	{
		if (dictionary.TryGetValue(key, out value))
			return dictionary.Remove(key);

		value = default;
		return false;
	}

	public static HashSet<T> ToHashSet<T>(this IEnumerable<T> source)
	{
		return new HashSet<T>(source);
	}

	public static ArraySegment<T> Slice<T>(this ArraySegment<T> segment, int index)
	{
		return segment.Slice(index, segment.Count - index);
	}

	public static ArraySegment<T> Slice<T>(this ArraySegment<T> segment, int index, int count)
	{
		if ((uint) index > (uint) segment.Count || (uint) count > (uint) (segment.Count - index))
			throw new ArgumentOutOfRangeException(nameof(index));

		return new ArraySegment<T>(segment.Array!, segment.Offset + index, count);
	}

	public static T[] ToArray<T>(this ArraySegment<T> segment)
	{
		return segment.AsSpan().ToArray();
	}
	#endregion

	#region IO
	public static Task WriteAsync(this Stream stream, ArraySegment<byte> buffer, CancellationToken token)
	{
		return stream.WriteAsync(buffer.Array!, buffer.Offset, buffer.Count, token);
	}

	public static Task CopyToAsync(this HttpContent content, Stream stream, CancellationToken token)
	{
		return content.CopyToAsync(stream).WaitAsync(token);
	}

	public static Task<TcpClient> AcceptTcpClientAsync(this TcpListener listener, CancellationToken token)
	{
		return listener.AcceptTcpClientAsync().WaitAsync(token);
	}

	public static ValueTask ConnectAsync(this TcpClient client, IPAddress address, int port, CancellationToken token)
	{
		return new ValueTask(client.ConnectAsync(address, port).WaitAsync(token));
	}

	public static ValueTask ConnectAsync(this Socket socket, IPAddress address, int port, CancellationToken token)
	{
		return new ValueTask(socket.ConnectAsync(address, port).WaitAsync(token));
	}

	public static ValueTask<int> SendToAsync(this Socket socket, ArraySegment<byte> buffer, SocketFlags socketFlags, EndPoint remoteEP, CancellationToken token)
	{
		return new ValueTask<int>(socket.SendToAsync(buffer, socketFlags, remoteEP).WaitAsync(token));
	}

	public static ValueTask<SocketReceiveMessageFromResult> ReceiveMessageFromAsync(this Socket socket, ArraySegment<byte> buffer, SocketFlags socketFlags, EndPoint remoteEndPoint, CancellationToken token)
	{
		return new ValueTask<SocketReceiveMessageFromResult>(socket.ReceiveMessageFromAsync(buffer, socketFlags, remoteEndPoint).WaitAsync(token));
	}
	#endregion
}
#endif
