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

using System.Buffers;

namespace DnsToolkit.Net.Dns;

/// <summary>
///   Pooled receive buffers for UDP clients, so that a query does not allocate a buffer of the maximum message size
/// </summary>
internal static class UdpReceiveBuffer
{
	/// <summary>
	///   The maximum size of a DNS message received over UDP
	/// </summary>
	public const int MAX_MESSAGE_SIZE = UInt16.MaxValue;

	public static byte[] Rent()
	{
		return ArrayPool<byte>.Shared.Rent(MAX_MESSAGE_SIZE + DnsRawPackage.LENGTH_HEADER_LENGTH);
	}

	public static ArraySegment<byte> GetReceiveSegment(byte[] buffer)
	{
		return new ArraySegment<byte>(buffer, DnsRawPackage.LENGTH_HEADER_LENGTH, MAX_MESSAGE_SIZE);
	}

	/// <summary>
	///   Copies the received message into an array of its size, including the length header
	/// </summary>
	public static byte[] CopyMessage(byte[] buffer, int length)
	{
		var message = new byte[length + DnsRawPackage.LENGTH_HEADER_LENGTH];
		DnsMessageBase.EncodeUShort(message, 0, (ushort) length);
		Buffer.BlockCopy(buffer, DnsRawPackage.LENGTH_HEADER_LENGTH, message, DnsRawPackage.LENGTH_HEADER_LENGTH, length);
		return message;
	}

	/// <summary>
	///   Returns the buffer to the pool, but only if the receive operation is done. A receive which was abandoned
	///   on timeout may still write into the buffer, so in that case the buffer is left to the garbage collector.
	/// </summary>
	public static void Return(byte[] buffer, Task? receiveTask)
	{
		if (receiveTask == null || receiveTask.IsCompleted)
			ArrayPool<byte>.Shared.Return(buffer);
	}
}
