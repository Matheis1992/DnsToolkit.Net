#region Copyright and License
// Copyright 2010..2024 Alexander Reinert
// Modifications Copyright 2026 Matheis1992
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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DnsToolkit.Net
{
	internal static class TcpClientExtensions
	{
		public static bool TryConnect(this TcpClient tcpClient, IPAddress address, int port, int timeout)
		{
			try
			{
				var ar = tcpClient.BeginConnect(address, port, null, null);

				if (!ar.AsyncWaitHandle.WaitOne(TaskExtensions.ToTimeout(timeout), false))
				{
					tcpClient.Close();
				}

				tcpClient.EndConnect(ar);
			}
			catch
			{
				return false;
			}

			return true;
		}

		public static async Task<bool> TryConnectAsync(this TcpClient tcpClient, IPAddress address, int port, int timeout, CancellationToken token)
		{
			try
			{
				await tcpClient.ConnectAsync(address, port, token).AsTask().WaitAsync(TaskExtensions.ToTimeout(timeout), token).ConfigureAwait(false);
				return true;
			}
			catch
			{
				try
				{
					tcpClient.Close();
				}
				catch
				{
					// ignored
				}

				return false;
			}
		}

		/// <summary>
		///   Checks without blocking, if the remote side closed the connection
		/// </summary>
		public static bool IsConnected(this TcpClient client)
		{
			if (!client.Connected)
				return false;

			// No data is read, not even peeked: a pending read of the connection, e.g. the receive loop of a pooled connection,
			// may take the data meanwhile, and the peek then blocked until further data arrived or the receive timeout expired.
			// Readable without data means, that the remote side closed the connection. As the pending read may also take the
			// data between both checks, the connection only counts as closed, if this is seen twice in a row.
			try
			{
				for (var i = 0; i < 2; i++)
				{
					if (!client.Client.Poll(0, SelectMode.SelectRead) || (client.Client.Available > 0))
						return true;
				}

				return false;
			}
			catch
			{
				return false;
			}
		}
	}
}