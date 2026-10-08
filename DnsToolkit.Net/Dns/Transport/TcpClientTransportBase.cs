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

using System.Net;
using System.Net.Sockets;

namespace DnsToolkit.Net.Dns;

public abstract class TcpClientTransportBase<TTransport> : PipelinedClientTransportBase
	where TTransport : TcpClientTransportBase<TTransport>
{
	private readonly int _port;

	/// <summary>
	///   The maximum allowed size of queries in bytes
	/// </summary>
	public override ushort MaximumAllowedQuerySize => UInt16.MaxValue;

	/// <summary>
	///   Creates a new instance of the TcpClientTransport
	/// </summary>
	/// <param name="port">The port to be used</param>
	protected TcpClientTransportBase(int port)
		: base(port)
	{
		_port = port;
	}

	protected abstract Task<Stream?> GetStreamAsync(TcpClient client, CancellationToken token);

	protected override async Task<IPipelineableClientConnection?> ConnectInternalAsync(DnsClientEndpointInfo endpointInfo, int queryTimeout, CancellationToken token)
	{
		var client = new TcpClient(endpointInfo.DestinationAddress.AddressFamily)
		{
			ReceiveTimeout = queryTimeout,
			SendTimeout = queryTimeout
		};

		try
		{
			if (!await client.TryConnectAsync(endpointInfo.DestinationAddress, _port, queryTimeout, token))
			{
				return null;
			}

			// Limit the stream setup (e.g. the TLS handshake), as the connect task is shared by all queries to this server
			Stream? stream;
			using (var setupCts = CancellationTokenSource.CreateLinkedTokenSource(token))
			{
				if (queryTimeout > 0)
					setupCts.CancelAfter(queryTimeout);

				stream = await GetStreamAsync(client, setupCts.Token);
			}

			if (stream == null)
			{
				client.Dispose();
				return null;
			}

			return new TcpClientConnection(this, (IPEndPoint) client.Client.RemoteEndPoint!, (IPEndPoint) client.Client.LocalEndPoint!, client, stream);
		}
		catch
		{
			client.Dispose();
			return null;
		}
	}

	private class TcpClientConnection : IPipelineableClientConnection
	{
		private readonly TcpClientTransportBase<TTransport> _transport;

		private readonly IPEndPoint _destinationEndPoint;
		private readonly IPEndPoint _localEndPoint;
		private readonly TcpClient _client;
		private readonly DnsTcpMessageStream _messageStream;

		public TcpClientConnection(TcpClientTransportBase<TTransport> transport, IPEndPoint destinationEndPoint, IPEndPoint localEndPoint, TcpClient client, Stream stream)
		{
			_transport = transport;
			_destinationEndPoint = destinationEndPoint;
			_localEndPoint = localEndPoint;
			_client = client;
			_messageStream = new DnsTcpMessageStream(stream);
		}

		public IClientTransport Transport => _transport;

		public async Task<bool> SendAsync(DnsRawPackage package, CancellationToken token = new())
		{
			if (package.Length > 0)
			{
				try
				{
					// serialized by the message stream, as several queries share the connection
					await _messageStream.WriteMessageAsync(package.ToArraySegment(true), token);
				}
				catch
				{
					return false;
				}
			}

			return true;
		}

		public async Task<DnsReceivedRawPackage?> ReceiveAsync(CancellationToken token = new())
		{
			try
			{
				// the timeout of a query is handled by the caller using the token
				var message = await _messageStream.ReadMessageAsync(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan, token);

				if (message == null)
				{
					MarkFaulty();
					return null;
				}

				return new DnsReceivedRawPackage(message, _destinationEndPoint, _localEndPoint);
			}
			catch
			{
				MarkFaulty();
				return null;
			}
		}

		public async Task<DnsReceivedRawPackage?> ReceiveAsync(DnsMessageIdentification identification, CancellationToken token)
		{
			DnsReceivedRawPackage? package;
			while ((package = await ReceiveAsync(token)) != null)
			{
				if (package.MessageIdentification.Equals(identification))
					return package;
			}

			return null;
		}

		public void RestartIdleTimeout(TimeSpan? timeout)
		{
			// do nothing, is implemented in PipelinedClientConnection
		}

		public bool IsAlive => !IsFaulty && _client.IsConnected();

		public bool IsFaulty { get; private set; }

		public void MarkFaulty()
		{
			IsFaulty = true;
		}

		public void Dispose()
		{
			MarkFaulty();
			_messageStream.Dispose();
			_client.TryDispose();
		}
	}
}