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

/// <summary>
///   A abstract base transport used by a server using tcp communication
/// </summary>
/// <typeparam name="TTransport">The type of the implemented transport</typeparam>
public abstract class TcpServerTransportBase<TTransport> : IServerTransport
	where TTransport : TcpServerTransportBase<TTransport>
{
	/// <summary>
	///   The read and write timeout of the transport in milliseconds
	/// </summary>
	public int Timeout { get; }

	/// <summary>
	///   The keep alive timeout in milliseconds for waiting for subsequent queries on the same connection
	/// </summary>
	public int KeepAlive { get; }

	private readonly TcpListener _tcpListener;

	/// <summary>
	///   The default allowed response size if no EDNS option is set.
	/// </summary>
	public ushort DefaultAllowedResponseSize => ushort.MaxValue;

	/// <summary>
	///   A value indicating, if the transport supports sending multiple response to a single query.
	/// </summary>
	public bool SupportsMultipleResponses => true;

	/// <summary>
	///   A value indicating, if truncated responses are allowed using this transport.
	/// </summary>
	public bool AllowTruncatedResponses => false;

	/// <summary>
	///   The transport protocol this transport is using
	/// </summary>
	public abstract TransportProtocol TransportProtocol { get; }

	protected TcpServerTransportBase(IPEndPoint bindEndPoint, int timeout = 5000, int keepAlive = 120000)
	{
		Timeout = timeout;
		KeepAlive = keepAlive;
		_tcpListener = new TcpListener(bindEndPoint);
		if (bindEndPoint.Address.Equals(IPAddress.IPv6Any))
			_tcpListener.Server.DualMode = true;
	}

	/// <summary>
	///   Binds the transport to the network stack
	/// </summary>
	public void Bind()
	{
		_tcpListener.Start();
	}

	/// <summary>
	///   Closes the transport
	/// </summary>
	public void Close()
	{
		_tcpListener.Stop();
	}

	protected abstract TcpServerConnectionBase CreateConnection(TcpClient client, CancellationToken token);

	/// <summary>
	///   Waits for a new connection and return the connection
	/// </summary>
	/// <param name="token"> The token to monitor cancellation requests </param>
	/// <returns>A new connection to a client or null, if no connection could not be established</returns>
	public async Task<IServerConnection?> AcceptConnectionAsync(CancellationToken token = default)
	{
		try
		{
			var client = await _tcpListener.AcceptTcpClientAsync(token);
			client.SendTimeout = Timeout;
			client.ReceiveTimeout = Timeout;

			return CreateConnection(client, token);
		}
		catch
		{
			return null;
		}
	}

	public void Dispose()
	{
		try
		{
			_tcpListener.Stop();
		}
		catch
		{
			// ignored
		}
	}

	/// <summary>
	///   The connection which is used to the server using TCP communication
	/// </summary>
	protected abstract class TcpServerConnectionBase : IServerConnection
	{
		protected readonly TTransport TransportInternal;
		private DnsTcpMessageStream? _messageStream;

		protected TcpClient Client { get; }

		/// <summary>
		///   The corresponding transport
		/// </summary>
		public IServerTransport Transport => TransportInternal;

		/// <summary>
		///   The remote endpoint of the connection
		/// </summary>
		public IPEndPoint RemoteEndPoint => (IPEndPoint) Client.Client.RemoteEndPoint!;

		/// <summary>
		///   The local endpoint of the connection
		/// </summary>
		public IPEndPoint LocalEndPoint => (IPEndPoint) Client.Client.LocalEndPoint!;

		protected TcpServerConnectionBase(TTransport transport, TcpClient client)
		{
			TransportInternal = transport;
			Client = client;
		}

		protected abstract Task<Stream?> GetStreamFromClientAsync(CancellationToken token);

		/// <summary>
		///   Initializes the connection before it can be used for sending/receiving data
		/// </summary>
		public async Task<bool> InitializeAsync(CancellationToken token)
		{
			var stream = await GetStreamFromClientAsync(token);
			if (stream == null)
				return false;

			_messageStream = new DnsTcpMessageStream(stream);
			return true;
		}

		/// <summary>
		///   Receives a new package of the client
		/// </summary>
		/// <param name="token"> The token to monitor cancellation requests </param>
		/// <returns>A raw package sent by the client, or null if the client disconnected or a timeout occured</returns>
		public virtual async Task<DnsReceivedRawPackage?> ReceiveAsync(CancellationToken token = default)
		{
			if (_messageStream == null)
				return null;

			try
			{
				var remoteEndPoint = RemoteEndPoint;
				var localEndPoint = LocalEndPoint;

				// wait up to the keep alive for the next query, and up to the timeout for the rest of it
				var message = await _messageStream.ReadMessageAsync(
					DnsTcpMessageStream.ToTimeout(TransportInternal.KeepAlive),
					DnsTcpMessageStream.ToTimeout(TransportInternal.Timeout),
					token);

				return message == null ? null : new DnsReceivedRawPackage(message, remoteEndPoint, localEndPoint);
			}
			catch
			{
				return null;
			}
		}

		/// <summary>
		///   Sends a raw package to the client
		/// </summary>
		/// <param name="package">The package, which should be sent to the client</param>
		/// <param name="token"> The token to monitor cancellation requests </param>
		/// <returns>true, of the package could be sent to the client; otherwise, false</returns>
		public virtual async Task<bool> SendAsync(DnsRawPackage package, CancellationToken token = default)
		{
			if (_messageStream == null)
				return false;

			try
			{
				// serialized by the message stream, as responses to pipelined queries are sent concurrently
				await _messageStream.WriteMessageAsync(package.ToArraySegment(true), token);
				return true;
			}
			catch
			{
				return false;
			}
		}

		/// <summary>
		///   A value indicating if data could be read from the client
		/// </summary>
		public bool CanRead => Client.Connected;

		public void Dispose()
		{
			_messageStream?.Dispose();
			Client.TryDispose();
		}
	}
}