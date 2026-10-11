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

	private readonly IPEndPoint _bindEndPoint;
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
		_bindEndPoint = bindEndPoint;
		_tcpListener = new TcpListener(bindEndPoint);
	}

	/// <summary>
	///   Binds the transport to the network stack
	/// </summary>
	public void Bind()
	{
		// Stopping the listener replaces its socket, so dual mode is set for every start, also after a restart of the server
		if (_bindEndPoint.Address.Equals(IPAddress.IPv6Any))
			_tcpListener.Server.DualMode = true;

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
	/// <returns>A new connection to a client, or null if the token was cancelled</returns>
	/// <exception cref="SocketException">The listener failed, e.g. because it was stopped</exception>
	public async Task<IServerConnection?> AcceptConnectionAsync(CancellationToken token = default)
	{
		// Errors which only concern a single client, e.g. a client which disconnected again before it was accepted,
		// are handled here by accepting the next client, so the server only sees errors of the listener itself
		while (true)
		{
			TcpClient client;

			try
			{
				client = await _tcpListener.AcceptTcpClientAsync(token).ConfigureAwait(false);
			}
			catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted)
			{
				continue;
			}
			catch (OperationCanceledException) when (token.IsCancellationRequested)
			{
				return null;
			}

			try
			{
				client.SendTimeout = Timeout;
				client.ReceiveTimeout = Timeout;

				return CreateConnection(client, token);
			}
			catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
			{
				// the client disconnected meanwhile
				client.Dispose();
			}
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
	protected abstract class TcpServerConnectionBase : IServerConnection, IKeepAliveServerConnection
	{
		protected readonly TTransport TransportInternal;
		private DnsTcpMessageStream? _messageStream;

		// Canceled once the keep alive expired, then no further queries are read. The keep alive only runs while no query is
		// in progress, so it does not end the connection, while responses are still produced (RFC 7766, section 6.2.3).
		private readonly CancellationTokenSource _idleCts = new();
		private readonly object _queriesLock = new();
		private int _queriesInProgress;

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
			var stream = await GetStreamFromClientAsync(token).ConfigureAwait(false);
			if (stream == null)
				return false;

			_messageStream = new DnsTcpMessageStream(stream);

			lock (_queriesLock)
				_idleCts.CancelAfter(TaskExtensions.ToTimeout(TransportInternal.KeepAlive));

			return true;
		}

		private void OnQueryReceived()
		{
			lock (_queriesLock)
			{
				if (_queriesInProgress++ == 0)
					_idleCts.CancelAfter(System.Threading.Timeout.InfiniteTimeSpan);
			}
		}

		void IKeepAliveServerConnection.OnQueryFinished()
		{
			// CancelAfter cancels by a timer, also with a delay of 0, so nothing runs inside of the lock
			lock (_queriesLock)
			{
				if (--_queriesInProgress == 0)
					_idleCts.CancelAfter(TaskExtensions.ToTimeout(TransportInternal.KeepAlive));
			}
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

				// Wait for the next query until the keep alive expired, and up to the timeout for the rest of it. Neither the keep
				// alive nor the token cancel the read itself, as canceling closes the stream, but the responses to the queries
				// in progress still have to be sent, before the connection is closed.
				var read = _messageStream.ReadMessageAsync(
					System.Threading.Timeout.InfiniteTimeSpan,
					_idleCts.Token,
					TaskExtensions.ToTimeout(TransportInternal.Timeout),
					CancellationToken.None);

				byte[]? message;
				try
				{
					message = await read.WaitAsync(token).ConfigureAwait(false);
				}
				catch (OperationCanceledException) when (token.IsCancellationRequested)
				{
					// The read ends when the connection is disposed, after the responses were sent.
					// A query, which is received meanwhile, is not processed anymore.
					_ = read.ContinueWith(t => t.Exception, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
					return null;
				}

				if (message == null)
					return null;

				// counted here, so the keep alive cannot expire between receiving the query and processing it
				OnQueryReceived();
				return new DnsReceivedRawPackage(message, remoteEndPoint, localEndPoint);
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
				// A client, which does not read its responses, would otherwise keep the connection and its slot forever. The
				// timeouts of the socket do not apply to asynchronous writes.
				using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token);
				if (TransportInternal.Timeout > 0)
					timeoutCts.CancelAfter(TransportInternal.Timeout);

				// serialized by the message stream, as responses to pipelined queries are sent concurrently
				await _messageStream.WriteMessageAsync(package.ToArraySegment(true), timeoutCts.Token).ConfigureAwait(false);
				return true;
			}
			catch
			{
				// Also a response, which timed out while it waited for the others, is closing the connection. Otherwise the
				// client would wait for it on a connection, which still looks healthy, instead of retrying on a new one.
				_messageStream.Dispose();
				return false;
			}
		}

		/// <summary>
		///   A value indicating if data could be read from the client
		/// </summary>
		public bool CanRead => Client.Connected;

		public void Dispose()
		{
			// Stops the timer of the keep alive. The source is not disposed, as the server may still report finished queries.
			_idleCts.Cancel();

			_messageStream?.Dispose();
			Client.TryDispose();
		}
	}
}