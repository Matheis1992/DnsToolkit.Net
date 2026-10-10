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
using System.Runtime.InteropServices;

namespace DnsToolkit.Net.Dns;

/// <summary>
///   A transport used by a server using udp communication
/// </summary>
public class UdpServerTransport : IServerTransport
{
	/// <summary>
	///   The default port of UDP DNS communication
	/// </summary>
	public const int DEFAULT_PORT = 53;

	private readonly IPEndPoint _endpoint;
	private readonly int _timeout;

	private readonly object _lock = new();
	private bool _isDisposed;

	// A closed socket cannot be bound again, so every bind creates a new one. Null, if the transport is not bound.
	private Socket? _socket;

	/// <summary>
	///   The default allowed response size if no EDNS option is set.
	/// </summary>
	public ushort DefaultAllowedResponseSize => 512;

	/// <summary>
	///   A value indicating, if the transport supports sending multiple response to a single query.
	/// </summary>
	public bool SupportsMultipleResponses => false;

	/// <summary>
	///   A value indicating, if truncated responses are allowed using this transport.
	/// </summary>
	public bool AllowTruncatedResponses => true;

	/// <summary>
	///   The transport protocol this transport is using
	/// </summary>
	public TransportProtocol TransportProtocol => TransportProtocol.Udp;

	/// <summary>
	///   Creates a new instance of the UdpServerTransport
	/// </summary>
	/// <param name="bindAddress">The IP address on which the transport should listen</param>
	/// <param name="timeout">The read an write timeout in milliseconds</param>
	public UdpServerTransport(IPAddress bindAddress, int timeout = 5000)
		: this(new IPEndPoint(bindAddress, DEFAULT_PORT), timeout) { }

	/// <summary>
	///   Creates a new instance of the UdpServerTransport
	/// </summary>
	/// <param name="endpoint">The IP endpoint on which the transport should listen</param>
	/// <param name="timeout">The read an write timeout in milliseconds</param>
	public UdpServerTransport(IPEndPoint endpoint, int timeout = 5000)
	{
		_endpoint = endpoint;
		_timeout = timeout;
		_anyEndPoint = new IPEndPoint(endpoint.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);
	}

	private readonly IPEndPoint _anyEndPoint;

	private Socket CreateSocket()
	{
		var socket = new Socket(_endpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);

		try
		{
			if (_endpoint.Address.Equals(IPAddress.IPv6Any))
				socket.DualMode = true;

			DisableConnectionResetReporting(socket);
			return socket;
		}
		catch
		{
			socket.Dispose();
			throw;
		}
	}

	/// <summary>
	///   On Windows an ICMP port unreachable for a sent response, e.g. because the client already closed its socket,
	///   fails the next receive of the socket. For a server socket shared by all clients this must be disabled.
	/// </summary>
	private static void DisableConnectionResetReporting(Socket socket)
	{
		if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
			return;

		const int SIO_UDP_CONNRESET = -1744830452;

		try
		{
			socket.IOControl(SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);
		}
		catch (SocketException)
		{
			// not supported, the error is also handled on receive
		}
	}

	/// <summary>
	///   Binds the transport to the network stack. After the transport was closed, it can be bound again.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The transport was disposed</exception>
	/// <exception cref="InvalidOperationException">The transport is already bound</exception>
	public void Bind()
	{
		lock (_lock)
		{
			if (_isDisposed)
				throw new ObjectDisposedException(GetType().FullName);

			if (_socket != null)
				throw new InvalidOperationException("The transport is already bound");

			var socket = CreateSocket();

			try
			{
				socket.Bind(_endpoint);
			}
			catch
			{
				socket.Dispose();
				throw;
			}

			_socket = socket;
		}
	}

	/// <summary>
	///   Closes the transport
	/// </summary>
	public void Close()
	{
		TakeSocket()?.Close();
	}

	/// <summary>
	///   Ends the current binding, so the transport can be bound again
	/// </summary>
	private Socket? TakeSocket(bool dispose = false)
	{
		lock (_lock)
		{
			if (dispose)
				_isDisposed = true;

			var socket = _socket;
			_socket = null;
			return socket;
		}
	}

	/// <summary>
	///   Waits for a new connection and return the connection
	/// </summary>
	/// <param name="token"> The token to monitor cancellation requests </param>
	/// <returns>A new connection to a client, or null if the token was cancelled</returns>
	/// <exception cref="SocketException">The socket failed, e.g. because it was closed</exception>
	/// <exception cref="InvalidOperationException">The transport is not bound</exception>
	public async Task<IServerConnection?> AcceptConnectionAsync(CancellationToken token = default)
	{
		var socket = Volatile.Read(ref _socket) ?? throw new InvalidOperationException("The transport is not bound");

		// Errors which only concern a single datagram are handled here by receiving the next one,
		// so the server only sees errors of the socket itself
		while (true)
		{
			var buffer = UdpReceiveBuffer.Rent();
			Task<SocketReceiveMessageFromResult>? receiveTask = null;

			try
			{
#if NETSTANDARD2_0
				// this receive cannot be cancelled, so only the waiting is cancelled
				receiveTask = socket.ReceiveMessageFromAsync(UdpReceiveBuffer.GetReceiveSegment(buffer), SocketFlags.None, _anyEndPoint);
				var result = await receiveTask.WaitAsync(token);
#else
				receiveTask = socket.ReceiveMessageFromAsync(UdpReceiveBuffer.GetReceiveSegment(buffer), SocketFlags.None, _anyEndPoint, token).AsTask();
				var result = await receiveTask;
#endif

				return new UdpServerConnection(
					this,
					new DnsReceivedRawPackage(UdpReceiveBuffer.CopyMessage(buffer, result.ReceivedBytes), (IPEndPoint) result.RemoteEndPoint, _endpoint),
					socket,
					_timeout);
			}
			catch (SocketException ex) when (IsDatagramError(ex.SocketErrorCode))
			{
				// receive the next datagram
			}
			catch (OperationCanceledException) when (token.IsCancellationRequested)
			{
				return null;
			}
			finally
			{
				// a receive which is still pending may write into the buffer, so it is only returned if the receive is done
				UdpReceiveBuffer.Return(buffer, receiveTask);
			}
		}
	}

	/// <summary>
	///   Errors of a single datagram, e.g. an ICMP message for a previously sent response or a datagram larger than the buffer
	/// </summary>
	private static bool IsDatagramError(SocketError error)
	{
		return error is SocketError.ConnectionReset
			or SocketError.MessageSize
			or SocketError.NetworkReset
			or SocketError.HostUnreachable
			or SocketError.NetworkUnreachable;
	}

	public void Dispose()
	{
		TakeSocket(dispose: true)?.TryDispose();
	}

	private class UdpServerConnection : IServerConnection
	{
		private readonly UdpServerTransport _transport;
		private readonly Socket _socket;
		private readonly int _timeout;
		private readonly DnsReceivedRawPackage _receivedRawPackage;

		public UdpServerConnection(UdpServerTransport transport, DnsReceivedRawPackage receivedRawPackage, Socket socket, int timeout)
		{
			_transport = transport;
			_receivedRawPackage = receivedRawPackage;
			_socket = socket;
			_timeout = timeout;
		}

		public IServerTransport Transport => _transport;

		public Task<bool> InitializeAsync(CancellationToken token)
		{
			return Task.FromResult(true);
		}

		public Task<DnsReceivedRawPackage?> ReceiveAsync(CancellationToken token)
		{
			CanRead = false;
			return Task.FromResult<DnsReceivedRawPackage?>(_receivedRawPackage);
		}

		public async Task<bool> SendAsync(DnsRawPackage package, CancellationToken token = new())
		{
			try
			{
				var sentBytes = await _socket.SendToAsync(package.ToArraySegment(false), SocketFlags.None, _receivedRawPackage.RemoteEndpoint, token).AsTask().WithTimeout(_timeout, token);

				return sentBytes == package.Length;
			}
			catch
			{
				return false;
			}
		}

		public IPEndPoint RemoteEndPoint => _receivedRawPackage.RemoteEndpoint;

		public IPEndPoint LocalEndPoint => _receivedRawPackage.LocalEndpoint;

		public bool CanRead { get; private set; } = true;

		public void Dispose() { }
	}
}