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

namespace DnsToolkit.Net.Dns;

/// <summary>
///   Abstract implementation of a pipelined client transport. All queries to a server share one connection.
/// </summary>
public abstract class PipelinedClientTransportBase : IClientTransport
{
	private static readonly TimeSpan _idleTimeout = TimeSpan.FromMilliseconds(100);

	private readonly ConnectionPool<SharedPipelinedConnection> _pool = new();
	private readonly int _port;

	/// <summary>
	///   The maximum allowed size of queries in bytes
	/// </summary>
	public abstract ushort MaximumAllowedQuerySize { get; }

	/// <summary>
	///   Returns a value indicating if the transport is reliable
	/// </summary>
	public bool SupportsReliableTransfer => true;

	/// <summary>
	///   Returns a value indicating if the transport supports multicast communication
	/// </summary>
	public bool SupportsMulticastTransfer => false;

	/// <summary>
	///   Returns a value indicating if the transport supports pooled connections
	/// </summary>
	public bool SupportsPooledConnections => true;

	protected PipelinedClientTransportBase(int port)
	{
		_port = port;
	}

	/// <summary>
	///   Creates a new connection to a server
	/// </summary>
	/// <param name="endpointInfo">The endpoint to connect to</param>
	/// <param name="queryTimeout">The query timeout in milliseconds</param>
	/// <param name="token"> The token to monitor cancellation requests </param>
	/// <returns>A connection to the specified server or null, if the connection could not be established</returns>
	public async Task<IClientConnection?> ConnectAsync(DnsClientEndpointInfo endpointInfo, int queryTimeout, CancellationToken token = default)
	{
		if (endpointInfo.IsMulticast)
			throw new NotSupportedException("Multicast is not supported on pipelined transports");

		var address = endpointInfo.DestinationAddress;
		var connection = await _pool.GetOrConnectAsync(address, () => CreateSharedConnectionAsync(endpointInfo, queryTimeout), token).ConfigureAwait(false);

		return connection == null ? null : new PipelinedClientConnection(connection, this);
	}

	private async Task<SharedPipelinedConnection?> CreateSharedConnectionAsync(DnsClientEndpointInfo endpointInfo, int queryTimeout)
	{
		// not canceled by the caller, as the connection is shared by all queries to the server
		var connection = await ConnectInternalAsync(endpointInfo, queryTimeout, CancellationToken.None).ConfigureAwait(false);

		if (connection == null)
			return null;

		// The query, which established the connection, sends its query within its timeout, otherwise it gave up.
		// So an unused connection, e.g. because all its queries were canceled, is closed after it.
		TimeSpan? initialIdleTimeout = queryTimeout > 0 ? Max(TimeSpan.FromMilliseconds(queryTimeout), _idleTimeout) : null;

		var address = endpointInfo.DestinationAddress;
		return new SharedPipelinedConnection(connection, unusable => _pool.Remove(address, unusable), _idleTimeout, initialIdleTimeout);
	}

	private static TimeSpan Max(TimeSpan a, TimeSpan b) => a > b ? a : b;

	protected abstract Task<IPipelineableClientConnection?> ConnectInternalAsync(DnsClientEndpointInfo endpointInfo, int queryTimeout, CancellationToken token);

	/// <summary>
	///   Gets connection from the pool
	/// </summary>
	/// <param name="endpointInfo">The endpoint of the connection</param>
	/// <param name="token"> The token to monitor cancellation requests </param>
	/// <returns>A pooled connection or null, if no connection to the specified endpoint exists in the pool</returns>
	public async Task<IClientConnection?> GetPooledConnectionAsync(DnsClientEndpointInfo endpointInfo, CancellationToken token = default)
	{
		var connection = await _pool.GetPooledAsync(endpointInfo.DestinationAddress, token).ConfigureAwait(false);

		return connection == null ? null : new PipelinedClientConnection(connection, this);
	}

	public void Dispose()
	{
		_pool.Clear();
	}
}
