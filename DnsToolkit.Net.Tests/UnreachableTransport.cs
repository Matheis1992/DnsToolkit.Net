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

using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

/// <summary>
///   A transport, which can connect to no server, and counts how often it is disposed
/// </summary>
internal sealed class UnreachableTransport : IClientTransport
{
	private int _connectCount;
	private int _disposeCount;

	public int ConnectCount => Volatile.Read(ref _connectCount);
	public int DisposeCount => Volatile.Read(ref _disposeCount);

	public ushort MaximumAllowedQuerySize => UInt16.MaxValue;
	public bool SupportsReliableTransfer => true;
	public bool SupportsMulticastTransfer => false;
	public bool SupportsPooledConnections => false;

	public Task<IClientConnection?> ConnectAsync(DnsClientEndpointInfo endpointInfo, int queryTimeout, CancellationToken token = default)
	{
		Interlocked.Increment(ref _connectCount);
		return Task.FromResult<IClientConnection?>(null);
	}

	public Task<IClientConnection?> GetPooledConnectionAsync(DnsClientEndpointInfo endpointInfo, CancellationToken token = default)
		=> Task.FromResult<IClientConnection?>(null);

	public void Dispose() => Interlocked.Increment(ref _disposeCount);
}
