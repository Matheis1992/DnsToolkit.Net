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
///   A server transport, which can be closed without blocking a thread. It is optional, so existing transports keep working:
///   <see cref="DnsServer.StopAsync" /> uses <see cref="CloseAsync" /> of the transports implementing it and
///   <see cref="IServerTransport.Close" /> of all other transports.
/// </summary>
public interface IAsyncClosableServerTransport : IServerTransport
{
	/// <summary>
	///   Closes the transport
	/// </summary>
	/// <param name="token">The token to indicate, that closing should no longer be graceful</param>
	Task CloseAsync(CancellationToken token = default);
}
