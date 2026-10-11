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

namespace DnsToolkit.Net.Dns;

/// <summary>
///   A connection with a keep alive, which only runs while no query is in progress (RFC 7766, section 6.2.3). The connection
///   counts the queries it receives, the server reports when each of them is finished.
/// </summary>
internal interface IKeepAliveServerConnection
{
	/// <summary>
	///   Called by the server, once the response to a query of the connection was sent or the query failed
	/// </summary>
	void OnQueryFinished();
}
