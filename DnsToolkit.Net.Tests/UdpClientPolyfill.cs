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

#if NETFRAMEWORK
using System.Net.Sockets;

namespace DnsToolkit.Net.Tests;

/// <summary>
///   UdpClient.ReceiveAsync(CancellationToken) of .NET 6 for the tests on net48, so the tests pass the token of the test on
///   every target framework
/// </summary>
internal static class UdpClientPolyfill
{
	public static ValueTask<UdpReceiveResult> ReceiveAsync(this UdpClient client, CancellationToken token)
	{
		return new ValueTask<UdpReceiveResult>(client.ReceiveAsync().WaitAsync(token));
	}
}
#endif
