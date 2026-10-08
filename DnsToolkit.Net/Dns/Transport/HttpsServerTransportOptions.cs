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
using System.Security.Authentication;
using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace DnsToolkit.Net.Dns;

/// <summary>
///   Settings of a <see cref="HttpsServerTransport" />. Every setting which is not set keeps its default.
///   The DNS over HTTPS server only uses these settings, it does not read the configuration of the hosting application.
/// </summary>
public class HttpsServerTransportOptions
{
	private int _port = 443;
	private string _path = "dns-query";
	private TimeSpan _shutdownTimeout = TimeSpan.FromSeconds(5);

	/// <summary>
	///   The IP address on which the server listens. Default: null, which means all interfaces
	/// </summary>
	public IPAddress? Address { get; set; }

	/// <summary>
	///   The port on which the server listens. Default: 443
	/// </summary>
	public int Port
	{
		get => _port;
		set
		{
			if ((value < 0) || (value > UInt16.MaxValue))
				throw new ArgumentOutOfRangeException(nameof(value), "The port must be between 0 and 65535");

			_port = value;
		}
	}

	/// <summary>
	///   The path of the DNS over HTTPS endpoint. Default: dns-query
	/// </summary>
	public string Path
	{
		get => _path;
		set
		{
			if (String.IsNullOrWhiteSpace(value))
				throw new ArgumentException("The path must not be empty", nameof(value));

			_path = value;
		}
	}

	/// <summary>
	///   The enabled TLS protocols. Default: TLS 1.2 and TLS 1.3
	/// </summary>
	public SslProtocols SslProtocols { get; set; } = SslProtocols.Tls12 | SslProtocols.Tls13;

	/// <summary>
	///   The time requests in progress get to complete, when the server is stopped. Default: 5 seconds
	/// </summary>
	public TimeSpan ShutdownTimeout
	{
		get => _shutdownTimeout;
		set
		{
			if (value < TimeSpan.Zero)
				throw new ArgumentOutOfRangeException(nameof(value), "The shutdown timeout must not be negative");

			_shutdownTimeout = value;
		}
	}

	/// <summary>
	///   The maximum number of open HTTP connections. If it is reached, further connections are closed immediately.
	///   With HTTP/2 a client can send many queries on one connection. Null means no limit. Default: 1000
	/// </summary>
	public long? MaxConcurrentConnections
	{
		get => _maxConcurrentConnections;
		set
		{
			if (value < 1)
				throw new ArgumentOutOfRangeException(nameof(value), "At least one connection has to be allowed");

			_maxConcurrentConnections = value;
		}
	}

	private long? _maxConcurrentConnections = 1000;

	/// <summary>
	///   Configures further settings of the Kestrel web server, e.g. limits or HTTP/2 settings.
	///   It is called after the other settings are applied, so it can also change them. Default: null
	/// </summary>
	public Action<KestrelServerOptions>? ConfigureKestrel { get; set; }
}
