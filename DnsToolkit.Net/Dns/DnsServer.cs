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

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DnsToolkit.Net.Dns
{
	/// <summary>
	///   Provides a base dns server interface
	/// </summary>
	public class DnsServer : IDisposable, IAsyncDisposable
	{
		/// <summary>
		///   Represents the method, that will be called to get the keydata for processing a tsig signed message
		/// </summary>
		/// <param name="algorithm"> The algorithm which is used in the message </param>
		/// <param name="isTruncated"> A value indicating if the MAC was truncated </param>
		/// <param name="keyName"> The keyname which is used in the message </param>
		/// <returns> Binary representation of the key </returns>
		public delegate byte[]? SelectTsigKey(TSigAlgorithm algorithm, bool isTruncated, DomainName keyName);

		public const int DEFAULT_DNS_PORT = 53;

		private readonly IServerTransport[] _transports;
		private Task[] _transportTasks = Array.Empty<Task>();
		// canceled when stopping: no further connections are accepted and no further queries are read
		private CancellationTokenSource _serverCancellationTokenSource = new();

		// canceled when stopping is no longer graceful: the responses to the queries in progress are not sent anymore
		private CancellationTokenSource _abortCancellationTokenSource = new();

		private readonly ActiveConnections _activeConnections = new();

		private static readonly TimeSpan _stopTimeout = TimeSpan.FromSeconds(5);

		/// <summary>
		///   Method that will be called to get the keydata for processing a tsig signed message
		/// </summary>
		public SelectTsigKey? TsigKeySelector;

		/// <summary>
		///   Creates a new dns server instance which will listen on UDP and TCP on all available interfaces
		/// </summary>
		/// <param name="timeout"> The timeout in milliseconds </param>
		/// <param name="keepAlive"> The keepalive period in milliseconds to wait for additional queries on the same connection </param>
		public DnsServer(int timeout = 5000, int keepAlive = 120000)
			: this(
				new UdpServerTransport(IPAddress.IPv6Any, timeout),
				new TcpServerTransport(IPAddress.IPv6Any, timeout, keepAlive)) { }

		/// <summary>
		///   Creates a new dns server instance
		/// </summary>
		/// <param name="transports"> Transports, which should be used </param>
		public DnsServer(params IServerTransport[] transports)
		{
			if (transports.Length == 0)
				throw new ArgumentException("At least one transport must be given");

			_transports = transports;
		}

		/// <summary>
		///   Starts the server
		/// </summary>
		/// <summary>
		///   The maximum number of connections each transport processes at the same time. For UDP every query counts
		///   as a connection. If the limit is reached, a transport accepts the next connection only after another one
		///   was closed, so clients wait in the backlog of the operating system. The limit applies to each transport
		///   separately, so e.g. idle TCP connections cannot block UDP. It has to be set before the server is started.
		///   Default: 1000
		/// </summary>
		public int MaxConcurrentConnectionsPerTransport
		{
			get => _maxConcurrentConnectionsPerTransport;
			set
			{
				if (value < 1)
					throw new ArgumentOutOfRangeException(nameof(value), "At least one connection has to be allowed");

				_maxConcurrentConnectionsPerTransport = value;
			}
		}

		private int _maxConcurrentConnectionsPerTransport = 1000;

		public void Start()
		{
			foreach (var transport in _transports)
			{
				transport.Bind();
			}

			_serverCancellationTokenSource = new CancellationTokenSource();
			_abortCancellationTokenSource = new CancellationTokenSource();

			var token = _serverCancellationTokenSource.Token;
			var abortToken = _abortCancellationTokenSource.Token;
			var maxConnections = MaxConcurrentConnectionsPerTransport;
			_transportTasks = _transports.Select(t => Task.Run(() => ConnectionLoopAsync(t, maxConnections, token, abortToken))).ToArray();
		}

		/// <summary>
		///   Stops the server gracefully: no further connections and queries are accepted, idle connections are closed
		///   immediately and the queries in progress are answered, before the transports are closed. If this takes
		///   longer than 5 seconds, the remaining connections are aborted.
		/// </summary>
		public void Stop()
		{
			using var timeoutCts = new CancellationTokenSource(_stopTimeout);

			try
			{
				// The stop does not continue on the context of the caller, so blocking here cannot deadlock
				StopCoreAsync(isAsync: false, timeoutCts.Token).GetAwaiter().GetResult();
			}
			catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
			{
				// the remaining connections were aborted
			}
		}

		/// <summary>
		///   Stops the server gracefully: no further connections and queries are accepted, idle connections are closed
		///   immediately and the queries in progress are answered, before the transports are closed.
		/// </summary>
		/// <param name="token">
		///   The token to indicate, that stopping should no longer be graceful. The remaining connections are aborted
		///   then and the transports are closed immediately.
		/// </param>
		/// <exception cref="OperationCanceledException">The token was canceled, so the server was not stopped gracefully</exception>
		public Task StopAsync(CancellationToken token = default)
		{
			return StopCoreAsync(isAsync: true, token);
		}

		private async Task StopCoreAsync(bool isAsync, CancellationToken token)
		{
			// no further connections are accepted and no further queries are read, so idle connections are closed
			_serverCancellationTokenSource.Cancel();

			var isGraceful = false;
			try
			{
				// the transports are still open, so the queries in progress can be answered
				await WhenNoConnectionsAsync(_transportTasks, _activeConnections).WaitAsync(token).ConfigureAwait(false);
				isGraceful = true;
			}
			finally
			{
				if (!isGraceful)
				{
					_abortCancellationTokenSource.Cancel();
					_activeConnections.DisposeAll();
				}

				await CloseTransportsAsync(isAsync, token).ConfigureAwait(false);
			}
		}

		private static async Task WhenNoConnectionsAsync(Task[] transportTasks, ActiveConnections activeConnections)
		{
			// no connection is added after the connection loops ended
			await Task.WhenAll(transportTasks).ConfigureAwait(false);
			await activeConnections.WhenNoneAsync().ConfigureAwait(false);
		}

		private async Task CloseTransportsAsync(bool isAsync, CancellationToken token)
		{
			foreach (var transport in _transports)
			{
				if (isAsync && (transport is IAsyncClosableServerTransport asyncTransport))
				{
					await asyncTransport.CloseAsync(token).ConfigureAwait(false);
				}
				else
				{
					transport.Close();
				}
			}
		}

		/// <summary>
		///   The connections in progress of all transports
		/// </summary>
		private sealed class ActiveConnections
		{
			private readonly HashSet<IServerConnection> _connections = new();
			private TaskCompletionSource<bool>? _none;

			public void Add(IServerConnection connection)
			{
				lock (_connections)
				{
					_connections.Add(connection);
				}
			}

			public void Remove(IServerConnection connection)
			{
				TaskCompletionSource<bool>? none = null;

				lock (_connections)
				{
					if (_connections.Remove(connection) && (_connections.Count == 0))
					{
						none = _none;
						_none = null;
					}
				}

				none?.TrySetResult(true);
			}

			public Task WhenNoneAsync()
			{
				lock (_connections)
				{
					if (_connections.Count == 0)
						return Task.CompletedTask;

					return (_none ??= new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously)).Task;
				}
			}

			/// <summary>
			///   Aborts all connections, so pending reads and writes end. The connections are removed once their processing ended.
			/// </summary>
			public void DisposeAll()
			{
				List<IServerConnection> connections;
				lock (_connections)
				{
					connections = _connections.ToList();
				}

				foreach (var connection in connections)
					connection.TryDispose();
			}
		}

		private async Task ConnectionLoopAsync(IServerTransport transport, int maxConnections, CancellationToken token, CancellationToken abortToken)
		{
			var failedAcceptCount = 0;

			// One slot per connection in progress. It is not disposed, as connections may still release their slot after the loop ended.
			var connectionSlots = new SemaphoreSlim(maxConnections, maxConnections);

			while (!token.IsCancellationRequested)
			{
				try
				{
					// wait for a free slot before accepting, so the backlog of the operating system holds further clients
					await connectionSlots.WaitAsync(token);
				}
				catch (OperationCanceledException)
				{
					break;
				}

				IServerConnection? connection;

				try
				{
					connection = await transport.AcceptConnectionAsync(token);
				}
				catch (Exception) when (token.IsCancellationRequested)
				{
					// the server is stopping, the transport may fail as it is closed
					connectionSlots.Release();
					break;
				}
				catch (Exception ex)
				{
					OnExceptionThrownAsync(ex);
					connection = null;
				}

				if (connection == null)
				{
					connectionSlots.Release();

					// The transports handle errors of single clients themselves, so this is a failure of the transport itself.
					// A transport which fails permanently fails immediately again, so wait longer after each failure.
					try
					{
						await Task.Delay(GetFailedAcceptDelay(++failedAcceptCount), token);
					}
					catch (OperationCanceledException)
					{
						break;
					}

					continue;
				}

				failedAcceptCount = 0;

				// tracked until it is disposed, so stopping the server can wait for it or abort it
				_activeConnections.Add(connection);

				// Not bound to the token, as the connection has to be disposed and its slot released in any case
				_ = Task.Run(() => ProcessConnectionAsync(connection, () =>
				{
					connectionSlots.Release();
					_activeConnections.Remove(connection);
				}, token, abortToken));
			}
		}

		private static readonly TimeSpan _maxFailedAcceptDelay = TimeSpan.FromMilliseconds(100);

		/// <summary>
		///   The delay after consecutive failed accepts: none after the first failure, then 1 ms doubled with each failure,
		///   up to 100 ms. A single failure costs nothing, a transport which fails permanently is retried ten times a second.
		/// </summary>
		internal static TimeSpan GetFailedAcceptDelay(int failedAcceptCount)
		{
			if (failedAcceptCount <= 1)
				return TimeSpan.Zero;

			// 2^(count - 2) ms, the exponent is limited to avoid an overflow
			var delay = TimeSpan.FromMilliseconds(1 << Math.Min(failedAcceptCount - 2, 16));
			return delay < _maxFailedAcceptDelay ? delay : _maxFailedAcceptDelay;
		}

		private class RefCountDispose
		{
			private int _count = 0;
			private int _isDisposed = 0;
			private readonly IDisposable _disposable;
			private readonly Action _onDisposed;

			public RefCountDispose(IDisposable disposable, Action onDisposed)
			{
				_disposable = disposable;
				_onDisposed = onDisposed;
			}

			public void Increment()
			{
				Interlocked.Increment(ref _count);
			}

			public void Decrement()
			{
				if ((Interlocked.Decrement(ref _count) <= 0) && (Interlocked.Exchange(ref _isDisposed, 1) == 0))
				{
					_disposable.TryDispose();
					_onDisposed();
				}
			}
		}

		private async Task ProcessConnectionAsync(IServerConnection connection, Action onDisposed, CancellationToken token, CancellationToken abortToken)
		{
			// The receive loop holds one reference and every query in progress holds another one,
			// so the connection is disposed after the loop ended and all queries are answered
			var refCount = new RefCountDispose(connection, onDisposed);
			refCount.Increment();

			try
			{
				var clientConnectedEventArgs = new ClientConnectedEventArgs(connection.Transport.TransportProtocol, connection.RemoteEndPoint, connection.LocalEndPoint);
				await ClientConnected.RaiseAsync(this, clientConnectedEventArgs);

				if (clientConnectedEventArgs.RefuseConnect)
					return;

				if (!await connection.InitializeAsync(token))
					return;

				while (connection.CanRead)
				{
					var queryPackage = await connection.ReceiveAsync(token);

					if (queryPackage == null)
						break;

					refCount.Increment();

					// Not bound to a token, as ProcessRawPackageAsync has to release its reference in any case.
					// It sends the response also while the server is stopping, only aborting the stop cancels it.
					_ = Task.Run(() => ProcessRawPackageAsync(connection, queryPackage, refCount, abortToken));
				}
			}
			catch (Exception ex)
			{
				OnExceptionThrownAsync(ex);
			}
			finally
			{
				refCount.Decrement();
			}
		}

		private async Task ProcessRawPackageAsync(IServerConnection connection, DnsReceivedRawPackage queryPackage, RefCountDispose refCount, CancellationToken abortToken)
		{
			try
			{
				DnsMessageBase query;
				byte[]? tsigMac;
				try
				{
					query = DnsMessageBase.CreateByFlag(queryPackage.ToArraySegment(false), TsigKeySelector, null);
					tsigMac = query.TSigOptions?.Mac;
				}
				catch (Exception e)
				{
					throw new Exception("Error parsing dns query", e);
				}

				DnsMessageBase response;
				try
				{
					response = await ProcessMessageAsync(query, connection.Transport.TransportProtocol, connection.RemoteEndPoint!);
				}
				catch (Exception ex)
				{
					OnExceptionThrownAsync(ex);

					response = query.CreateFailureResponse();
				}

				var responsePackage = response.Encode(tsigMac, false, out var newTsigMac);

				if (responsePackage.Length <= connection.Transport.DefaultAllowedResponseSize)
				{
					await connection.SendAsync(responsePackage, abortToken);
				}
				else
				{
					if (response.AllowMultipleResponses && connection.Transport.SupportsMultipleResponses)
					{
						var isSubSequentResponse = false;

						foreach (var partialResponse in response.SplitResponse())
						{
							responsePackage = partialResponse.Encode(tsigMac, isSubSequentResponse, out newTsigMac);
							await connection.SendAsync(responsePackage, abortToken);
							isSubSequentResponse = true;
							tsigMac = newTsigMac;
						}
					}
					else if (connection.Transport.AllowTruncatedResponses)
					{
						#region Truncating
						if (response is DnsMessage message)
						{
							int maxLength = connection.Transport.DefaultAllowedResponseSize;
							if (query.IsEDnsEnabled && message.IsEDnsEnabled)
							{
								maxLength = Math.Max(connection.Transport.DefaultAllowedResponseSize, (int) message.EDnsOptions!.UdpPayloadSize);
							}

							while (responsePackage.Length > maxLength)
							{
								// First step: remove data from additional records except the opt record
								if ((message.IsEDnsEnabled && (message.AdditionalRecords.Count > 1)) || (!message.IsEDnsEnabled && (message.AdditionalRecords.Count > 0)))
								{
									for (var i = message.AdditionalRecords.Count - 1; i >= 0; i--)
									{
										if (message.AdditionalRecords[i].RecordType != RecordType.Opt)
										{
											message.AdditionalRecords.RemoveAt(i);
										}
									}

									responsePackage = message.Encode(tsigMac);
									continue;
								}

								var savedLength = 0;
								if (message.AuthorityRecords.Count > 0)
								{
									for (var i = message.AuthorityRecords.Count - 1; i >= 0; i--)
									{
										savedLength += message.AuthorityRecords[i].MaximumLength;
										message.AuthorityRecords.RemoveAt(i);

										if ((responsePackage.Length - savedLength) < maxLength)
										{
											break;
										}
									}

									message.IsTruncated = true;

									responsePackage = message.Encode(tsigMac);
									continue;
								}

								if (message.AnswerRecords.Count > 0)
								{
									for (var i = message.AnswerRecords.Count - 1; i >= 0; i--)
									{
										savedLength += message.AnswerRecords[i].MaximumLength;
										message.AnswerRecords.RemoveAt(i);

										if ((responsePackage.Length - savedLength) < maxLength)
										{
											break;
										}
									}

									message.IsTruncated = true;

									responsePackage = message.Encode(tsigMac);
									continue;
								}

								if (message.Questions.Count > 0)
								{
									for (var i = message.Questions.Count - 1; i >= 0; i--)
									{
										savedLength += message.Questions[i].MaximumLength;
										message.Questions.RemoveAt(i);

										if ((responsePackage.Length - savedLength) < maxLength)
										{
											break;
										}
									}

									message.IsTruncated = true;

									responsePackage = message.Encode(tsigMac);
								}
							}
						}
						#endregion

						await connection.SendAsync(responsePackage, abortToken);
					}
					else
					{
						OnExceptionThrownAsync(new ArgumentException("The length of the serialized response is greater than 65,535 bytes"));

						response = query.CreateFailureResponse();

						responsePackage = response.Encode(tsigMac, false, out newTsigMac);
						await connection.SendAsync(responsePackage, abortToken);
					}
				}

				// Since support for multiple tsig signed messages is not finished, just close connection after response to first signed query
				if (newTsigMac != null)
					connection.Dispose();
			}
			catch (Exception ex)
			{
				OnExceptionThrownAsync(ex);
			}
			finally
			{
				refCount.Decrement();
			}
		}

		private async Task<DnsMessageBase> ProcessMessageAsync(DnsMessageBase query, TransportProtocol transportProtocol, IPEndPoint remoteEndpoint)
		{
			if (query.TSigOptions != null)
			{
				switch (query.TSigOptions.ValidationResult)
				{
					case ReturnCode.FormatError:
					{
						var response = query.CreateFailureResponse();
						response.ReturnCode = ReturnCode.FormatError;
						response.TSigOptions = null;

#pragma warning disable 4014
						InvalidSignedMessageReceived.RaiseAsync(this, new InvalidSignedMessageEventArgs(query, transportProtocol, remoteEndpoint));
#pragma warning restore 4014

						return response;
					}

					case ReturnCode.BadKey:
					case ReturnCode.BadSig:
					case ReturnCode.BadTrunc:
					{
						var response = query.CreateFailureResponse();
						response.ReturnCode = ReturnCode.NotAuthoritive;
						response.TSigOptions = new TSigRecord(query.TSigOptions.Name, query.TSigOptions.Algorithm, query.TSigOptions.TimeSigned, query.TSigOptions.Fudge, query.TSigOptions.OriginalID, query.TSigOptions.ValidationResult, null, null);

#pragma warning disable 4014
						InvalidSignedMessageReceived.RaiseAsync(this, new InvalidSignedMessageEventArgs(query, transportProtocol, remoteEndpoint));
#pragma warning restore 4014

						return response;
					}

					case ReturnCode.BadTime:
					{
						var otherData = new byte[6];
						var tmp = 0;
						TSigRecord.EncodeDateTime(otherData, ref tmp, DateTime.Now);

						var response = query.CreateFailureResponse();
						response.ReturnCode = ReturnCode.NotAuthoritive;
						response.TSigOptions = new TSigRecord(query.TSigOptions.Name, query.TSigOptions.Algorithm, query.TSigOptions.TimeSigned, query.TSigOptions.Fudge, query.TSigOptions.OriginalID, query.TSigOptions.ValidationResult, otherData, null);

#pragma warning disable 4014
						InvalidSignedMessageReceived.RaiseAsync(this, new InvalidSignedMessageEventArgs(query, transportProtocol, remoteEndpoint));
#pragma warning restore 4014

						return response;
					}
				}
			}

			QueryReceivedEventArgs eventArgs = new QueryReceivedEventArgs(query, transportProtocol, remoteEndpoint);
			await QueryReceived.RaiseAsync(this, eventArgs);
			return eventArgs.Response ?? query.CreateFailureResponse();
		}

		private void OnExceptionThrownAsync(Exception e)
		{
			if (e is ObjectDisposedException)
				return;

			Trace.TraceError("Exception in DnsServer: " + e);
			ExceptionThrown.RaiseAsync(this, new ExceptionEventArgs(e));
		}

		/// <summary>
		///   This event is fired on exceptions of the listeners. You can use it for custom logging.
		/// </summary>
		public event AsyncEventHandler<ExceptionEventArgs>? ExceptionThrown;

		/// <summary>
		///   This event is fired whenever a message is received, that is not correct signed
		/// </summary>
		public event AsyncEventHandler<InvalidSignedMessageEventArgs>? InvalidSignedMessageReceived;

		/// <summary>
		///   This event is fired whenever a client connects to the server
		/// </summary>
		public event AsyncEventHandler<ClientConnectedEventArgs>? ClientConnected;

		/// <summary>
		///   This event is fired whenever a query is received by the server
		/// </summary>
		public event AsyncEventHandler<QueryReceivedEventArgs>? QueryReceived;

		/// <summary>
		///   Stops the server like <see cref="Stop" /> and disposes the transports
		/// </summary>
		void IDisposable.Dispose()
		{
			Stop();

			foreach (var transport in _transports)
			{
				transport.TryDispose();
			}
		}

		/// <summary>
		///   Stops the server like <see cref="StopAsync" /> and disposes the transports
		/// </summary>
		async ValueTask IAsyncDisposable.DisposeAsync()
		{
			await StopAsync().ConfigureAwait(false);

			foreach (var transport in _transports)
			{
				try
				{
					if (transport is IAsyncDisposable asyncDisposable)
					{
						await asyncDisposable.DisposeAsync().ConfigureAwait(false);
					}
					else
					{
						transport.Dispose();
					}
				}
				catch
				{
					// like TryDispose, disposing must not fail
				}
			}
		}
	}
}