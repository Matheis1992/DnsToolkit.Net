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
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Routing;

namespace DnsToolkit.Net.Dns;

public static class EndpointRouteBuilderExtensions
{
	public delegate Task<DnsMessageBase?> DnsHttpsRequestDelegate(DnsMessageBase query, HttpContext context, CancellationToken token);

	internal delegate Task<DnsRawPackage?> DnsRawPackageDelegate(DnsReceivedRawPackage query, HttpContext context, CancellationToken token);

	/// <summary>
	///   Thrown by a <see cref="DnsRawPackageDelegate" />, if the server does not accept queries anymore, e.g. because it is stopping
	/// </summary>
	internal sealed class ServiceUnavailableException : Exception { }

	public static IEndpointConventionBuilder MapDnsOverHttps(
		this IEndpointRouteBuilder endpoints,
		DnsHttpsRequestDelegate handler)
	{
		return endpoints.MapDnsOverHttps("dns-query", handler);
	}

	public static IEndpointConventionBuilder MapDnsOverHttps(
		this IEndpointRouteBuilder endpoints,
		string pattern,
		DnsHttpsRequestDelegate handler)
	{
		return endpoints.MapDnsOverHttps(pattern, (package, context, token) => HandleRequestAsync(package, context, handler, token));
	}

	private static async Task<DnsRawPackage?> HandleRequestAsync(DnsReceivedRawPackage content, HttpContext ctx, DnsHttpsRequestDelegate handler, CancellationToken token)
	{
		DnsMessageBase dnsQuery;

		try
		{
			dnsQuery = DnsMessageBase.CreateByFlag(content.ToArraySegment(false), null, null);
		}
		catch
		{
			await Results.StatusCode((int) HttpStatusCode.UnprocessableEntity).ExecuteAsync(ctx);
			return null;
		}

		DnsMessageBase? dnsResponse = null;
		try
		{
			dnsResponse = await handler(dnsQuery, ctx, token);
		}
		catch
		{
			// ignored
		}

		return (dnsResponse ?? dnsQuery.CreateFailureResponse()).Encode();
	}

	internal static IEndpointConventionBuilder MapDnsOverHttps(
		this IEndpointRouteBuilder endpoints,
		string pattern,
		DnsRawPackageDelegate handler)
	{
		return endpoints.Map(pattern, (HttpContext ctx, CancellationToken token) => HandleRequestAsync(ctx, token, handler));
	}

	private const string _DOH_CONTENT_TYPE = "application/dns-message";

	/// <summary>
	///   The maximum size of a DNS message, given by its two byte length in the wire format (RFC 8484 section 6)
	/// </summary>
	private const int _MAX_MESSAGE_SIZE = UInt16.MaxValue;

	// internal for the tests, which call it with a simulated request
	internal static async Task HandleRequestAsync(HttpContext ctx, CancellationToken token, DnsRawPackageDelegate handler)
	{
		string? contentType;
		byte[] content;

		if (ctx.Request.Method == HttpMethod.Get.Method)
		{
			var queryText = ctx.Request.Query.TryGetValue("dns", out var queryValues) && queryValues.Count == 1 ? queryValues[0] : null;

			if (String.IsNullOrEmpty(queryText))
			{
				await Results.BadRequest().ExecuteAsync(ctx);
				return;
			}

			try
			{
				var requiredPadding = (4 - queryText.Length % 4) % 4;

				content = (queryText + new string('=', requiredPadding)).FromBase64UrlString(2);
			}
			catch
			{
				await Results.BadRequest().ExecuteAsync(ctx);
				return;
			}

			contentType = _DOH_CONTENT_TYPE;
		}
		else if (ctx.Request.Method == HttpMethod.Post.Method)
		{
			if (ctx.Request.ContentLength > _MAX_MESSAGE_SIZE)
			{
				await Results.StatusCode((int) HttpStatusCode.RequestEntityTooLarge).ExecuteAsync(ctx);
				return;
			}

			// Limit the body before reading it, so a larger body (e.g. without Content-Length) is aborted while
			// reading instead of being buffered completely. A lower limit set for the server is kept.
			var bodySizeFeature = ctx.Features.Get<IHttpMaxRequestBodySizeFeature>();
			if ((bodySizeFeature != null) && !bodySizeFeature.IsReadOnly && !(bodySizeFeature.MaxRequestBodySize < _MAX_MESSAGE_SIZE))
				bodySizeFeature.MaxRequestBodySize = _MAX_MESSAGE_SIZE;

			using var ms = new MemoryStream();

			ms.WriteByte(0);
			ms.WriteByte(0);

			try
			{
				await ctx.Request.Body.CopyToAsync(ms, token);
			}
			catch (BadHttpRequestException ex) when (ex.StatusCode == (int) HttpStatusCode.RequestEntityTooLarge)
			{
				await Results.StatusCode((int) HttpStatusCode.RequestEntityTooLarge).ExecuteAsync(ctx);
				return;
			}

			content = ms.ToArray();

			contentType = ctx.Request.ContentType;
		}
		else
		{
			await Results.StatusCode((int) HttpStatusCode.MethodNotAllowed).ExecuteAsync(ctx);
			return;
		}

		if (contentType != _DOH_CONTENT_TYPE)
		{
			await Results.StatusCode((int) HttpStatusCode.UnsupportedMediaType).ExecuteAsync(ctx);
			return;
		}

		// the content contains the two bytes of the length header
		if (content.Length - 2 > _MAX_MESSAGE_SIZE)
		{
			await Results.StatusCode((int) HttpStatusCode.RequestEntityTooLarge).ExecuteAsync(ctx);
			return;
		}

		var remoteEndpoint = new IPEndPoint(IPAddress.None, 0);
		var localEndpoint = new IPEndPoint(IPAddress.None, 0);

		var httpConnectionFeature = ctx.Features.Get<IHttpConnectionFeature>();
		if (httpConnectionFeature != null)
		{
			remoteEndpoint = new IPEndPoint(httpConnectionFeature.RemoteIpAddress ?? IPAddress.None, httpConnectionFeature.RemotePort);
			localEndpoint = new IPEndPoint(httpConnectionFeature.LocalIpAddress ?? IPAddress.None, httpConnectionFeature.LocalPort);
		}

		DnsMessageBase.EncodeUShort(content, 0, (ushort) (content.Length - 2));
		var receivedPackage = new DnsReceivedRawPackage(content, remoteEndpoint, localEndpoint);

		DnsRawPackage? response;
		try
		{
			response = await handler(receivedPackage, ctx, token);
		}
		catch (ServiceUnavailableException)
		{
			// the client can retry immediately, e.g. with another server
			await Results.StatusCode((int) HttpStatusCode.ServiceUnavailable).ExecuteAsync(ctx);
			return;
		}

		if (response == null)
		{
			await Results.StatusCode((int) HttpStatusCode.InternalServerError).ExecuteAsync(ctx);
		}
		else
		{
			ctx.Response.ContentType = _DOH_CONTENT_TYPE;
			ctx.Response.ContentLength = response.Length;
			ctx.Response.StatusCode = (int) HttpStatusCode.OK;
			await ctx.Response.Body.WriteAsync(response.ToArraySegment(false), token);
		}
	}
}