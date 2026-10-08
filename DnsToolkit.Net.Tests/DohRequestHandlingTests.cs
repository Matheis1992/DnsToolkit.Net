#if !NETFRAMEWORK
using System.Net;
using DnsToolkit.Net.Dns;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;

namespace DnsToolkit.Net.Tests;

/// <summary>
///   Tests the DNS over HTTPS endpoint with simulated requests, without web server and network
/// </summary>
public class DohRequestHandlingTests
{
	private const int MaxMessageSize = 65535;
	private static readonly DomainName _name = DomainName.Parse("host.example.test");

	[Fact]
	public async Task ContentLengthAboveMaximum_IsRejected_WithoutReadingTheBody()
	{
		var body = new SimulatedBody(new byte[70_000]);
		var request = CreatePostRequest(body, contentLength: 70_000);

		await HandleAsync(request);

		Assert.Equal(StatusCodes.Status413PayloadTooLarge, request.Context.Response.StatusCode);
		Assert.Equal(0, body.BytesRead);
		Assert.Null(request.ReceivedQuery);
	}

	[Fact]
	public async Task BodySizeLimit_IsLoweredToDnsMaximum_BeforeReading()
	{
		var body = new SimulatedBody(Query(0x1111));
		var request = CreatePostRequest(body, bodySizeLimit: 30_000_000);
		body.OnFirstRead = () => request.BodySizeLimitAtFirstRead = request.BodySizeFeature.MaxRequestBodySize;

		await HandleAsync(request);

		Assert.Equal(MaxMessageSize, request.BodySizeLimitAtFirstRead);
		Assert.Equal(StatusCodes.Status200OK, request.Context.Response.StatusCode);
	}

	[Fact]
	public async Task LowerBodySizeLimitOfTheServer_IsKept()
	{
		// e.g. set by HttpsServerTransportOptions.ConfigureKestrel, the query of about 30 bytes exceeds it
		var body = new SimulatedBody(Query(0x1111));
		var request = CreatePostRequest(body, bodySizeLimit: 10);

		await HandleAsync(request);

		Assert.Equal(10, request.BodySizeFeature.MaxRequestBodySize);
		Assert.Equal(StatusCodes.Status413PayloadTooLarge, request.Context.Response.StatusCode);
		Assert.Null(request.ReceivedQuery);
	}

	[Fact]
	public async Task ReadOnlyBodySizeLimit_IsNotChanged()
	{
		var body = new SimulatedBody(Query(0x1111));
		var request = CreatePostRequest(body, bodySizeLimit: 30_000_000, isBodySizeLimitReadOnly: true);

		await HandleAsync(request);

		Assert.Equal(30_000_000, request.BodySizeFeature.MaxRequestBodySize);
		Assert.Equal(StatusCodes.Status200OK, request.Context.Response.StatusCode);
	}

	[Fact]
	public async Task BodyExceedingTheLimitWhileReading_IsRejected()
	{
		// a chunked body has no Content-Length, so the size is only known while reading
		var body = new SimulatedBody(new byte[70_000]);
		var request = CreatePostRequest(body, bodySizeLimit: 30_000_000);

		await HandleAsync(request);

		Assert.Equal(StatusCodes.Status413PayloadTooLarge, request.Context.Response.StatusCode);
		Assert.InRange(body.BytesRead, 0, MaxMessageSize + 1);
		Assert.Null(request.ReceivedQuery);
	}

	[Fact]
	public async Task QueryLargerThan512Bytes_IsPassedToTheHandler()
	{
		var query = LargeQuery(0x2222, 1000);
		var request = CreatePostRequest(new SimulatedBody(query), contentLength: query.Length);

		await HandleAsync(request);

		Assert.Equal(StatusCodes.Status200OK, request.Context.Response.StatusCode);
		Assert.Equal("application/dns-message", request.Context.Response.ContentType);
		Assert.Equal(query, request.ReceivedQuery!.ToArraySegment(false).ToArray());

		var response = DnsMessage.Parse(new ArraySegment<byte>(((MemoryStream) request.Context.Response.Body).ToArray()));
		Assert.Equal(0x2222, response.TransactionID);
	}

	[Fact]
	public async Task QueryOfDnsMaximumSize_IsAccepted()
	{
		var query = new byte[MaxMessageSize];
		Query(0x3333).CopyTo(query, 0);
		var request = CreatePostRequest(new SimulatedBody(query), contentLength: query.Length);

		await HandleAsync(request, answer: false);

		Assert.NotNull(request.ReceivedQuery);
		Assert.Equal(MaxMessageSize, request.ReceivedQuery!.Length);
	}

	private static Task HandleAsync(SimulatedRequest request, bool answer = true)
	{
		return EndpointRouteBuilderExtensions.HandleRequestAsync(request.Context, default, (query, _, _) =>
		{
			request.ReceivedQuery = query;
			if (!answer)
				return Task.FromResult<DnsRawPackage?>(null);

			var message = DnsMessage.Parse(query.ToArraySegment(false));
			return Task.FromResult<DnsRawPackage?>(message.CreateResponseInstance().Encode());
		});
	}

	private static SimulatedRequest CreatePostRequest(SimulatedBody body, long? contentLength = null, long bodySizeLimit = 30_000_000, bool isBodySizeLimitReadOnly = false)
	{
		var feature = new SimulatedBodySizeFeature(bodySizeLimit, isBodySizeLimitReadOnly);
		body.Limit = () => feature.MaxRequestBodySize;

		var context = new DefaultHttpContext
		{
			RequestServices = new ServiceCollection().AddLogging().BuildServiceProvider(),
		};
		context.Request.Method = "POST";
		context.Request.ContentType = "application/dns-message";
		context.Request.ContentLength = contentLength;
		context.Request.Body = body;
		context.Response.Body = new MemoryStream();
		context.Features.Set<IHttpMaxRequestBodySizeFeature>(feature);

		return new SimulatedRequest(context, feature);
	}

	private sealed class SimulatedRequest
	{
		public SimulatedRequest(HttpContext context, SimulatedBodySizeFeature bodySizeFeature)
		{
			Context = context;
			BodySizeFeature = bodySizeFeature;
		}

		public HttpContext Context { get; }
		public SimulatedBodySizeFeature BodySizeFeature { get; }
		public DnsReceivedRawPackage? ReceivedQuery { get; set; }
		public long? BodySizeLimitAtFirstRead { get; set; }
	}

	/// <summary>
	///   The body size limit of a request, which Kestrel makes read only once the body is read
	/// </summary>
	private sealed class SimulatedBodySizeFeature : IHttpMaxRequestBodySizeFeature
	{
		private long? _maxRequestBodySize;

		public SimulatedBodySizeFeature(long maxRequestBodySize, bool isReadOnly)
		{
			_maxRequestBodySize = maxRequestBodySize;
			IsReadOnly = isReadOnly;
		}

		public bool IsReadOnly { get; }

		public long? MaxRequestBodySize
		{
			get => _maxRequestBodySize;
			set
			{
				if (IsReadOnly)
					throw new InvalidOperationException("The maximum request body size cannot be modified after the app has already started reading the request body.");
				_maxRequestBodySize = value;
			}
		}
	}

	/// <summary>
	///   A request body, which like Kestrel throws a BadHttpRequestException with 413 if more than the limit is read
	/// </summary>
	private sealed class SimulatedBody : Stream
	{
		private readonly byte[] _data;
		private int _position;

		public SimulatedBody(byte[] data) => _data = data;

		public Func<long?> Limit { get; set; } = () => null;
		public Action? OnFirstRead { get; set; }
		public int BytesRead => _position;

		public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
			=> Task.FromResult(Read(buffer, offset, count));

		public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
		{
			var array = new byte[buffer.Length];
			var length = Read(array, 0, array.Length);
			array.AsSpan(0, length).CopyTo(buffer.Span);
			return new ValueTask<int>(length);
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			if (_position == 0)
			{
				OnFirstRead?.Invoke();
				OnFirstRead = null;
			}

			// deliver in small parts, like a network connection
			var length = Math.Min(Math.Min(count, 4096), _data.Length - _position);
			if (Limit() is { } limit && _position + length > limit)
				throw new BadHttpRequestException("Request body too large.", StatusCodes.Status413PayloadTooLarge);

			Buffer.BlockCopy(_data, _position, buffer, offset, length);
			_position += length;
			return length;
		}

		public override bool CanRead => true;
		public override bool CanSeek => false;
		public override bool CanWrite => false;
		public override long Length => throw new NotSupportedException();
		public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
		public override void Flush() { }
		public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
		public override void SetLength(long value) => throw new NotSupportedException();
		public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
	}

	private static byte[] Query(ushort transactionId)
	{
		var query = new DnsMessage { TransactionID = transactionId };
		query.Questions.Add(new DnsQuestion(_name, RecordType.A, RecordClass.INet));
		return query.Encode().ToArraySegment(false).ToArray();
	}

	private static byte[] LargeQuery(ushort transactionId, int size)
	{
		var query = new DnsMessage { TransactionID = transactionId };
		query.Questions.Add(new DnsQuestion(_name, RecordType.A, RecordClass.INet));
		for (var i = 0; query.Encode().Length < size; i++)
			query.AdditionalRecords.Add(new TxtRecord(DomainName.Parse($"pad{i}.example.test"), 60, new string('x', 200)));
		return query.Encode().ToArraySegment(false).ToArray();
	}
}
#endif
