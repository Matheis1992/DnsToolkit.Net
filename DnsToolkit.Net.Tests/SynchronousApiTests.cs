using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

/// <summary>
///   The synchronous methods block a thread while waiting for the DNS responses, so they are obsolete and every one of them
///   has an asynchronous version
/// </summary>
public class SynchronousApiTests
{
	private static readonly DomainName _rootServer = DomainName.Parse("a.root-servers.test");
	private static readonly DnsKeyRecord _rootKey = DnsKeyRecord.CreateSigningKey(DomainName.Root, RecordClass.INet, 3600, DnsKeyFlags.Zone | DnsKeyFlags.SecureEntryPoint, 3, DnsSecAlgorithm.Ed25519);
	private static readonly DnsKeyRecord _rootZoneSigningKey = DnsKeyRecord.CreateSigningKey(DomainName.Root, RecordClass.INet, 3600, DnsKeyFlags.Zone, 3, DnsSecAlgorithm.Ed25519);

	[Fact]
	public void SynchronousMethodsWithAnAsynchronousVersion_AreObsolete_AndNameIt()
	{
		var missing = typeof(DnsClient).Assembly.GetExportedTypes()
			.SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)
				.Where(method => (method.IsPublic || method.IsFamily || method.IsFamilyOrAssembly) && !method.IsSpecialName)
				.Where(method => !IsAwaitable(method.ReturnType) && !IsIntendedSynchronous(method))
				.Where(method => type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static).Any(x => x.Name == method.Name + "Async"))
				.Where(method => method.GetCustomAttribute<ObsoleteAttribute>()?.Message?.Contains(method.Name + "Async") != true)
				.Select(method => $"{type.Name}.{method.Name}"))
			.Distinct()
			.ToList();

		Assert.Empty(missing);
	}

	private static bool IsAwaitable(Type type)
	{
		return typeof(Task).IsAssignableFrom(type) || (type == typeof(ValueTask)) || (type.IsGenericType && (type.GetGenericTypeDefinition() == typeof(ValueTask<>)));
	}

	/// <summary>
	///   Overrides follow their base class, like the methods of a stream. Dispose and Stop of the server and Close of its
	///   transports only wait for the connections to end, which is needed for IDisposable.
	/// </summary>
	private static bool IsIntendedSynchronous(MethodInfo method)
	{
		return (method.GetBaseDefinition() != method)
		       || (method.Name == nameof(IDisposable.Dispose))
		       || ((method.DeclaringType == typeof(DnsServer)) && (method.Name == nameof(DnsServer.Stop)))
		       || (typeof(IServerTransport).IsAssignableFrom(method.DeclaringType) && (method.Name == nameof(IServerTransport.Close)));
	}

	[Fact]
	public async Task UpdateAsync_LoadsTheHintsWithTheAsynchronousMethodsOfTheResolver()
	{
		var resolver = new AsyncOnlyResolver(RootZone());
		var store = new MemoryHintStore();
		using var cts = new CancellationTokenSource();

		await store.UpdateAsync(resolver, cts.Token).WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None);

		AssertHints(store);
		Assert.NotEmpty(resolver.Tokens);
		Assert.All(resolver.Tokens, token => Assert.Equal(cts.Token, token));
	}

	[Fact]
	public void Update_UsesTheAsynchronousMethodsOfTheResolver()
	{
		var store = new MemoryHintStore();

#pragma warning disable CS0618 // the obsolete method is tested
		store.Update(new AsyncOnlyResolver(RootZone()));
#pragma warning restore CS0618

		AssertHints(store);
	}

	private static void AssertHints(MemoryHintStore store)
	{
		Assert.NotNull(store.Saved);
		Assert.Equal(new[] { IPAddress.Parse("192.0.2.1"), IPAddress.Parse("2001:db8::1") }, store.RootServers.OrderBy(x => x.AddressFamily));
		Assert.Equal(_rootKey.CalculateKeyTag(), Assert.Single(store.RootKeys).KeyTag);
	}

	private static List<DnsRecordBase> RootZone()
	{
		return new List<DnsRecordBase>
		{
			new NsRecord(DomainName.Root, 3600, _rootServer),
			new ARecord(_rootServer, 3600, IPAddress.Parse("192.0.2.1")),
			new AaaaRecord(_rootServer, 3600, IPAddress.Parse("2001:db8::1")),
			_rootKey,
			_rootZoneSigningKey,
		};
	}

	[Theory]
	[InlineData(DnsSecValidationResult.Signed, true, true)]
	[InlineData(DnsSecValidationResult.Bogus, true, false)]
	[InlineData(DnsSecValidationResult.Unsigned, true, false)]
	[InlineData(DnsSecValidationResult.Signed, false, false)]
	public async Task VerifyCertificateBySMimeAAsync_ChecksTheSignedRecordsOfTheMailAddress(DnsSecValidationResult validationResult, bool isRecordOfTheCertificate, bool expected)
	{
		using var certificate = CreateCertificate();
		using var otherCertificate = CreateCertificate();

		// the name of the record is the hash of the mail address below _smimecert of its domain (RFC 8162)
		var resolver = new SMimeAResolver(validationResult, isRecordOfTheCertificate ? certificate : otherCertificate);
		using var cts = new CancellationTokenSource();

		var result = await certificate.VerifyCertificateBySMimeAAsync("user@example.test", resolver: resolver, token: cts.Token).WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None);

		Assert.Equal(expected, result);
		Assert.True(resolver.QueriedName!.IsSubDomainOf(DomainName.Parse("_smimecert.example.test")));
		Assert.Equal(cts.Token, resolver.Token);
	}

	private static X509Certificate2 CreateCertificate()
	{
		using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		var request = new CertificateRequest("CN=user@example.test", key, HashAlgorithmName.SHA256);
		return request.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(1));
	}

	/// <summary>
	///   Answers from a fixed set of records, but only asynchronously
	/// </summary>
	private sealed class AsyncOnlyResolver : IDnsResolver
	{
		private readonly List<DnsRecordBase> _records;

		public AsyncOnlyResolver(List<DnsRecordBase> records)
		{
			_records = records;
		}

		public List<CancellationToken> Tokens { get; } = new();

		public List<T> Resolve<T>(DomainName name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet)
			where T : DnsRecordBase
			=> throw new NotSupportedException("The synchronous method blocks a thread");

		public async Task<List<T>> ResolveAsync<T>(DomainName name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet, CancellationToken token = default)
			where T : DnsRecordBase
		{
			await Task.Yield();

			lock (Tokens)
				Tokens.Add(token);

			return _records.Where(x => x.Name.Equals(name) && (x.RecordType == recordType) && (x.RecordClass == recordClass)).OfType<T>().ToList();
		}

		public void ClearCache() { }

		public void Dispose() { }
	}

	/// <summary>
	///   Returns the SMIMEA record of a certificate with the given validation result, but only asynchronously
	/// </summary>
	private sealed class SMimeAResolver : IDnsSecResolver
	{
		private readonly DnsSecValidationResult _validationResult;
		private readonly X509Certificate2 _certificate;

		public SMimeAResolver(DnsSecValidationResult validationResult, X509Certificate2 certificate)
		{
			_validationResult = validationResult;
			_certificate = certificate;
		}

		public DomainName? QueriedName { get; private set; }

		public CancellationToken Token { get; private set; }

		public List<T> Resolve<T>(DomainName name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet)
			where T : DnsRecordBase
			=> throw new NotSupportedException();

		public Task<List<T>> ResolveAsync<T>(DomainName name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet, CancellationToken token = default)
			where T : DnsRecordBase
			=> throw new NotSupportedException();

		public DnsSecResult<T> ResolveSecure<T>(DomainName name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet)
			where T : DnsRecordBase
			=> throw new NotSupportedException("The synchronous method blocks a thread");

		public async Task<DnsSecResult<T>> ResolveSecureAsync<T>(DomainName name, RecordType recordType = RecordType.A, RecordClass recordClass = RecordClass.INet, CancellationToken token = default)
			where T : DnsRecordBase
		{
			await Task.Yield();

			Assert.Equal(RecordType.SMimeA, recordType);
			QueriedName = name;
			Token = token;

			var record = new SMimeARecord(name, 3600, SMimeARecord.SMimeACertificateUsage.DaneEE, SMimeARecord.SMimeASelector.FullCertificate, SMimeARecord.SMimeAMatchingType.Full, _certificate);
			return new DnsSecResult<T>(new List<T> { (T) (DnsRecordBase) record }, _validationResult);
		}

		public void ClearCache() { }

		public void Dispose() { }
	}

	private sealed class MemoryHintStore : UpdateableResolverHintStoreBase
	{
		public Zone? Saved { get; private set; }

		protected override void Save(Zone zone) => Saved = zone;

		protected override Zone Load() => Saved ?? new Zone(DomainName.Root);
	}
}
