namespace DnsToolkit.Net.Tests;

/// <summary>
///   Tests which measure process wide values (e.g. allocated bytes) must not run in parallel to other tests
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public class NonParallelCollection
{
	public const string Name = "Non parallel";
}
