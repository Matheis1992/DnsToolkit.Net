using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

public class ReceiverQueuesTests
{
	private static readonly DnsMessageIdentification _id = Identification(0x1111);

	[Fact]
	public void SameIdentification_IsKeptInOrderOfRegistration()
	{
		var queues = new ReceiverQueues<object>();
		var first = new object();
		var second = new object();
		queues.Add(_id, first);
		queues.Add(_id, second);

		Assert.Equal(2, queues.Count);
		Assert.Equal(new[] { first, second }, queues.Get(_id));
	}

	[Fact]
	public void Identifications_AreKeptApart()
	{
		var queues = new ReceiverQueues<object>();
		var first = new object();
		var second = new object();
		queues.Add(_id, first);
		queues.Add(Identification(0x2222), second);

		Assert.Equal(new[] { second }, queues.Get(Identification(0x2222)));
		Assert.Equal(new[] { first }, queues.Get(_id));
		Assert.Empty(queues.Get(Identification(0x3333)));
	}

	[Fact]
	public void Remove_RemovesOnlyTheGivenReceiver()
	{
		var queues = new ReceiverQueues<object>();
		var first = new object();
		var second = new object();
		var third = new object();
		queues.Add(_id, first);
		queues.Add(_id, second);
		queues.Add(_id, third);

		Assert.True(queues.Remove(_id, second));
		Assert.False(queues.Remove(_id, second));
		Assert.False(queues.Remove(Identification(0x2222), first));

		Assert.Equal(2, queues.Count);
		Assert.Equal(new[] { first, third }, queues.Get(_id));

		Assert.True(queues.Remove(_id, first));
		Assert.True(queues.Remove(_id, third));
		Assert.Equal(0, queues.Count);
		Assert.Empty(queues.Get(_id));
	}

	[Fact]
	public void RemoveAll_ReturnsAllReceivers()
	{
		var queues = new ReceiverQueues<object>();
		var receivers = new[] { new object(), new object(), new object() };
		queues.Add(_id, receivers[0]);
		queues.Add(_id, receivers[1]);
		queues.Add(Identification(0x2222), receivers[2]);

		var removed = queues.RemoveAll();

		Assert.Equal(3, removed.Count);
		Assert.All(receivers, r => Assert.Contains(r, removed));
		Assert.Equal(0, queues.Count);
		Assert.Empty(queues.Get(_id));
	}

	private static DnsMessageIdentification Identification(ushort transactionId)
	{
		return new DnsMessageIdentification(transactionId, new DnsQuestion(DomainName.Parse("host.example.test"), RecordType.A, RecordClass.INet));
	}
}
