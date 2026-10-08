using DnsToolkit.Net.Dns;

namespace DnsToolkit.Net.Tests;

public class ReceiverQueuesTests
{
	private static readonly DnsMessageIdentification _id = Identification(0x1111);

	[Fact]
	public void SameIdentification_IsServedInOrderOfRegistration()
	{
		var queues = new ReceiverQueues();
		var first = Receiver();
		var second = Receiver();
		queues.Add(_id, first);
		queues.Add(_id, second);

		Assert.Equal(2, queues.Count);
		Assert.Same(first, queues.TakeFirst(_id));
		Assert.Same(second, queues.TakeFirst(_id));
		Assert.Null(queues.TakeFirst(_id));
		Assert.Equal(0, queues.Count);
	}

	[Fact]
	public void Identifications_AreKeptApart()
	{
		var queues = new ReceiverQueues();
		var first = Receiver();
		var second = Receiver();
		queues.Add(_id, first);
		queues.Add(Identification(0x2222), second);

		Assert.Same(second, queues.TakeFirst(Identification(0x2222)));
		Assert.Same(first, queues.TakeFirst(_id));
	}

	[Fact]
	public void Remove_RemovesOnlyTheGivenReceiver()
	{
		var queues = new ReceiverQueues();
		var first = Receiver();
		var second = Receiver();
		var third = Receiver();
		queues.Add(_id, first);
		queues.Add(_id, second);
		queues.Add(_id, third);

		Assert.True(queues.Remove(_id, second));
		Assert.False(queues.Remove(_id, second));
		Assert.False(queues.Remove(Identification(0x2222), first));

		Assert.Equal(2, queues.Count);
		Assert.Same(first, queues.TakeFirst(_id));
		Assert.Same(third, queues.TakeFirst(_id));
	}

	[Fact]
	public void RemoveAll_ReturnsAllReceivers()
	{
		var queues = new ReceiverQueues();
		var receivers = new[] { Receiver(), Receiver(), Receiver() };
		queues.Add(_id, receivers[0]);
		queues.Add(_id, receivers[1]);
		queues.Add(Identification(0x2222), receivers[2]);

		var removed = queues.RemoveAll();

		Assert.Equal(3, removed.Count);
		Assert.All(receivers, r => Assert.Contains(r, removed));
		Assert.Equal(0, queues.Count);
		Assert.Null(queues.TakeFirst(_id));
	}

	private static DnsMessageIdentification Identification(ushort transactionId)
	{
		return new DnsMessageIdentification(transactionId, new DnsQuestion(DomainName.Parse("host.example.test"), RecordType.A, RecordClass.INet));
	}

	private static TaskCompletionSource<DnsReceivedRawPackage?> Receiver() => new();
}
