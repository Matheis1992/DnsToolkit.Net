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
///   <para>Oblivious HTTP service binding parameter, which marks a target as an Oblivious HTTP gateway</para>
///   <para>
///     Defined in
///     <a href="https://www.rfc-editor.org/rfc/rfc9540.html">RFC 9540</a>.
///   </para>
/// </summary>
public class ObliviousHttpServiceBindingParameter : ServiceBindingParameterBase
{
	/// <summary>
	///   Creates a new instance of the ObliviousHttpServiceBindingParameter class
	/// </summary>
	public ObliviousHttpServiceBindingParameter() { }

	internal ObliviousHttpServiceBindingParameter(IList<byte> resultData, ref int currentPosition, ushort valueLength)
	{
		// the value is empty
		if (valueLength != 0)
			throw new FormatException("The ohttp parameter has a value");
	}

	internal ObliviousHttpServiceBindingParameter(ServiceBindingParameterKey type, string? parameter)
	{
		if (parameter != null)
			throw new FormatException();
	}

	public override ServiceBindingParameterKey Key => ServiceBindingParameterKey.ObliviousHttp;

	protected override void EncodeValueData(IList<byte> messageData, ref int currentPosition, bool useCanonical) { }

	protected override int ValueDataLength => 0;

	protected override string ValueToString()
	{
		return String.Empty;
	}
}
