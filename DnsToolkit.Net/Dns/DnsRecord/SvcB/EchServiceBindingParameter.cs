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
///   <para>Encrypted ClientHello (ECH) service binding parameter</para>
///   <para>
///     The key is reserved in
///     <a href="https://www.rfc-editor.org/rfc/rfc9460.html">RFC 9460</a>,
///     the value is the ECHConfigList of the TLS Encrypted ClientHello extension.
///   </para>
/// </summary>
public class EchServiceBindingParameter : ServiceBindingParameterBase
{
	/// <summary>
	///   The ECHConfigList in wire format
	/// </summary>
	public byte[] EchConfigList { get; }

	/// <summary>
	///   Creates a new instance of the EchServiceBindingParameter class
	/// </summary>
	/// <param name="echConfigList"> The ECHConfigList in wire format </param>
	public EchServiceBindingParameter(byte[] echConfigList)
	{
		EchConfigList = echConfigList ?? throw new ArgumentNullException(nameof(echConfigList));
	}

	internal EchServiceBindingParameter(IList<byte> resultData, ref int currentPosition, ushort valueLength)
	{
		EchConfigList = DnsMessageBase.ParseByteData(resultData, ref currentPosition, valueLength);
	}

	internal EchServiceBindingParameter(ServiceBindingParameterKey type, string? parameter)
	{
		// the presentation format is the Base64 encoding of the ECHConfigList
		if (String.IsNullOrEmpty(parameter))
			throw new FormatException();

		EchConfigList = Convert.FromBase64String(parameter);
	}

	public override ServiceBindingParameterKey Key => ServiceBindingParameterKey.ECH;

	protected override void EncodeValueData(IList<byte> messageData, ref int currentPosition, bool useCanonical)
	{
		DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, EchConfigList);
	}

	protected override int ValueDataLength => EchConfigList.Length;

	protected override string ValueToString()
	{
		return Convert.ToBase64String(EchConfigList);
	}
}
