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

using System.Text;

namespace DnsToolkit.Net.Dns;

/// <summary>
///   <para>DNS over HTTPS path service binding parameter</para>
///   <para>
///     Defined in
///     <a href="https://www.rfc-editor.org/rfc/rfc9461.html">RFC 9461</a>.
///   </para>
/// </summary>
public class DohPathServiceBindingParameter : ServiceBindingParameterBase
{
	/// <summary>
	///   The relative URI template of the DNS over HTTPS endpoint, e.g. /dns-query{?dns}
	/// </summary>
	public string Template { get; }

	/// <summary>
	///   Creates a new instance of the DohPathServiceBindingParameter class
	/// </summary>
	/// <param name="template"> The relative URI template of the DNS over HTTPS endpoint, e.g. /dns-query{?dns} </param>
	public DohPathServiceBindingParameter(string template)
	{
		Template = template ?? throw new ArgumentNullException(nameof(template));
	}

	internal DohPathServiceBindingParameter(IList<byte> resultData, ref int currentPosition, ushort valueLength)
	{
		// the template is encoded in UTF-8
		Template = Encoding.UTF8.GetString(DnsMessageBase.ParseByteData(resultData, ref currentPosition, valueLength));
	}

	internal DohPathServiceBindingParameter(ServiceBindingParameterKey type, string? parameter)
	{
		if (String.IsNullOrEmpty(parameter))
			throw new FormatException();

		Template = parameter;
	}

	public override ServiceBindingParameterKey Key => ServiceBindingParameterKey.DohPath;

	protected override void EncodeValueData(IList<byte> messageData, ref int currentPosition, bool useCanonical)
	{
		DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Encoding.UTF8.GetBytes(Template));
	}

	protected override int ValueDataLength => Encoding.UTF8.GetByteCount(Template);

	protected override string ValueToString()
	{
		return "\"" + Template.ToMasterfileLabelRepresentation() + "\"";
	}
}
