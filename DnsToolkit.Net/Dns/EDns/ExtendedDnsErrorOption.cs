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
///   <para>Extended DNS Error option, which gives the reason of an error or of a modified answer</para>
///   <para>
///     A message can contain several of these options.
///     Defined in
///     <a href="https://www.rfc-editor.org/rfc/rfc8914.html">RFC 8914</a>.
///   </para>
/// </summary>
public class ExtendedDnsErrorOption : EDnsOptionBase
{
	/// <summary>
	///   The reason of the error
	/// </summary>
	public ExtendedDnsErrorCode InfoCode { get; }

	/// <summary>
	///   An optional text for humans, which is not meant to be processed by programs
	/// </summary>
	public string ExtraText { get; }

	internal ExtendedDnsErrorOption(IList<byte> resultData, int startPosition, int length)
		: base(EDnsOptionType.ExtendedDnsError)
	{
		InfoCode = (ExtendedDnsErrorCode) DnsMessageBase.ParseUShort(resultData, ref startPosition);
		// UTF-8, which some servers terminate with a NUL character, though they should not
		ExtraText = Encoding.UTF8.GetString(DnsMessageBase.ParseByteData(resultData, ref startPosition, length - 2)).TrimEnd('\0');
	}

	/// <summary>
	///   Creates a new instance of the ExtendedDnsErrorOption class
	/// </summary>
	/// <param name="infoCode"> The reason of the error </param>
	/// <param name="extraText"> An optional text for humans </param>
	public ExtendedDnsErrorOption(ExtendedDnsErrorCode infoCode, string? extraText = null)
		: base(EDnsOptionType.ExtendedDnsError)
	{
		InfoCode = infoCode;
		ExtraText = extraText ?? String.Empty;
	}

	internal override ushort DataLength => (ushort) (2 + Encoding.UTF8.GetByteCount(ExtraText));

	internal override void EncodeData(IList<byte> messageData, ref int currentPosition)
	{
		DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) InfoCode);
		DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Encoding.UTF8.GetBytes(ExtraText));
	}

	public override string ToString()
	{
		return ExtraText.Length == 0 ? $"{InfoCode} ({(ushort) InfoCode})" : $"{InfoCode} ({(ushort) InfoCode}): {ExtraText}";
	}
}
