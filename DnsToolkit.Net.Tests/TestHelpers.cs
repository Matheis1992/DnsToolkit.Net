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

namespace DnsToolkit.Net.Tests;

/// <summary>
///   Helpers of all tests, which every test file imports with the global using static of the project file
/// </summary>
internal static class TestHelpers
{
	/// <summary>
	///   The token of the running test, which is canceled when the test run is canceled
	/// </summary>
	public static CancellationToken TestToken => TestContext.Current.CancellationToken;

	/// <summary>
	///   Asserts that the task completes within the timeout, and awaits it
	/// </summary>
	public static async Task CompletesWithinAsync(Task task, TimeSpan timeout)
	{
		var completed = await Task.WhenAny(task, Task.Delay(timeout, TestToken));
		// a canceled test run is reported as canceled, not as a timeout
		TestToken.ThrowIfCancellationRequested();
		Assert.True(completed == task, $"The task did not complete within {timeout}");
		await task;
	}
}
