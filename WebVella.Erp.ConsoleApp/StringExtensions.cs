using System;
using System.IO;

namespace WebVella.Erp.ConsoleApp
{
	public static class StringExtensions
	{
		//utility method to get configuration file path
		/// <summary>
		/// Resolves a file name that ships alongside the application to an absolute path.
		/// </summary>
		/// <remarks>
		/// DEFECT ADDRESSED - review finding F30 (Configuration / Availability), CWE-16 configuration,
		/// OWASP A05:2021 Security Misconfiguration.
		/// <para>
		/// THREAT: this method resolved the application root with a WINDOWS-ONLY regular expression -
		/// a drive letter followed by a backslash-delimited path up to a \bin segment. On Linux and
		/// macOS that pattern cannot match anything, <c>Match(...).Value</c> is the empty string, and
		/// <c>Path.Combine("", fileName)</c> yields a name relative to the PROCESS WORKING DIRECTORY
		/// rather than to the deployed application. The console host's JSON configuration provider is
		/// mandatory, so it threw <c>FileNotFoundException</c> during startup - BEFORE the
		/// environment-variable provider that supplies every secret could be consulted. The security
		/// consequence is availability plus a bad incentive: an operator who cannot start the host on
		/// the platform it is deployed on, and whose error message names a file sitting in plain view
		/// beside the executable, is pushed towards running it from an unexpected working directory or
		/// towards abandoning the scrubbed-configuration model altogether.
		/// </para>
		/// <para>
		/// <c>AppContext.BaseDirectory</c> is the framework's own answer to "where was this
		/// application deployed", is defined on every platform, and is independent of the working
		/// directory - so it is correct for a service, a scheduled task and an interactive shell
		/// alike. It replaces both the regular expression and the assembly-location probe, which
		/// additionally returns an empty string for a single-file publish.
		/// </para>
		/// <para>
		/// The absolute path is returned WITHOUT testing for existence, and that is deliberate. This
		/// helper's single responsibility is "make this name absolute against the application";
		/// deciding which of several candidate names is present belongs to the caller, which is where
		/// the case-tolerant probe for Config.json lives. Returning a path that does not exist keeps
		/// the configuration provider's own failure message accurate and actionable.
		/// </para>
		/// </remarks>
		/// <param name="fileName">A file name, or a relative path, that ships with the application.</param>
		/// <returns>The absolute path to <paramref name="fileName"/> beside the application binaries.</returns>
		public static string ToApplicationPath(this string fileName)
		{
			return Path.Combine(AppContext.BaseDirectory, fileName);
		}
	}
}
