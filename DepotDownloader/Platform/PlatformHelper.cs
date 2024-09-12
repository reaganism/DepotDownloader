using System;

namespace DepotDownloader.Platform;

/// <summary>
///     Provides utilities for getting and handling <see cref="IPlatform"/>s.
/// </summary>
public static class PlatformHelper
{
    /// <summary>
    ///     Creates a platform implementation based on the current OS.
    /// </summary>
    /// <returns>
    ///     A platform implementation based on the current OS.
    /// </returns>
    public static IPlatform CreatePlatform()
    {
        if (OperatingSystem.IsWindows())
        {
            return new WindowsPlatform();
        }

        if (OperatingSystem.IsLinux())
        {
            return new LinuxPlatform();
        }

        if (OperatingSystem.IsMacOS())
        {
            return new MacOsPlatform();
        }

        // TODO: Free/OpenBSD support?

        throw new PlatformNotSupportedException("The current OS is not supported.");
    }
}