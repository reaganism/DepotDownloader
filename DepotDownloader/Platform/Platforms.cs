using System.IO;
using System.Runtime.Versioning;

namespace DepotDownloader.Platform;

/// <summary>
///     Interface for platform-specific implementations.
/// </summary>
public interface IPlatform
{
    /// <summary>
    ///     Sets the file at the given <paramref name="path"/> to be executable
    ///     based on the <paramref name="value"/>.
    /// </summary>
    /// <param name="path">The path of the file to set executable.</param>
    /// <param name="value">
    ///     Whether it's set to be executable or un-executable.
    /// </param>
    void SetExecutable(string path, bool value);
}

#region Platform abstractions
/// <summary>
///     Unified Unix abstractions over an <see cref="IPlatform"/>
///     implementation.
/// </summary>
[UnsupportedOSPlatform("windows")]
public abstract class UnixPlatform : IPlatform
{
    private const UnixFileMode mode_execute = UnixFileMode.UserExecute
                                            | UnixFileMode.GroupExecute
                                            | UnixFileMode.OtherExecute;

    public virtual void SetExecutable(string path, bool value)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("Cannot make file executable because the file doesn't exist.", path);
        }

        var mode = File.GetUnixFileMode(path);
        if ((mode & mode_execute) == mode_execute == value)
        {
            return;
        }

        File.SetUnixFileMode(
            path,
            value
                ? mode | mode_execute
                : mode & ~mode_execute
        );
    }
}
#endregion

#region Platform implementations
/// <summary>
///     Platform implementation for Windows.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsPlatform : IPlatform
{
    void IPlatform.SetExecutable(string path, bool value)
    {
        // Do nothing on Windows.
    }
}

/// <summary>
///     Platform implementation for macOS.
/// </summary>
[SupportedOSPlatform("macos")]
public sealed class MacOsPlatform : UnixPlatform;

/// <summary>
///     Platform implementation for Linux.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class LinuxPlatform : UnixPlatform;
#endregion