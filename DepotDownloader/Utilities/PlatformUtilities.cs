// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System.IO;
using System.Runtime.InteropServices;

namespace DepotDownloader.Utilities;

internal static class PlatformUtilities
{
    public static void SetExecutable(string path, bool value)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return;
        }

        const UnixFileMode mode_execute = UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute;

        var mode           = File.GetUnixFileMode(path);
        var hasExecuteMask = (mode & mode_execute) == mode_execute;
        if (hasExecuteMask != value)
        {
            File.SetUnixFileMode(
                path,
                value
                    ? mode | mode_execute
                    : mode & ~mode_execute
            );
        }
    }
}