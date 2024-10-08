// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using DepotDownloader.Stores;

using Spectre.Console;

using SteamKit2;

namespace DepotDownloader;

public static class Program
{
    public static async Task Main(string[] args)
    {
        if (args.Length == 0)
        {
            // PrintVersion();
            PrintUsage();
            return;
        }

        DebugLog.Enabled = false;

        var accountSettings = AccountSettingsStore.LoadFromFile("account.config");

#region Common Options
        // Not using HasParameter because it is case-insensitive
        if (args.Length == 1 && (args[0] == "-V" || args[0] == "--version"))
        {
            // PrintVersion(true);
            return;
        }

        if (HasParameter(args, "-debug"))
        {
            // PrintVersion(true);

            DebugLog.Enabled = true;
            DebugLog.AddListener(
                (category, message) =>
                {
                    Console.WriteLine("[{0}] {1}", category, message);
                }
            );
        }

        var username = GetParameter<string>(args, "-username") ?? GetParameter<string>(args, "-user");
        var password = GetParameter<string>(args, "-password") ?? GetParameter<string>(args, "-pass");
        ContentDownloader.CONFIG.RememberPassword = HasParameter(args, "-remember-password");
        ContentDownloader.CONFIG.UseQrCode        = HasParameter(args, "-qr");

        ContentDownloader.CONFIG.DownloadManifestOnly = HasParameter(args, "-manifest-only");

        var cellId = GetParameter(args, "-cellid", -1);
        if (cellId == -1)
        {
            cellId = 0;
        }

        ContentDownloader.CONFIG.CellId = cellId;

        var fileList = GetParameter<string>(args, "-filelist");

        if (fileList != null)
        {
            const string range_prefix = "regex:";

            try
            {
                ContentDownloader.CONFIG.UsingFileList        = true;
                ContentDownloader.CONFIG.FilesToDownload      = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                ContentDownloader.CONFIG.FilesToDownloadRegex = [];

                var files = await File.ReadAllLinesAsync(fileList);

                foreach (var fileEntry in files)
                {
                    if (string.IsNullOrWhiteSpace(fileEntry))
                    {
                        continue;
                    }

                    if (fileEntry.StartsWith(range_prefix))
                    {
                        var rgx = new Regex(fileEntry[range_prefix.Length..], RegexOptions.Compiled | RegexOptions.IgnoreCase);
                        ContentDownloader.CONFIG.FilesToDownloadRegex.Add(rgx);
                    }
                    else
                    {
                        ContentDownloader.CONFIG.FilesToDownload.Add(fileEntry.Replace('\\', '/'));
                    }
                }

                Console.WriteLine("Using filelist: '{0}'.", fileList);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Warning: Unable to load filelist: {0}", ex);
            }
        }

        ContentDownloader.CONFIG.InstallDirectory = GetParameter<string>(args, "-dir");

        ContentDownloader.CONFIG.VerifyAll    = HasParameter(args, "-verify-all") || HasParameter(args, "-verify_all") || HasParameter(args, "-validate");
        ContentDownloader.CONFIG.MaxServers   = GetParameter(args, "-max-servers",   20);
        ContentDownloader.CONFIG.MaxDownloads = GetParameter(args, "-max-downloads", 8);
        ContentDownloader.CONFIG.MaxServers   = Math.Max(ContentDownloader.CONFIG.MaxServers, ContentDownloader.CONFIG.MaxDownloads);
        ContentDownloader.CONFIG.LoginId      = HasParameter(args, "-loginid") ? GetParameter<uint>(args, "-loginid") : null;
#endregion

        var appId = GetParameter(args, "-app", ContentDownloader.INVALID_APP_ID);
        if (appId == ContentDownloader.INVALID_APP_ID)
        {
            Console.WriteLine("Error: -app not specified!");
            return;
        }

        var pubFile = GetParameter(args, "-pubfile", ContentDownloader.INVALID_MANIFEST_ID);
        var ugcId   = GetParameter(args, "-ugc",     ContentDownloader.INVALID_MANIFEST_ID);
        if (pubFile != ContentDownloader.INVALID_MANIFEST_ID)
        {
#region Pubfile Downloading
            if (InitializeSteam(username, password))
            {
                try
                {
                    await ContentDownloader.DownloadPubfileAsync(appId, pubFile).ConfigureAwait(false);
                }
                catch (Exception ex) when (
                    ex is ContentDownloaderException
                 || ex is OperationCanceledException)
                {
                    Console.WriteLine(ex.Message);
                    return;
                }
                catch (Exception e)
                {
                    Console.WriteLine("Download failed to due to an unhandled exception: {0}", e.Message);
                    throw;
                }
                finally
                {
                    ContentDownloader.ShutdownSteam3();
                }
            }
            else
            {
                Console.WriteLine("Error: InitializeSteam failed");
                return;
            }
#endregion
        }
        else if (ugcId != ContentDownloader.INVALID_MANIFEST_ID)
        {
#region UGC Downloading
            if (InitializeSteam(username, password))
            {
                try
                {
                    await ContentDownloader.DownloadUgcAsync(appId, ugcId).ConfigureAwait(false);
                }
                catch (Exception ex) when (
                    ex is ContentDownloaderException
                 || ex is OperationCanceledException)
                {
                    Console.WriteLine(ex.Message);
                    return;
                }
                catch (Exception e)
                {
                    Console.WriteLine("Download failed to due to an unhandled exception: {0}", e.Message);
                    throw;
                }
                finally
                {
                    ContentDownloader.ShutdownSteam3();
                }
            }
            else
            {
                Console.WriteLine("Error: InitializeSteam failed");
                return;
            }
#endregion
        }
        else
        {
#region App downloading
            var branch = GetParameter<string>(args, "-branch") ?? GetParameter<string>(args, "-beta") ?? ContentDownloader.DEFAULT_BRANCH;
            ContentDownloader.CONFIG.BetaPassword = GetParameter<string>(args, "-betapassword");

            ContentDownloader.CONFIG.DownloadAllPlatforms = HasParameter(args, "-all-platforms");
            var os = GetParameter<string>(args, "-os");

            if (ContentDownloader.CONFIG.DownloadAllPlatforms && !string.IsNullOrEmpty(os))
            {
                Console.WriteLine("Error: Cannot specify -os when -all-platforms is specified.");
                return;
            }

            var arch = GetParameter<string>(args, "-osarch");

            ContentDownloader.CONFIG.DownloadAllLanguages = HasParameter(args, "-all-languages");
            var language = GetParameter<string>(args, "-language");

            if (ContentDownloader.CONFIG.DownloadAllLanguages && !string.IsNullOrEmpty(language))
            {
                Console.WriteLine("Error: Cannot specify -language when -all-languages is specified.");
                return;
            }

            var lv = HasParameter(args, "-lowviolence");

            var        depotManifestIds = new List<(uint, ulong)>();
            const bool is_ugc           = false;

            var depotIdList    = GetParameterList<uint>(args, "-depot");
            var manifestIdList = GetParameterList<ulong>(args, "-manifest");
            if (manifestIdList.Count > 0)
            {
                if (depotIdList.Count != manifestIdList.Count)
                {
                    Console.WriteLine("Error: -manifest requires one id for every -depot specified");
                    return;
                }

                var zippedDepotManifest = depotIdList.Zip(manifestIdList, (depotId, manifestId) => (depotId, manifestId));
                depotManifestIds.AddRange(zippedDepotManifest);
            }
            else
            {
                depotManifestIds.AddRange(depotIdList.Select(depotId => (depotId, ContentDownloader.INVALID_MANIFEST_ID)));
            }

            if (InitializeSteam(username, password))
            {
                try
                {
                    await ContentDownloader.DownloadAppAsync(appId, depotManifestIds, branch, os, arch, language, lv, is_ugc).ConfigureAwait(false);
                }
                catch (Exception ex) when (
                    ex is ContentDownloaderException
                 || ex is OperationCanceledException)
                {
                    Console.WriteLine(ex.Message);
                    return;
                }
                catch (Exception e)
                {
                    Console.WriteLine("Download failed to due to an unhandled exception: {0}", e.Message);
                    throw;
                }
                finally
                {
                    ContentDownloader.ShutdownSteam3();
                }
            }
            else
            {
                Console.WriteLine("Error: InitializeSteam failed");
                return;
            }
#endregion
        }
    }

    private static bool InitializeSteam(string? username, string? password)
    {
        if (!ContentDownloader.CONFIG.UseQrCode)
        {
            if (username != null && password == null && (!ContentDownloader.CONFIG.RememberPassword || !AccountSettingsStore.CONTAINER.Store.LoginTokens.ContainsKey(username)))
            {
                do
                {
                    password = AnsiConsole.Prompt(new TextPrompt<string>("Enter account password for \"{0}\": ").Secret('*'));
                    Console.WriteLine();
                }
                while (string.Empty == password);
            }
            else if (username == null)
            {
                Console.WriteLine("No username given. Using anonymous account with dedicated server subscription.");
            }
        }

        return ContentDownloader.InitializeSteam3(username, password);
    }

    private static int IndexOfParam(string[] args, string param)
    {
        for (var x = 0; x < args.Length; ++x)
        {
            if (args[x].Equals(param, StringComparison.OrdinalIgnoreCase))
            {
                return x;
            }
        }

        return -1;
    }

    private static bool HasParameter(string[] args, string param)
    {
        return IndexOfParam(args, param) > -1;
    }

    private static T? GetParameter<T>(string[] args, string param, T? defaultValue = default)
    {
        var index = IndexOfParam(args, param);

        if (index == -1 || index == (args.Length - 1))
        {
            return defaultValue;
        }

        var strParam = args[index + 1];

        var converter = TypeDescriptor.GetConverter(typeof(T));
        if (converter.ConvertFromString(strParam) is not T t)
        {
            // throw new InvalidCastException($"Failed to convert '{strParam}' to type '{typeof(T).Name}'");
            return default(T);
        }

        return t;
    }

    private static List<T> GetParameterList<T>(string[] args, string param)
    {
        var list  = new List<T>();
        var index = IndexOfParam(args, param);

        if (index == -1 || index == (args.Length - 1))
        {
            return list;
        }

        index++;

        while (index < args.Length)
        {
            var strParam = args[index];

            if (strParam[0] == '-')
            {
                break;
            }

            var converter = TypeDescriptor.GetConverter(typeof(T));
            if (converter.ConvertFromString(strParam) is not T t)
            {
                throw new InvalidCastException($"Failed to convert '{strParam}' to type '{typeof(T).Name}'");
            }

            list.Add(t);

            index++;
        }

        return list;
    }

    private static void PrintUsage()
    {
        // Do not use tabs to align parameters here because tab size may differ
        Console.WriteLine();
        Console.WriteLine("Usage: downloading one or all depots for an app:");
        Console.WriteLine("       depotdownloader -app <id> [-depot <id> [-manifest <id>]]");
        Console.WriteLine("                       [-username <username> [-password <password>]] [other options]");
        Console.WriteLine();
        Console.WriteLine("Usage: downloading a workshop item using pubfile id");
        Console.WriteLine("       depotdownloader -app <id> -pubfile <id> [-username <username> [-password <password>]]");
        Console.WriteLine("Usage: downloading a workshop item using ugc id");
        Console.WriteLine("       depotdownloader -app <id> -ugc <id> [-username <username> [-password <password>]]");
        Console.WriteLine();
        Console.WriteLine("Parameters:");
        Console.WriteLine("  -app <#>                 - the AppID to download.");
        Console.WriteLine("  -depot <#>               - the DepotID to download.");
        Console.WriteLine("  -manifest <id>           - manifest id of content to download (requires -depot, default: current for branch).");
        Console.WriteLine($"  -beta <branchname>       - download from specified branch if available (default: {ContentDownloader.DEFAULT_BRANCH}).");
        Console.WriteLine("  -betapassword <pass>     - branch password if applicable.");
        Console.WriteLine("  -all-platforms           - downloads all platform-specific depots when -app is used.");
        Console.WriteLine("  -os <os>                 - the operating system for which to download the game (windows, macos or linux, default: OS the program is currently running on)");
        Console.WriteLine("  -osarch <arch>           - the architecture for which to download the game (32 or 64, default: the host's architecture)");
        Console.WriteLine("  -all-languages           - download all language-specific depots when -app is used.");
        Console.WriteLine("  -language <lang>         - the language for which to download the game (default: english)");
        Console.WriteLine("  -lowviolence             - download low violence depots when -app is used.");
        Console.WriteLine();
        Console.WriteLine("  -ugc <#>                 - the UGC ID to download.");
        Console.WriteLine("  -pubfile <#>             - the PublishedFileId to download. (Will automatically resolve to UGC id)");
        Console.WriteLine();
        Console.WriteLine("  -username <user>         - the username of the account to login to for restricted content.");
        Console.WriteLine("  -password <pass>         - the password of the account to login to for restricted content.");
        Console.WriteLine("  -remember-password       - if set, remember the password for subsequent logins of this user. (Use -username <username> -remember-password as login credentials)");
        Console.WriteLine();
        Console.WriteLine("  -dir <installdir>        - the directory in which to place downloaded files.");
        Console.WriteLine("  -filelist <file.txt>     - a list of files to download (from the manifest). Prefix file path with 'regex:' if you want to match with regex.");
        Console.WriteLine("  -validate                - Include checksum verification of files already downloaded");
        Console.WriteLine();
        Console.WriteLine("  -manifest-only           - downloads a human readable manifest for any depots that would be downloaded.");
        Console.WriteLine("  -cellid <#>              - the overridden CellID of the content server to download from.");
        Console.WriteLine("  -max-servers <#>         - maximum number of content servers to use. (default: 20).");
        Console.WriteLine("  -max-downloads <#>       - maximum number of chunks to download concurrently. (default: 8).");
        Console.WriteLine("  -loginid <#>             - a unique 32-bit integer Steam LogonID in decimal, required if running multiple instances of DepotDownloader concurrently.");
    }
}