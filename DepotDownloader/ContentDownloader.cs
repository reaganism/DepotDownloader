// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

using DepotDownloader.Net;
using DepotDownloader.Stores;
using DepotDownloader.Utilities;

using SteamKit2;
using SteamKit2.CDN;

using HttpClientFactory = DepotDownloader.Net.HttpClientFactory;

namespace DepotDownloader;

internal class ContentDownloaderException(string value) : Exception(value);

internal static class ContentDownloader
{
    public const uint   INVALID_APP_ID      = uint.MaxValue;
    public const uint   INVALID_DEPOT_ID    = uint.MaxValue;
    public const ulong  INVALID_MANIFEST_ID = ulong.MaxValue;
    public const string DEFAULT_BRANCH      = "public";

    public static readonly DownloadConfig CONFIG = new();

    private static Steam3Session? steam3;
    private static CdnClientPool? cdnPool;

    private const           string default_download_dir = "depots";
    private const           string config_dir           = ".DepotDownloader";
    private static readonly string staging_dir          = Path.Combine(config_dir, "staging");

    private sealed class DepotDownloadInfo(
        uint   depotId,
        uint   appId,
        ulong  manifestId,
        string branch,
        string installDir,
        byte[] depotKey
    )
    {
        public uint DepotId { get; } = depotId;

        public uint AppId { get; } = appId;

        public ulong ManifestId { get; } = manifestId;

        public string Branch { get; } = branch;

        public string InstallDir { get; } = installDir;

        public byte[] DepotKey { get; } = depotKey;
    }

    private static bool CreateDirectories(uint depotId, uint depotVersion, [NotNullWhen(returnValue: true)] out string? installDir)
    {
        installDir = null;

        try
        {
            if (string.IsNullOrWhiteSpace(CONFIG.InstallDirectory))
            {
                Directory.CreateDirectory(default_download_dir);

                var depotPath = Path.Combine(default_download_dir, depotId.ToString());
                Directory.CreateDirectory(depotPath);

                installDir = Path.Combine(depotPath, depotVersion.ToString());
                Directory.CreateDirectory(installDir);
            }
            else
            {
                Directory.CreateDirectory(CONFIG.InstallDirectory);

                installDir = CONFIG.InstallDirectory;
            }

            Directory.CreateDirectory(Path.Combine(installDir, config_dir));
            Directory.CreateDirectory(Path.Combine(installDir, staging_dir));
        }
        catch
        {
            return false;
        }

        return true;
    }

    private static bool TestIsFileIncluded(string filename)
    {
        if (!CONFIG.UsingFileList)
        {
            return true;
        }

        filename = filename.Replace('\\', '/');

        if (CONFIG.FilesToDownload?.Contains(filename) ?? false)
        {
            return true;
        }

        foreach (var rgx in CONFIG.FilesToDownloadRegex ?? [])
        {
            var m = rgx.Match(filename);

            if (m.Success)
            {
                return true;
            }
        }

        return false;
    }

    private static bool AccountHasAccess(uint depotId)
    {
        if (steam3 == null || steam3.SteamUser?.SteamID == null || (steam3.Licenses == null && steam3.SteamUser.SteamID.AccountType != EAccountType.AnonUser))
        {
            return false;
        }

        var licenseQuery = steam3.SteamUser.SteamID.AccountType == EAccountType.AnonUser ? [17906] : steam3.Licenses!.Select(x => x.PackageID).Distinct().ToArray();
        steam3.RequestPackageInfo(licenseQuery);

        foreach (var license in licenseQuery)
        {
            if (!steam3.PackageInfo.TryGetValue(license, out var package) || package == null)
            {
                continue;
            }

            if (package.KeyValues["appids"].Children.Any(child => child.AsUnsignedInteger() == depotId))
            {
                return true;
            }

            if (package.KeyValues["depotids"].Children.Any(child => child.AsUnsignedInteger() == depotId))
            {
                return true;
            }
        }

        return false;
    }

    private static KeyValue? GetSteam3AppSection(uint appId, EAppInfoSection section)
    {
        if (steam3?.AppInfo == null)
        {
            return null;
        }

        if (!steam3.AppInfo.TryGetValue(appId, out var app) || app == null)
        {
            return null;
        }

        var appInfo = app.KeyValues;
        var sectionKey = section switch
        {
            EAppInfoSection.Common   => "common",
            EAppInfoSection.Extended => "extended",
            EAppInfoSection.Config   => "config",
            EAppInfoSection.Depots   => "depots",
            _                        => throw new ArgumentOutOfRangeException(nameof(section), section, null),
        };
        var sectionKv = appInfo.Children.FirstOrDefault(c => c.Name == sectionKey);
        return sectionKv;
    }

    private static uint GetSteam3AppBuildNumber(uint appId, string branch)
    {
        if (appId == INVALID_APP_ID)
        {
            return 0;
        }

        var depots = GetSteam3AppSection(appId, EAppInfoSection.Depots);
        Debug.Assert(depots is not null);
        var branches = depots["branches"];
        var node     = branches[branch];

        if (node == KeyValue.Invalid)
        {
            return 0;
        }

        var buildId = node["buildid"];
        return buildId == KeyValue.Invalid ? 0 : uint.Parse(buildId.Value ?? "0");
    }

    private static ulong GetSteam3DepotManifest(uint depotId, uint appId, string branch)
    {
        if (steam3 is null)
        {
            throw new InvalidOperationException("Steam3 session is not initialized");
        }

        var depots = GetSteam3AppSection(appId, EAppInfoSection.Depots);
        Debug.Assert(depots is not null);
        var depotChild = depots[depotId.ToString()];

        if (depotChild == KeyValue.Invalid)
        {
            return INVALID_MANIFEST_ID;
        }

        // Shared depots can either provide manifests, or leave you relying on
        // their parent app.  It seems that with the latter, "sharedinstall"
        // will exist (and equals 2 in the one existance I know of).  Rather
        // than relay on the unknown sharedinstall key, just look for manifests.
        // Test cases: 111710, 346680.
        if (depotChild["manifests"] == KeyValue.Invalid && depotChild["depotfromapp"] != KeyValue.Invalid)
        {
            var otherAppId = depotChild["depotfromapp"].AsUnsignedInteger();
            if (otherAppId == appId)
            {
                // This shouldn't ever happen, but ya never know with Valve. Don't infinite loop.
                Console.WriteLine(
                    "App {0}, Depot {1} has depotfromapp of {2}!",
                    appId,
                    depotId,
                    otherAppId
                );
                return INVALID_MANIFEST_ID;
            }

            steam3.RequestAppInfo(otherAppId);
            return GetSteam3DepotManifest(depotId, otherAppId, branch);
        }

        var manifests          = depotChild["manifests"];
        var encryptedManifests = depotChild["encryptedmanifests"];

        if (manifests.Children.Count == 0 && encryptedManifests.Children.Count == 0)
        {
            return INVALID_MANIFEST_ID;
        }

        var node = manifests[branch]["gid"];

        if (node == KeyValue.Invalid && !string.Equals(branch, DEFAULT_BRANCH, StringComparison.OrdinalIgnoreCase))
        {
            var encryptedNode = encryptedManifests[branch];
            if (encryptedNode != KeyValue.Invalid)
            {
                var password = CONFIG.BetaPassword;
                while (string.IsNullOrEmpty(password))
                {
                    Console.Write("Please enter the password for branch {0}: ", branch);
                    CONFIG.BetaPassword = password = Console.ReadLine();
                }

                var encryptedGid = encryptedNode["gid"];

                if (encryptedGid != KeyValue.Invalid)
                {
                    // Submit the password to Steam now to get encryption keys
                    steam3.CheckAppBetaPassword(appId, CONFIG.BetaPassword);

                    if (!steam3.AppBetaPasswords.TryGetValue(branch, out var appBetaPassword))
                    {
                        Console.WriteLine("Password was invalid for branch {0}", branch);
                        return INVALID_MANIFEST_ID;
                    }

                    var    input = Util.DecodeHexString(encryptedGid.Value!);
                    byte[] manifestBytes;
                    try
                    {
                        manifestBytes = Util.SymmetricDecryptEcb(input, appBetaPassword);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("Failed to decrypt branch {0}: {1}", branch, e.Message);
                        return INVALID_MANIFEST_ID;
                    }

                    return BitConverter.ToUInt64(manifestBytes, 0);
                }

                Console.WriteLine("Unhandled depot encryption for depotId {0}", depotId);
                return INVALID_MANIFEST_ID;
            }

            return INVALID_MANIFEST_ID;
        }

        if (node.Value == null)
        {
            return INVALID_MANIFEST_ID;
        }

        return ulong.Parse(node.Value);
    }

    private static string GetAppName(uint appId)
    {
        var info = GetSteam3AppSection(appId, EAppInfoSection.Common);
        return info == null ? string.Empty : info["name"].AsString() ?? string.Empty;
    }

    public static bool InitializeSteam3(string? username, string? password)
    {
        var loginToken = default(string);

        if (username != null && CONFIG.RememberPassword)
        {
            _ = AccountSettingsStore.CONTAINER.Store.LoginTokens.TryGetValue(username, out loginToken);
        }

        steam3 = new Steam3Session(
            new SteamUser.LogOnDetails
            {
                Username               = username,
                Password               = loginToken == null ? password : null,
                ShouldRememberPassword = CONFIG.RememberPassword,
                AccessToken            = loginToken,
                LoginID                = CONFIG.LoginId ?? 0x534B32, // "SK2"
            }
        );

        if (!steam3.WaitForCredentials())
        {
            Console.WriteLine("Unable to get steam3 credentials.");
            return false;
        }

        return true;
    }

    public static void ShutdownSteam3()
    {
        if (cdnPool != null)
        {
            cdnPool.Shutdown();
            cdnPool = null;
        }

        steam3?.Disconnect();
    }

    public static async Task DownloadPubfileAsync(uint appId, ulong publishedFileId)
    {
        if (steam3 == null)
        {
            throw new InvalidOperationException("Steam3 session is not initialized");
        }

        var details = steam3.GetPublishedFileDetails(appId, publishedFileId);

        if (!string.IsNullOrEmpty(details.file_url))
        {
            await DownloadWebFile(appId, details.filename, details.file_url);
        }
        else if (details.hcontent_file > 0)
        {
            await DownloadAppAsync(appId, new List<(uint, ulong)> { (appId, details.hcontent_file) }, DEFAULT_BRANCH, null, null, null, false, true);
        }
        else
        {
            Console.WriteLine("Unable to locate manifest ID for published file {0}", publishedFileId);
        }
    }

    public static async Task DownloadUgcAsync(uint appId, ulong ugcId)
    {
        if (steam3 == null)
        {
            throw new InvalidOperationException("Steam3 session is not initialized");
        }

        if (steam3.SteamUser is null)
        {
            throw new InvalidOperationException("Cannot download UGC content because SteamUser is not available");
        }

        var details = default(SteamCloud.UGCDetailsCallback);

        if (steam3.SteamUser.SteamID?.AccountType != EAccountType.AnonUser)
        {
            details = steam3.GetUgcDetails(ugcId);
        }
        else
        {
            Console.WriteLine($"Unable to query UGC details for {ugcId} from an anonymous account");
        }

        if (!string.IsNullOrEmpty(details?.URL))
        {
            await DownloadWebFile(appId, details.FileName, details.URL);
        }
        else
        {
            await DownloadAppAsync(appId, new List<(uint, ulong)> { (appId, ugcId) }, DEFAULT_BRANCH, null, null, null, false, true);
        }
    }

    private static async Task DownloadWebFile(uint appId, string fileName, string url)
    {
        if (!CreateDirectories(appId, 0, out var installDir))
        {
            Console.WriteLine("Error: Unable to create install directories!");
            return;
        }

        var stagingDir      = Path.Combine(installDir, staging_dir);
        var fileStagingPath = Path.Combine(stagingDir, fileName);
        var fileFinalPath   = Path.Combine(installDir, fileName);

        // TODO: Better error handling here.
        Directory.CreateDirectory(Path.GetDirectoryName(fileFinalPath)   ?? throw new InvalidOperationException());
        Directory.CreateDirectory(Path.GetDirectoryName(fileStagingPath) ?? throw new InvalidOperationException());

        await using (var file = File.OpenWrite(fileStagingPath))
        using (var client = HttpClientFactory.CreateHttpClient())
        {
            Console.WriteLine("Downloading {0}", fileName);
            var responseStream = await client.GetStreamAsync(url);
            await responseStream.CopyToAsync(file);
        }

        if (File.Exists(fileFinalPath))
        {
            File.Delete(fileFinalPath);
        }

        File.Move(fileStagingPath, fileFinalPath);
    }

    public static async Task DownloadAppAsync(uint appId, List<(uint depotId, ulong manifestId)> depotManifestIds, string branch, string? os, string? arch, string? language, bool lv, bool isUgc)
    {
        if (steam3 == null)
        {
            throw new InvalidOperationException("Steam3 session is not initialized");
        }

        cdnPool = new CdnClientPool(steam3, appId);

        // Load our configuration data containing the depots currently installed
        var configPath = CONFIG.InstallDirectory;
        if (string.IsNullOrWhiteSpace(configPath))
        {
            configPath = default_download_dir;
        }

        Directory.CreateDirectory(Path.Combine(configPath,               config_dir));
        DepotConfigStore.CONTAINER.LoadFromFile(Path.Combine(configPath, config_dir, "depot.config"), false);

        steam3.RequestAppInfo(appId);

        if (!AccountHasAccess(appId))
        {
            if (steam3.RequestFreeAppLicense(appId))
            {
                Console.WriteLine("Obtained FreeOnDemand license for app {0}", appId);

                // Fetch app info again in case we didn't get it fully without a license.
                steam3.RequestAppInfo(appId, true);
            }
            else
            {
                var contentName = GetAppName(appId);
                throw new ContentDownloaderException($"App {appId} ({contentName}) is not available from this account.");
            }
        }

        var hasSpecificDepots = depotManifestIds.Count > 0;
        var depotIdsFound     = new List<uint>();
        var depotIdsExpected  = depotManifestIds.Select(x => x.depotId).ToList();
        var depots            = GetSteam3AppSection(appId, EAppInfoSection.Depots);

        if (isUgc)
        {
            Debug.Assert(depots is not null);
            var workshopDepot = depots["workshopdepot"].AsUnsignedInteger();
            if (workshopDepot != 0 && !depotIdsExpected.Contains(workshopDepot))
            {
                depotIdsExpected.Add(workshopDepot);
                depotManifestIds = depotManifestIds.Select(pair => (workshopDepot, pair.manifestId)).ToList();
            }

            depotIdsFound.AddRange(depotIdsExpected);
        }
        else
        {
            Console.WriteLine("Using app branch: '{0}'.", branch);

            if (depots is not null)
            {
                foreach (var depotSection in depots.Children)
                {
                    if (depotSection.Children.Count == 0)
                    {
                        continue;
                    }

                    if (!uint.TryParse(depotSection.Name, out var id))
                    {
                        continue;
                    }

                    if (hasSpecificDepots && !depotIdsExpected.Contains(id))
                    {
                        continue;
                    }

                    if (!hasSpecificDepots)
                    {
                        var depotConfig = depotSection["config"];
                        if (depotConfig != KeyValue.Invalid)
                        {
                            if (!CONFIG.DownloadAllPlatforms              &&
                                depotConfig["oslist"] != KeyValue.Invalid &&
                                !string.IsNullOrWhiteSpace(depotConfig["oslist"].Value))
                            {
                                var oslist = depotConfig["oslist"].Value!.Split(',');
                                if (Array.IndexOf(oslist, os ?? Util.GetSteamOs()) == -1)
                                {
                                    continue;
                                }
                            }

                            if (depotConfig["osarch"] != KeyValue.Invalid &&
                                !string.IsNullOrWhiteSpace(depotConfig["osarch"].Value))
                            {
                                var depotArch = depotConfig["osarch"].Value;
                                if (depotArch != (arch ?? Util.GetSteamArch()))
                                {
                                    continue;
                                }
                            }

                            if (!CONFIG.DownloadAllLanguages                &&
                                depotConfig["language"] != KeyValue.Invalid &&
                                !string.IsNullOrWhiteSpace(depotConfig["language"].Value))
                            {
                                var depotLang = depotConfig["language"].Value;
                                if (depotLang != (language ?? "english"))
                                {
                                    continue;
                                }
                            }

                            if (!lv                                            &&
                                depotConfig["lowviolence"] != KeyValue.Invalid &&
                                depotConfig["lowviolence"].AsBoolean())
                            {
                                continue;
                            }
                        }
                    }

                    depotIdsFound.Add(id);

                    if (!hasSpecificDepots)
                    {
                        depotManifestIds.Add((id, INVALID_MANIFEST_ID));
                    }
                }
            }

            if (depotManifestIds.Count == 0 && !hasSpecificDepots)
            {
                throw new ContentDownloaderException($"Couldn't find any depots to download for app {appId}");
            }

            if (depotIdsFound.Count < depotIdsExpected.Count)
            {
                var remainingDepotIds = depotIdsExpected.Except(depotIdsFound);
                throw new ContentDownloaderException($"Depot {string.Join(", ", remainingDepotIds)} not listed for app {appId}");
            }
        }

        var infos = new List<DepotDownloadInfo>();

        foreach (var (depotId, manifestId) in depotManifestIds)
        {
            var info = GetDepotInfo(depotId, appId, manifestId, branch);
            if (info is not null)
            {
                infos.Add(info);
            }
        }

        try
        {
            await DownloadSteam3Async(infos).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("App {0} was not completely downloaded.", appId);
            throw;
        }
    }

    private static DepotDownloadInfo? GetDepotInfo(uint depotId, uint appId, ulong manifestId, string branch)
    {
        if (steam3 is null)
        {
            throw new InvalidOperationException("Steam3 session is not initialized");
        }

        if (appId != INVALID_APP_ID)
        {
            steam3.RequestAppInfo(appId);
        }

        if (!AccountHasAccess(depotId))
        {
            Console.WriteLine("Depot {0} is not available from this account.", depotId);

            return null;
        }

        if (manifestId == INVALID_MANIFEST_ID)
        {
            manifestId = GetSteam3DepotManifest(depotId, appId, branch);
            if (manifestId == INVALID_MANIFEST_ID && !string.Equals(branch, DEFAULT_BRANCH, StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Warning: Depot {0} does not have branch named \"{1}\". Trying {2} branch.", depotId, branch, DEFAULT_BRANCH);
                branch     = DEFAULT_BRANCH;
                manifestId = GetSteam3DepotManifest(depotId, appId, branch);
            }

            if (manifestId == INVALID_MANIFEST_ID)
            {
                Console.WriteLine("Depot {0} missing public subsection or manifest section.", depotId);
                return null;
            }
        }

        steam3.RequestDepotKey(depotId, appId);
        if (!steam3.DepotKeys.TryGetValue(depotId, out var depotKey))
        {
            Console.WriteLine("No valid depot key for {0}, unable to download.", depotId);
            return null;
        }

        var uVersion = GetSteam3AppBuildNumber(appId, branch);

        if (!CreateDirectories(depotId, uVersion, out var installDir))
        {
            Console.WriteLine("Error: Unable to create install directories!");
            return null;
        }

        return new DepotDownloadInfo(depotId, appId, manifestId, branch, installDir, depotKey);
    }

    private class ChunkMatch(DepotManifest.ChunkData oldChunk, DepotManifest.ChunkData newChunk)
    {
        public DepotManifest.ChunkData OldChunk { get; } = oldChunk;

        public DepotManifest.ChunkData NewChunk { get; } = newChunk;
    }

    private class DepotFilesData
    {
        public DepotDownloadInfo? DepotDownloadInfo { get; init; }

        public DepotDownloadCounter? DepotCounter { get; init; }

        public string? StagingDir { get; init; }

        public DepotManifest? PreviousManifest { get; init; }

        public List<DepotManifest.FileData>? FilteredFiles { get; init; }

        public HashSet<string>? AllFileNames { get; init; }
    }

    private class FileStreamData
    {
        public FileStream? FileStream { get; set; }

        public SemaphoreSlim? FileLock { get; init; }

        public int ChunksToDownload;
    }

    private class GlobalDownloadCounter
    {
        public ulong TotalBytesCompressed { get; set; }

        public ulong TotalBytesUncompressed { get; set; }
    }

    private class DepotDownloadCounter
    {
        public ulong CompleteDownloadSize { get; set; }

        public ulong SizeDownloaded { get; set; }

        public ulong DepotBytesCompressed { get; set; }

        public ulong DepotBytesUncompressed { get; set; }
    }

    private static async Task DownloadSteam3Async(List<DepotDownloadInfo> depots)
    {
        if (cdnPool is null)
        {
            throw new InvalidOperationException("CDN pool is not initialized");
        }

        // TODO: Ansi.Progress(Ansi.ProgressState.Indeterminate);

        var cts = new CancellationTokenSource();
        cdnPool.ExhaustedToken = cts;

        var downloadCounter       = new GlobalDownloadCounter();
        var depotsToDownload      = new List<DepotFilesData>(depots.Count);
        var allFileNamesAllDepots = new HashSet<string>();

        // First, fetch all the manifests for each depot (including previous manifests) and perform the initial setup
        foreach (var depot in depots)
        {
            var depotFileData = await ProcessDepotManifestAndFiles(cts, depot);
            if (depotFileData is not null)
            {
                Debug.Assert(depotFileData.AllFileNames is not null);
                depotsToDownload.Add(depotFileData);
                allFileNamesAllDepots.UnionWith(depotFileData.AllFileNames);
            }

            cts.Token.ThrowIfCancellationRequested();
        }

        // If we're about to write all the files to the same directory, we will need to first de-duplicate any files by path
        // This is in last-depot-wins order, from Steam or the list of depots supplied by the user
        if (!string.IsNullOrWhiteSpace(CONFIG.InstallDirectory) && depotsToDownload.Count > 0)
        {
            var claimedFileNames = new HashSet<string>();

            for (var i = depotsToDownload.Count - 1; i >= 0; i--)
            {
                // For each depot, remove all files from the list that have been claimed by a later depot
                depotsToDownload[i].FilteredFiles?.RemoveAll(file => claimedFileNames.Contains(file.FileName));
                Debug.Assert(depotsToDownload[i].AllFileNames is not null);
                claimedFileNames.UnionWith(depotsToDownload[i].AllFileNames!);
            }
        }

        foreach (var depotFileData in depotsToDownload)
        {
            await DownloadSteam3AsyncDepotFiles(cts, downloadCounter, depotFileData, allFileNamesAllDepots);
        }

        // TODO: Ansi.Progress(Ansi.ProgressState.Hidden);

        Console.WriteLine(
            "Total downloaded: {0} bytes ({1} bytes uncompressed) from {2} depots",
            downloadCounter.TotalBytesCompressed,
            downloadCounter.TotalBytesUncompressed,
            depots.Count
        );
    }

    private static async Task<DepotFilesData?> ProcessDepotManifestAndFiles(CancellationTokenSource cts, DepotDownloadInfo depot)
    {
        if (cdnPool is null)
        {
            throw new InvalidOperationException("CDN pool is not initialized");
        }

        if (steam3 is null)
        {
            throw new InvalidOperationException("Steam3 session is not initialized");
        }

        var depotCounter = new DepotDownloadCounter();

        Console.WriteLine("Processing depot {0}", depot.DepotId);

        var            oldManifest = default(DepotManifest);
        DepotManifest? newManifest;
        var            configDir = Path.Combine(depot.InstallDir, config_dir);

        DepotConfigStore.CONTAINER.Store.InstalledManifestIDs.TryGetValue(depot.DepotId, out var lastManifestId);

        // In case we have an early exit, this will force equiv of verify all
        // next run.
        DepotConfigStore.CONTAINER.Store.InstalledManifestIDs[depot.DepotId] = INVALID_MANIFEST_ID;
        DepotConfigStore.CONTAINER.Save();

        if (lastManifestId != INVALID_MANIFEST_ID)
        {
            var oldManifestFileName = Path.Combine(configDir, $"{depot.DepotId}_{lastManifestId}.manifest");

            if (File.Exists(oldManifestFileName))
            {
                byte[]? expectedChecksum;

                try
                {
                    expectedChecksum = await File.ReadAllBytesAsync(oldManifestFileName + ".sha");
                }
                catch (IOException)
                {
                    expectedChecksum = null;
                }

                var currentChecksum = Util.FileShaHash(oldManifestFileName);
                if (expectedChecksum is not null && expectedChecksum.SequenceEqual(currentChecksum))
                {
                    oldManifest = DepotManifest.LoadFromFile(oldManifestFileName);
                }
                else
                {
                    // We only have to show this warning if the old manifest ID was different
                    if (lastManifestId != depot.ManifestId)
                    {
                        Console.WriteLine($"Manifest {lastManifestId} on disk did not match the expected checksum.",);
                    }
                    oldManifest = null;
                }
            }
        }

        if (lastManifestId == depot.ManifestId && oldManifest != null)
        {
            newManifest = oldManifest;
            Console.WriteLine($"Already have manifest {depot.ManifestId} for depot {depot.DepotId}.");
        }
        else
        {
            var newManifestFileName = Path.Combine(configDir, $"{depot.DepotId}_{depot.ManifestId}.manifest");
            {
                byte[]? expectedChecksum;

                try
                {
                    expectedChecksum = await File.ReadAllBytesAsync(newManifestFileName + ".sha");
                }
                catch (IOException)
                {
                    expectedChecksum = null;
                }

                var currentChecksum = Util.FileShaHash(newManifestFileName);
                if (expectedChecksum is not null && expectedChecksum.SequenceEqual(currentChecksum))
                {
                    newManifest = DepotManifest.LoadFromFile(newManifestFileName);
                }
                else
                {
                    Console.WriteLine("Manifest {0} on disk did not match the expected checksum.", depot.ManifestId);
                    newManifest = null;
                }
            }

            if (newManifest != null)
            {
                Console.WriteLine("Already have manifest {0} for depot {1}.", depot.ManifestId, depot.DepotId);
            }
            else
            {
                Console.Write("Downloading depot manifest... ");

                var depotManifest                 = default(DepotManifest);
                var manifestRequestCode           = 0ul;
                var manifestRequestCodeExpiration = DateTime.MinValue;

                do
                {
                    cts.Token.ThrowIfCancellationRequested();

                    var connection = default(Server);

                    try
                    {
                        connection = cdnPool.GetConnection(cts.Token);

                        var cdnToken = default(string);
                        if (steam3.CdnAuthTokens.TryGetValue((depot.DepotId, connection.Host!), out var authTokenCallbackPromise))
                        {
                            var result = await authTokenCallbackPromise.Task;
                            cdnToken = result.Token;
                        }

                        var now = DateTime.Now;

                        // In order to download this manifest, we need the
                        // current manifest request code.  The manifest request
                        // code is only valid for a specific period in time.
                        if (manifestRequestCode == 0 || now >= manifestRequestCodeExpiration)
                        {
                            manifestRequestCode = await steam3.GetDepotManifestRequestCodeAsync(
                                depot.DepotId,
                                depot.AppId,
                                depot.ManifestId,
                                depot.Branch
                            );
                            // This code will hopefully be valid for one period
                            // following the issuing period.
                            manifestRequestCodeExpiration = now.Add(TimeSpan.FromMinutes(5));

                            // If we could not get the manifest code, this is a
                            // fatal error.
                            if (manifestRequestCode == 0)
                            {
                                Console.WriteLine("No manifest request code was returned for {0} {1}", depot.DepotId, depot.ManifestId);
                                await cts.CancelAsync();
                            }
                        }

                        DebugLog.WriteLine(
                            "ContentDownloader",
                            "Downloading manifest {0} from {1} with {2}",
                            depot.ManifestId,
                            connection,
                            cdnPool.ProxyServer != null ? cdnPool.ProxyServer : "no proxy"
                        );
                        depotManifest = await cdnPool.CdnClient.DownloadManifestAsync(
                            depot.DepotId,
                            depot.ManifestId,
                            manifestRequestCode,
                            connection,
                            depot.DepotKey,
                            cdnPool.ProxyServer,
                            cdnToken
                        ).ConfigureAwait(false);

                        cdnPool.ReturnConnection(connection);
                    }
                    catch (TaskCanceledException)
                    {
                        Console.WriteLine("Connection timeout downloading depot manifest {0} {1}. Retrying.", depot.DepotId, depot.ManifestId);
                    }
                    catch (SteamKitWebRequestException e)
                    {
                        Debug.Assert(connection is not null);

                        // If the CDN returned 403, attempt to get a cdn auth if we didn't yet
                        if (e.StatusCode == HttpStatusCode.Forbidden && !steam3.CdnAuthTokens.ContainsKey((depot.DepotId, connection.Host!)))
                        {
                            await steam3.RequestCdnAuthToken(depot.AppId, depot.DepotId, connection);

                            cdnPool.ReturnConnection(connection);

                            continue;
                        }

                        cdnPool.ReturnBrokenConnection(connection);

                        if (e.StatusCode == HttpStatusCode.Unauthorized || e.StatusCode == HttpStatusCode.Forbidden)
                        {
                            Console.WriteLine("Encountered {2} for depot manifest {0} {1}. Aborting.", depot.DepotId, depot.ManifestId, (int)e.StatusCode);
                            break;
                        }

                        if (e.StatusCode == HttpStatusCode.NotFound)
                        {
                            Console.WriteLine("Encountered 404 for depot manifest {0} {1}. Aborting.", depot.DepotId, depot.ManifestId);
                            break;
                        }

                        Console.WriteLine("Encountered error downloading depot manifest {0} {1}: {2}", depot.DepotId, depot.ManifestId, e.StatusCode);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (Exception e)
                    {
                        cdnPool.ReturnBrokenConnection(connection);
                        Console.WriteLine("Encountered error downloading manifest for depot {0} {1}: {2}", depot.DepotId, depot.ManifestId, e.Message);
                    }
                }
                while (depotManifest == null);

                if (depotManifest == null)
                {
                    Console.WriteLine("\nUnable to download manifest {0} for depot {1}", depot.ManifestId, depot.DepotId);
                    await cts.CancelAsync();
                }

                // Throw the cancellation exception if requested so that this task is marked failed
                cts.Token.ThrowIfCancellationRequested();

                Debug.Assert(newManifest is not null);
                newManifest.SaveToFile(newManifestFileName);
                await File.WriteAllBytesAsync(newManifestFileName + ".sha", Util.FileShaHash(newManifestFileName));

                Console.WriteLine(" Done!");
            }
        }

        Console.WriteLine($"Manifest {depot.ManifestId} ({newManifest.CreationTime})");

        if (CONFIG.DownloadManifestOnly)
        {
            DumpManifestToTextFile(depot, newManifest);
            return null;
        }

        var stagingDir = Path.Combine(depot.InstallDir, staging_dir);

        var filesAfterExclusions = newManifest.Files.AsParallel().Where(f => TestIsFileIncluded(f.FileName)).ToList();
        var allFileNames         = new HashSet<string>(filesAfterExclusions.Count);

        // Pre-process
        filesAfterExclusions.ForEach(
            file =>
            {
                allFileNames.Add(file.FileName);

                var fileFinalPath   = Path.Combine(depot.InstallDir, file.FileName);
                var fileStagingPath = Path.Combine(stagingDir,       file.FileName);

                if (file.Flags.HasFlag(EDepotFileFlag.Directory))
                {
                    Directory.CreateDirectory(fileFinalPath);
                    Directory.CreateDirectory(fileStagingPath);
                }
                else
                {
                    // TODO: Handle null.
                    // Some manifests don't explicitly include all necessary
                    // directories.
                    Directory.CreateDirectory(Path.GetDirectoryName(fileFinalPath)!);
                    Directory.CreateDirectory(Path.GetDirectoryName(fileStagingPath)!);

                    depotCounter.CompleteDownloadSize += file.TotalSize;
                }
            }
        );

        return new DepotFilesData
        {
            DepotDownloadInfo = depot,
            DepotCounter      = depotCounter,
            StagingDir        = stagingDir,
            PreviousManifest  = oldManifest,
            FilteredFiles     = filesAfterExclusions,
            AllFileNames      = allFileNames,
        };
    }

    private static async Task DownloadSteam3AsyncDepotFiles(
        CancellationTokenSource cts,
        GlobalDownloadCounter   downloadCounter,
        DepotFilesData          depotFilesData,
        HashSet<string>         allFileNamesAllDepots
    )
    {
        var depot = depotFilesData.DepotDownloadInfo;
        Debug.Assert(depot is not null);
        var depotCounter = depotFilesData.DepotCounter;

        Console.WriteLine("Downloading depot {0}", depot.DepotId);

        var files             = depotFilesData.FilteredFiles!.Where(f => !f.Flags.HasFlag(EDepotFileFlag.Directory)).ToArray();
        var networkChunkQueue = new ConcurrentQueue<(FileStreamData fileStreamData, DepotManifest.FileData fileData, DepotManifest.ChunkData chunk)>();

        await Util.InvokeAsync(
            files.Select(
                file => new Func<Task>(
                    async () =>
                        await Task.Run(() => DownloadSteam3AsyncDepotFile(cts, downloadCounter, depotFilesData, file, networkChunkQueue))
                )
            ),
            maxDegreeOfParallelism: CONFIG.MaxDownloads
        );

        await Util.InvokeAsync(
            networkChunkQueue.Select(
                q => new Func<Task>(
                    async () =>
                        await Task.Run(
                            () => DownloadSteam3AsyncDepotFileChunk(
                                cts,
                                downloadCounter,
                                depotFilesData,
                                q.fileData,
                                q.fileStreamData,
                                q.chunk
                            )
                        )
                )
            ),
            maxDegreeOfParallelism: CONFIG.MaxDownloads
        );

        // Check for deleted files if updating the depot.
        if (depotFilesData.PreviousManifest != null)
        {
            var previousFilteredFiles = depotFilesData.PreviousManifest.Files.AsParallel().Where(f => TestIsFileIncluded(f.FileName)).Select(f => f.FileName).ToHashSet();

            // Check if we are writing to a single output directory. If not, each depot folder is managed independently
            previousFilteredFiles.ExceptWith(
                string.IsNullOrWhiteSpace(CONFIG.InstallDirectory)
                    // Of the list of files in the previous manifest, remove any file names that exist in the current set of all file names
                    ? depotFilesData.AllFileNames!
                    // Of the list of files in the previous manifest, remove any file names that exist in the current set of all file names across all depots being downloaded
                    : allFileNamesAllDepots
            );

            foreach (var existingFileName in previousFilteredFiles)
            {
                var fileFinalPath = Path.Combine(depot.InstallDir, existingFileName);

                if (!File.Exists(fileFinalPath))
                {
                    continue;
                }

                File.Delete(fileFinalPath);
                Console.WriteLine("Deleted {0}", fileFinalPath);
            }
        }

        DepotConfigStore.CONTAINER.Store.InstalledManifestIDs[depot.DepotId] = depot.ManifestId;
        DepotConfigStore.CONTAINER.Save();

        Console.WriteLine("Depot {0} - Downloaded {1} bytes ({2} bytes uncompressed)", depot.DepotId, depotCounter!.DepotBytesCompressed, depotCounter.DepotBytesUncompressed);
    }

    private static void DownloadSteam3AsyncDepotFile(
        CancellationTokenSource                                                            cts,
        GlobalDownloadCounter                                                              downloadCounter,
        DepotFilesData                                                                     depotFilesData,
        DepotManifest.FileData                                                             file,
        ConcurrentQueue<(FileStreamData, DepotManifest.FileData, DepotManifest.ChunkData)> networkChunkQueue
    )
    {
        cts.Token.ThrowIfCancellationRequested();

        var depot                = depotFilesData.DepotDownloadInfo!;
        var stagingDir           = depotFilesData.StagingDir!;
        var depotDownloadCounter = depotFilesData.DepotCounter;
        var oldProtoManifest     = depotFilesData.PreviousManifest;
        var oldManifestFile      = default(DepotManifest.FileData);
        if (oldProtoManifest != null)
        {
            oldManifestFile = oldProtoManifest.Files.SingleOrDefault(f => f.FileName == file.FileName)!;
        }

        var fileFinalPath   = Path.Combine(depot.InstallDir, file.FileName);
        var fileStagingPath = Path.Combine(stagingDir,       file.FileName);

        // This may still exist if the previous run exited before cleanup
        if (File.Exists(fileStagingPath))
        {
            File.Delete(fileStagingPath);
        }

        List<DepotManifest.ChunkData> neededChunks;
        var                           fi           = new FileInfo(fileFinalPath);
        var                           fileDidExist = fi.Exists;
        if (!fileDidExist)
        {
            Console.WriteLine("Pre-allocating {0}", fileFinalPath);

            // create new file. need all chunks
            using var fs = File.Create(fileFinalPath);
            try
            {
                fs.SetLength((long)file.TotalSize);
            }
            catch (IOException ex)
            {
                throw new ContentDownloaderException($"Failed to allocate file {fileFinalPath}: {ex.Message}");
            }

            neededChunks = [..file.Chunks];
        }
        else
        {
            // open existing
            if (oldManifestFile != null)
            {
                neededChunks = [];

                var hashMatches = oldManifestFile.FileHash.SequenceEqual(file.FileHash);
                if (CONFIG.VerifyAll || !hashMatches)
                {
                    // we have a version of this file, but it doesn't fully match what we want
                    if (CONFIG.VerifyAll)
                    {
                        Console.WriteLine("Validating {0}", fileFinalPath);
                    }

                    var matchingChunks = new List<ChunkMatch>();

                    foreach (var chunk in file.Chunks)
                    {
                        var oldChunk = oldManifestFile.Chunks.FirstOrDefault(c => c.ChunkID!.SequenceEqual(chunk.ChunkID!));
                        if (oldChunk != null)
                        {
                            matchingChunks.Add(new ChunkMatch(oldChunk, chunk));
                        }
                        else
                        {
                            neededChunks.Add(chunk);
                        }
                    }

                    var orderedChunks = matchingChunks.OrderBy(x => x.OldChunk.Offset);

                    var copyChunks = new List<ChunkMatch>();

                    using (var fsOld = File.Open(fileFinalPath, FileMode.Open))
                    {
                        foreach (var match in orderedChunks)
                        {
                            fsOld.Seek((long)match.OldChunk.Offset, SeekOrigin.Begin);

                            var adler = Util.AdlerHash(fsOld, (int)match.OldChunk.UncompressedLength);
                            if (!adler.SequenceEqual(BitConverter.GetBytes(match.OldChunk.Checksum)))
                            {
                                neededChunks.Add(match.NewChunk);
                            }
                            else
                            {
                                copyChunks.Add(match);
                            }
                        }
                    }

                    if (!hashMatches || neededChunks.Count > 0)
                    {
                        File.Move(fileFinalPath, fileStagingPath);

                        using (var fsOld = File.Open(fileStagingPath, FileMode.Open))
                        {
                            using var fs = File.Open(fileFinalPath, FileMode.Create);
                            try
                            {
                                fs.SetLength((long)file.TotalSize);
                            }
                            catch (IOException ex)
                            {
                                throw new ContentDownloaderException($"Failed to resize file to expected size {fileFinalPath}: {ex.Message}");
                            }

                            foreach (var match in copyChunks)
                            {
                                fsOld.Seek((long)match.OldChunk.Offset, SeekOrigin.Begin);

                                var tmp = new byte[match.OldChunk.UncompressedLength];
                                if (fsOld.Read(tmp, 0, tmp.Length) != tmp.Length)
                                {
                                    throw new ContentDownloaderException($"Failed to read chunk from old file {fileStagingPath}");
                                }

                                fs.Seek((long)match.NewChunk.Offset, SeekOrigin.Begin);
                                fs.Write(tmp, 0, tmp.Length);
                            }
                        }

                        File.Delete(fileStagingPath);
                    }
                }
            }
            else
            {
                // No old manifest or file not in old manifest. We must validate.

                using var fs = File.Open(fileFinalPath, FileMode.Open);
                if ((ulong)fi.Length != file.TotalSize)
                {
                    try
                    {
                        fs.SetLength((long)file.TotalSize);
                    }
                    catch (IOException ex)
                    {
                        throw new ContentDownloaderException($"Failed to allocate file {fileFinalPath}: {ex.Message}");
                    }
                }

                Console.WriteLine("Validating {0}", fileFinalPath);
                neededChunks = Util.ValidateSteam3FileChecksums(fs, [.. file.Chunks.OrderBy(x => x.Offset)]);
            }

            if (neededChunks.Count == 0)
            {
                lock (depotDownloadCounter!)
                {
                    depotDownloadCounter.SizeDownloaded += file.TotalSize;
                    Console.WriteLine("{0,6:#00.00}% {1}", (depotDownloadCounter.SizeDownloaded / (float)depotDownloadCounter.CompleteDownloadSize) * 100.0f, fileFinalPath);
                }

                lock (downloadCounter) { }

                return;
            }

            var sizeOnDisk = file.TotalSize - (ulong)neededChunks.Select(x => (long)x.UncompressedLength).Sum();
            lock (depotDownloadCounter!)
            {
                depotDownloadCounter.SizeDownloaded += sizeOnDisk;
            }

            lock (downloadCounter) { }
        }

        var fileIsExecutable = file.Flags.HasFlag(EDepotFileFlag.Executable);
        if (fileIsExecutable && (!fileDidExist || oldManifestFile == null || !oldManifestFile.Flags.HasFlag(EDepotFileFlag.Executable)))
        {
            PlatformUtilities.SetExecutable(fileFinalPath, true);
        }
        else if (!fileIsExecutable && oldManifestFile != null && oldManifestFile.Flags.HasFlag(EDepotFileFlag.Executable))
        {
            PlatformUtilities.SetExecutable(fileFinalPath, false);
        }

        var fileStreamData = new FileStreamData
        {
            FileStream       = null,
            FileLock         = new SemaphoreSlim(1),
            ChunksToDownload = neededChunks.Count,
        };

        foreach (var chunk in neededChunks)
        {
            networkChunkQueue.Enqueue((fileStreamData, file, chunk));
        }
    }

    private static async Task DownloadSteam3AsyncDepotFileChunk(
        CancellationTokenSource cts,
        GlobalDownloadCounter   downloadCounter,
        DepotFilesData          depotFilesData,
        DepotManifest.FileData  file,
        FileStreamData          fileStreamData,
        DepotManifest.ChunkData chunk
    )
    {
        if (steam3 is null)
        {
            throw new InvalidOperationException("Steam3 session is not initialized");
        }

        if (cdnPool is null)
        {
            throw new InvalidOperationException("CDN pool is not initialized");
        }

        cts.Token.ThrowIfCancellationRequested();

        var depot                = depotFilesData.DepotDownloadInfo;
        var depotDownloadCounter = depotFilesData.DepotCounter;

        var chunkId = Convert.ToHexString(chunk.ChunkID!).ToLowerInvariant();

        var data = new DepotManifest.ChunkData
        {
            ChunkID            = chunk.ChunkID,
            Checksum           = chunk.Checksum,
            Offset             = chunk.Offset,
            CompressedLength   = chunk.CompressedLength,
            UncompressedLength = chunk.UncompressedLength,
        };

        var written     = 0;
        var chunkBuffer = ArrayPool<byte>.Shared.Rent((int)data.UncompressedLength);

        try
        {
            do
            {
                cts.Token.ThrowIfCancellationRequested();

                var connection = default(Server);

                try
                {
                    connection = cdnPool.GetConnection(cts.Token);

                    var cdnToken = default(string);
                    if (steam3.CdnAuthTokens.TryGetValue((depot!.DepotId, connection.Host!), out var authTokenCallbackPromise))
                    {
                        var result = await authTokenCallbackPromise.Task;
                        cdnToken = result.Token;
                    }

                    DebugLog.WriteLine("ContentDownloader", "Downloading chunk {0} from {1} with {2}", chunkId, connection, cdnPool.ProxyServer != null ? cdnPool.ProxyServer : "no proxy");
                    written = await cdnPool.CdnClient.DownloadDepotChunkAsync(
                        depot.DepotId,
                        data,
                        connection,
                        chunkBuffer,
                        depot.DepotKey,
                        cdnPool.ProxyServer,
                        cdnToken
                    ).ConfigureAwait(false);

                    cdnPool.ReturnConnection(connection);

                    break;
                }
                catch (TaskCanceledException)
                {
                    Console.WriteLine("Connection timeout downloading chunk {0}", chunkId);
                }
                catch (SteamKitWebRequestException e)
                {
                    // If the CDN returned 403, attempt to get a cdn auth if we didn't yet,
                    // if auth task already exists, make sure it didn't complete yet, so that it gets awaited above
                    if (e.StatusCode == HttpStatusCode.Forbidden &&
                        (!steam3.CdnAuthTokens.TryGetValue((depot!.DepotId, connection!.Host!), out var authTokenCallbackPromise) || !authTokenCallbackPromise.Task.IsCompleted))
                    {
                        await steam3.RequestCdnAuthToken(depot.AppId, depot.DepotId, connection);

                        cdnPool.ReturnConnection(connection);

                        continue;
                    }

                    cdnPool.ReturnBrokenConnection(connection);

                    if (e.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                    {
                        Console.WriteLine("Encountered {1} for chunk {0}. Aborting.", chunkId, (int)e.StatusCode);
                        break;
                    }

                    Console.WriteLine("Encountered error downloading chunk {0}: {1}", chunkId, e.StatusCode);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception e)
                {
                    cdnPool.ReturnBrokenConnection(connection);
                    Console.WriteLine("Encountered unexpected error downloading chunk {0}: {1}", chunkId, e.Message);
                }
            }
            while (written == 0);

            if (written == 0)
            {
                Console.WriteLine("Failed to find any server with chunk {0} for depot {1}. Aborting.", chunkId, depot!.DepotId);
                await cts.CancelAsync();
            }

            // Throw the cancellation exception if requested so that this task is marked failed
            cts.Token.ThrowIfCancellationRequested();

            try
            {
                await fileStreamData.FileLock!.WaitAsync().ConfigureAwait(false);

                if (fileStreamData.FileStream == null)
                {
                    var fileFinalPath = Path.Combine(depot!.InstallDir, file.FileName);
                    fileStreamData.FileStream = File.Open(fileFinalPath, FileMode.Open);
                }

                fileStreamData.FileStream.Seek((long)data.Offset, SeekOrigin.Begin);
                await fileStreamData.FileStream.WriteAsync(chunkBuffer.AsMemory(0, written), cts.Token);
            }
            finally
            {
                fileStreamData.FileLock!.Release();
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(chunkBuffer);
        }

        var remainingChunks = Interlocked.Decrement(ref fileStreamData.ChunksToDownload);
        if (remainingChunks == 0)
        {
            await fileStreamData.FileStream.DisposeAsync();
            fileStreamData.FileLock.Dispose();
        }

        ulong sizeDownloaded;
        lock (depotDownloadCounter!)
        {
            sizeDownloaded                              =  depotDownloadCounter.SizeDownloaded + (ulong)written;
            depotDownloadCounter.SizeDownloaded         =  sizeDownloaded;
            depotDownloadCounter.DepotBytesCompressed   += chunk.CompressedLength;
            depotDownloadCounter.DepotBytesUncompressed += chunk.UncompressedLength;
        }

        lock (downloadCounter)
        {
            downloadCounter.TotalBytesCompressed   += chunk.CompressedLength;
            downloadCounter.TotalBytesUncompressed += chunk.UncompressedLength;

            // TODO: Ansi.Progress(downloadCounter.TotalBytesUncompressed, downloadCounter.CompleteDownloadSize);
        }

        if (remainingChunks == 0)
        {
            var fileFinalPath = Path.Combine(depot!.InstallDir, file.FileName);
            Console.WriteLine($"{sizeDownloaded / (float)depotDownloadCounter.CompleteDownloadSize * 100.0f,6:#00.00}% {fileFinalPath}");
        }
    }

    private static void DumpManifestToTextFile(DepotDownloadInfo depot, DepotManifest manifest)
    {
        var       txtManifest = Path.Combine(depot.InstallDir, $"manifest_{depot.DepotId}_{depot.ManifestId}.txt");
        using var sw          = new StreamWriter(txtManifest);

        sw.WriteLine($"Content Manifest for Depot {depot.DepotId}");
        sw.WriteLine();
        sw.WriteLine($"Manifest ID / date     : {depot.ManifestId} / {manifest.CreationTime}");

        int   numFiles         = 0, numChunks      = 0;
        ulong uncompressedSize = 0, compressedSize = 0;

        foreach (var file in manifest.Files)
        {
            if (file.Flags.HasFlag(EDepotFileFlag.Directory))
            {
                continue;
            }

            numFiles++;
            numChunks += file.Chunks.Count;

            foreach (var chunk in file.Chunks)
            {
                uncompressedSize += chunk.UncompressedLength;
                compressedSize   += chunk.CompressedLength;
            }
        }

        sw.WriteLine($"Total number of files  : {numFiles}");
        sw.WriteLine($"Total number of chunks : {numChunks}");
        sw.WriteLine($"Total bytes on disk    : {uncompressedSize}");
        sw.WriteLine($"Total bytes compressed : {compressedSize}");
        sw.WriteLine();
        sw.WriteLine("          Size Chunks File SHA                                 Flags Name");

        foreach (var file in manifest.Files)
        {
            var sha1Hash = BitConverter.ToString(file.FileHash).Replace("-", "");
            sw.WriteLine($"{file.TotalSize,14} {file.Chunks.Count,6} {sha1Hash} {file.Flags,5:D} {file.FileName}");
        }
    }
}