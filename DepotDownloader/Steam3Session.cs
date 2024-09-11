// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using DepotDownloader.Stores;

using QRCoder;

using SteamKit2;
using SteamKit2.Authentication;
using SteamKit2.CDN;
using SteamKit2.Internal;

using HttpClientFactory = DepotDownloader.Net.HttpClientFactory;

namespace DepotDownloader;

internal sealed class Steam3Session
{
    private bool IsLoggedOn { get; set; }

    public ReadOnlyCollection<SteamApps.LicenseListCallback.License>? Licenses { get; private set; }

    private Dictionary<uint, ulong> AppTokens { get; } = [];

    private Dictionary<uint, ulong> PackageTokens { get; } = [];

    public Dictionary<uint, byte[]> DepotKeys { get; } = [];

    public ConcurrentDictionary<(uint, string), TaskCompletionSource<SteamApps.CDNAuthTokenCallback>> CdnAuthTokens { get; } = [];

    public Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo?> AppInfo { get; } = [];

    public Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo?> PackageInfo { get; } = [];

    public Dictionary<string, byte[]> AppBetaPasswords { get; } = [];

    public SteamClient? SteamClient { get; }

    public SteamUser? SteamUser { get; }

    public SteamContent? SteamContent { get; }

    private readonly SteamApps?                                           steamApps;
    private readonly SteamCloud?                                          steamCloud;
    private readonly SteamUnifiedMessages.UnifiedService<IPublishedFile>? steamPublishedFile;
    private readonly CallbackManager                                      callbacks;
    private readonly bool                                                 authenticatedUser;

    private bool         bConnected;
    private bool         bConnecting;
    private bool         bAborted;
    private bool         bExpectingDisconnectRemote;
    private bool         bDidDisconnect;
    private bool         bIsConnectionRecovery;
    private int          connectionBackoff;
    private int          seq; // more hack fixes
    private DateTime     connectTime;
    private AuthSession? authSession;

    // input
    private readonly SteamUser.LogOnDetails logonDetails;

    private static readonly TimeSpan steam3_timeout = TimeSpan.FromSeconds(30);

    public Steam3Session(SteamUser.LogOnDetails details)
    {
        logonDetails      = details;
        authenticatedUser = details.Username != null || ContentDownloader.CONFIG.UseQrCode;

        var clientConfiguration = SteamConfiguration.Create(
            config => config.WithHttpClientFactory(HttpClientFactory.CreateHttpClient)
        );

        SteamClient = new SteamClient(clientConfiguration);
        SteamUser   = SteamClient.GetHandler<SteamUser>();
        steamApps   = SteamClient.GetHandler<SteamApps>();
        steamCloud  = SteamClient.GetHandler<SteamCloud>();
        var steamUnifiedMessages = SteamClient.GetHandler<SteamUnifiedMessages>();
        {
            steamPublishedFile = steamUnifiedMessages?.CreateService<IPublishedFile>();
        }
        SteamContent = SteamClient.GetHandler<SteamContent>();

        callbacks = new CallbackManager(SteamClient);

        callbacks.Subscribe<SteamClient.ConnectedCallback>(ConnectedCallback);
        callbacks.Subscribe<SteamClient.DisconnectedCallback>(DisconnectedCallback);
        callbacks.Subscribe<SteamUser.LoggedOnCallback>(LogOnCallback);
        callbacks.Subscribe<SteamApps.LicenseListCallback>(LicenseListCallback);

        Console.Write("Connecting to Steam3...");
        Connect();
    }

    private delegate bool WaitCondition();

    private readonly object steamLock = new();

    private void WaitUntilCallback(Action submitter, WaitCondition waiter)
    {
        while (!bAborted && !waiter())
        {
            lock (steamLock)
            {
                submitter();
            }

            var theSeq = seq;
            do
            {
                lock (steamLock)
                {
                    WaitForCallbacks();
                }
            }
            while (!bAborted && seq == theSeq && !waiter());
        }
    }

    public bool WaitForCredentials()
    {
        if (IsLoggedOn || bAborted)
        {
            return IsLoggedOn;
        }

        WaitUntilCallback(() => { }, () => IsLoggedOn);
        return IsLoggedOn;
    }

    public void RequestAppInfo(uint appId, bool bForce = false)
    {
        if (steamApps is null)
        {
            throw new InvalidOperationException("Cannot request app info because SteamApps service is not available.");
        }

        if ((AppInfo.ContainsKey(appId) && !bForce) || bAborted)
        {
            return;
        }

        var completed = false;
        Action<SteamApps.PICSTokensCallback> cbMethodTokens = appTokens =>
        {
            completed = true;
            if (appTokens.AppTokensDenied.Contains(appId))
            {
                Console.WriteLine("Insufficient privileges to get access token for app {0}", appId);
            }

            foreach (var tokenDict in appTokens.AppTokens)
            {
                AppTokens[tokenDict.Key] = tokenDict.Value;
            }
        };

        WaitUntilCallback(
            () => { callbacks.Subscribe(steamApps.PICSGetAccessTokens(new List<uint> { appId }, new List<uint>()), cbMethodTokens); },
            () => completed
        );

        completed = false;
        Action<SteamApps.PICSProductInfoCallback> cbMethod = appInfo =>
        {
            completed = !appInfo.ResponsePending;

            foreach (var app in appInfo.Apps.Select(appValue => appValue.Value))
            {
                Console.WriteLine("Got AppInfo for {0}", app.ID);
                AppInfo[app.ID] = app;
            }

            foreach (var app in appInfo.UnknownApps)
            {
                AppInfo[app] = null;
            }
        };

        var request = new SteamApps.PICSRequest(appId);
        if (AppTokens.TryGetValue(appId, out var token))
        {
            request.AccessToken = token;
        }

        WaitUntilCallback(
            () => { callbacks.Subscribe(steamApps.PICSGetProductInfo(new List<SteamApps.PICSRequest> { request }, new List<SteamApps.PICSRequest>()), cbMethod); },
            () => completed
        );
    }

    public void RequestPackageInfo(IEnumerable<uint> packageIds)
    {
        if (steamApps is null)
        {
            throw new InvalidOperationException("Cannot request package info because SteamApps service is not available.");
        }

        var packages = packageIds.ToList();
        packages.RemoveAll(pid => PackageInfo.ContainsKey(pid));

        if (packages.Count == 0 || bAborted)
        {
            return;
        }

        var completed = false;
        Action<SteamApps.PICSProductInfoCallback> cbMethod = packageInfo =>
        {
            completed = !packageInfo.ResponsePending;

            foreach (var package in packageInfo.Packages.Select(packageValue => packageValue.Value))
            {
                PackageInfo[package.ID] = package;
            }

            foreach (var package in packageInfo.UnknownPackages)
            {
                PackageInfo[package] = null;
            }
        };

        var packageRequests = new List<SteamApps.PICSRequest>();

        foreach (var package in packages)
        {
            var request = new SteamApps.PICSRequest(package);

            if (PackageTokens.TryGetValue(package, out var token))
            {
                request.AccessToken = token;
            }

            packageRequests.Add(request);
        }

        WaitUntilCallback(
            () => { callbacks.Subscribe(steamApps.PICSGetProductInfo(new List<SteamApps.PICSRequest>(), packageRequests), cbMethod); },
            () => completed
        );
    }

    public bool RequestFreeAppLicense(uint appId)
    {
        if (steamApps is null)
        {
            throw new InvalidOperationException("Cannot request free app license because SteamApps service is not available.");
        }

        var success   = false;
        var completed = false;
        Action<SteamApps.FreeLicenseCallback> cbMethod = resultInfo =>
        {
            completed = true;
            success   = resultInfo.GrantedApps.Contains(appId);
        };

        WaitUntilCallback(
            () => { callbacks.Subscribe(steamApps.RequestFreeLicense(appId), cbMethod); },
            () => completed
        );

        return success;
    }

    public void RequestDepotKey(uint depotId, uint appid = 0)
    {
        if (steamApps is null)
        {
            throw new InvalidOperationException("Cannot request depot key because SteamApps service is not available.");
        }

        if (DepotKeys.ContainsKey(depotId) || bAborted)
        {
            return;
        }

        var completed = false;

        Action<SteamApps.DepotKeyCallback> cbMethod = depotKey =>
        {
            completed = true;
            Console.WriteLine("Got depot key for {0} result: {1}", depotKey.DepotID, depotKey.Result);

            if (depotKey.Result != EResult.OK)
            {
                Abort();
                return;
            }

            DepotKeys[depotKey.DepotID] = depotKey.DepotKey;
        };

        WaitUntilCallback(
            () => { callbacks.Subscribe(steamApps.GetDepotDecryptionKey(depotId, appid), cbMethod); },
            () => completed
        );
    }


    public async Task<ulong> GetDepotManifestRequestCodeAsync(uint depotId, uint appId, ulong manifestId, string branch)
    {
        if (bAborted)
        {
            return 0;
        }

        if (SteamContent is null)
        {
            throw new InvalidOperationException("Cannot get depot manifest request code because SteamContent service is not available.");
        }

        var requestCode = await SteamContent.GetManifestRequestCode(depotId, appId, manifestId, branch);

        Console.WriteLine(
            "Got manifest request code for {0} {1} result: {2}",
            depotId,
            manifestId,
            requestCode
        );

        return requestCode;
    }

    public async Task RequestCdnAuthToken(uint appid, uint depotId, Server server)
    {
        Debug.Assert(server.Host is not null);

        if (steamApps is null)
        {
            throw new InvalidOperationException("Cannot request CDN auth token because SteamApps service is not available.");
        }

        var cdnKey     = (depotId, server.Host);
        var completion = new TaskCompletionSource<SteamApps.CDNAuthTokenCallback>();

        if (bAborted || !CdnAuthTokens.TryAdd(cdnKey, completion))
        {
            return;
        }

        DebugLog.WriteLine(nameof(Steam3Session), $"Requesting CDN auth token for {server.Host}");

        var cdnAuth = await steamApps.GetCDNAuthToken(appid, depotId, server.Host);

        Console.WriteLine($"Got CDN auth token for {server.Host} result: {cdnAuth.Result} (expires {cdnAuth.Expiration})");

        if (cdnAuth.Result != EResult.OK)
        {
            return;
        }

        completion.TrySetResult(cdnAuth);
    }

    public void CheckAppBetaPassword(uint appid, string? password)
    {
        if (steamApps is null)
        {
            throw new InvalidOperationException("Cannot check app beta password because SteamApps service is not available.");
        }

        var completed = false;
        Action<SteamApps.CheckAppBetaPasswordCallback> cbMethod = appPassword =>
        {
            completed = true;

            Console.WriteLine("Retrieved {0} beta keys with result: {1}", appPassword.BetaPasswords.Count, appPassword.Result);

            foreach (var entry in appPassword.BetaPasswords)
            {
                AppBetaPasswords[entry.Key] = entry.Value;
            }
        };

        WaitUntilCallback(
            () => { callbacks.Subscribe(steamApps.CheckAppBetaPassword(appid, password!), cbMethod); },
            () => completed
        );
    }

    public PublishedFileDetails GetPublishedFileDetails(uint appId, PublishedFileID pubFile)
    {
        if (steamPublishedFile is null)
        {
            throw new InvalidOperationException("Cannot get published file details because unified PublishedFile service is not available.");
        }

        var pubFileRequest = new CPublishedFile_GetDetails_Request { appid = appId };
        pubFileRequest.publishedfileids.Add(pubFile);

        var completed = false;
        var details   = default(PublishedFileDetails);

        Action<SteamUnifiedMessages.ServiceMethodResponse> cbMethod = callback =>
        {
            completed = true;
            if (callback.Result == EResult.OK)
            {
                var response = callback.GetDeserializedResponse<CPublishedFile_GetDetails_Response>();
                details = response.publishedfiledetails.FirstOrDefault();
            }
            else
            {
                throw new Exception($"EResult {(int)callback.Result} ({callback.Result}) while retrieving file details for pubfile {pubFile}.");
            }
        };

        WaitUntilCallback(
            () => { callbacks.Subscribe(steamPublishedFile.SendMessage(api => api.GetDetails(pubFileRequest)), cbMethod); },
            () => completed
        );

        Debug.Assert(details is not null);
        return details;
    }


    public SteamCloud.UGCDetailsCallback GetUgcDetails(UGCHandle ugcHandle)
    {
        if (steamCloud is null)
        {
            throw new InvalidOperationException("Cannot get UGC details because SteamCloud service is not available.");
        }

        var completed = false;
        var details   = default(SteamCloud.UGCDetailsCallback);

        Action<SteamCloud.UGCDetailsCallback> cbMethod = callback =>
        {
            completed = true;
            details = callback.Result switch
            {
                EResult.OK           => callback,
                EResult.FileNotFound => null,
                _                    => throw new Exception($"EResult {(int)callback.Result} ({callback.Result}) while retrieving UGC details for {ugcHandle}."),
            };
        };

        WaitUntilCallback(
            () => { callbacks.Subscribe(steamCloud.RequestUGCDetails(ugcHandle), cbMethod); },
            () => completed
        );

        Debug.Assert(details is not null);
        return details;
    }

    private void ResetConnectionFlags()
    {
        bExpectingDisconnectRemote = false;
        bDidDisconnect             = false;
        bIsConnectionRecovery      = false;
    }

    private void Connect()
    {
        if (SteamClient is null)
        {
            throw new InvalidOperationException("Cannot connect because SteamClient is not available.");
        }

        bAborted          = false;
        bConnected        = false;
        bConnecting       = true;
        connectionBackoff = 0;
        authSession       = null;

        ResetConnectionFlags();

        connectTime = DateTime.Now;
        SteamClient.Connect();
    }

    private void Abort(bool sendLogOff = true)
    {
        Disconnect(sendLogOff);
    }

    public void Disconnect(bool sendLogOff = true)
    {
        if (SteamUser is null)
        {
            throw new InvalidOperationException("Cannot disconnect because SteamUser is not available.");
        }

        if (SteamClient is null)
        {
            throw new InvalidOperationException("Cannot disconnect because SteamClient is not available.");
        }

        if (sendLogOff)
        {
            SteamUser.LogOff();
        }

        bAborted              = true;
        bConnected            = false;
        bConnecting           = false;
        bIsConnectionRecovery = false;
        SteamClient.Disconnect();

        // TODO: Ansi.Progress(Ansi.ProgressState.Hidden);

        // flush callbacks until our disconnected event
        while (!bDidDisconnect)
        {
            callbacks.RunWaitAllCallbacks(TimeSpan.FromMilliseconds(100));
        }
    }

    private void Reconnect()
    {
        if (SteamClient is null)
        {
            throw new InvalidOperationException("Cannot reconnect because SteamClient is not available.");
        }

        bIsConnectionRecovery = true;
        SteamClient.Disconnect();
    }

    private void WaitForCallbacks()
    {
        callbacks.RunWaitCallbacks(TimeSpan.FromSeconds(1));

        var diff = DateTime.Now - connectTime;

        if (diff <= steam3_timeout || bConnected)
        {
            return;
        }

        Console.WriteLine("Timeout connecting to Steam3.");
        Abort();
    }

    private async void ConnectedCallback(SteamClient.ConnectedCallback connected)
    {
        if (SteamUser is null)
        {
            throw new InvalidOperationException("Cannot handle connected callback because SteamUser is not available.");
        }

        if (SteamClient is null)
        {
            throw new InvalidOperationException("Cannot handle connected callback because SteamClient is not available.");
        }

        Console.WriteLine(" Done!");
        bConnecting = false;
        bConnected  = true;

        // Update our tracking so that we don't time out, even if we need to
        // reconnect multiple times, e.g. if the authentication phase takes a
        // while and therefore multiple connections.
        connectTime       = DateTime.Now;
        connectionBackoff = 0;

        if (!authenticatedUser)
        {
            Console.Write("Logging anonymously into Steam3...");
            SteamUser.LogOnAnonymous();
        }
        else
        {
            if (logonDetails.Username != null)
            {
                Console.WriteLine("Logging '{0}' into Steam3...", logonDetails.Username);
            }

            if (authSession is null)
            {
                if (logonDetails is { Username: not null, Password: not null, AccessToken: null })
                {
                    try
                    {
                        _ = AccountSettingsStore.CONTAINER.Store.GuardData.TryGetValue(logonDetails.Username, out var guardData);
                        authSession = await SteamClient.Authentication.BeginAuthSessionViaCredentialsAsync(
                            new AuthSessionDetails
                            {
                                Username            = logonDetails.Username,
                                Password            = logonDetails.Password,
                                IsPersistentSession = ContentDownloader.CONFIG.RememberPassword,
                                GuardData           = guardData,
                                Authenticator       = new UserConsoleAuthenticator(),
                            }
                        );
                    }
                    catch (TaskCanceledException)
                    {
                        return;
                    }
                    catch (Exception ex)
                    {
                        await Console.Error.WriteLineAsync("Failed to authenticate with Steam: " + ex.Message);
                        Abort(false);
                        return;
                    }
                }
                else if (logonDetails.AccessToken is null && ContentDownloader.CONFIG.UseQrCode)
                {
                    Console.WriteLine("Logging in with QR code...");

                    try
                    {
                        var session = await SteamClient.Authentication.BeginAuthSessionViaQRAsync(
                            new AuthSessionDetails
                            {
                                IsPersistentSession = ContentDownloader.CONFIG.RememberPassword,
                                Authenticator       = new UserConsoleAuthenticator(),
                            }
                        );

                        authSession = session;

                        // Steam will periodically refresh the challenge url, so
                        // we need a new QR code.
                        session.ChallengeURLChanged = () =>
                        {
                            Console.WriteLine();
                            Console.WriteLine("The QR code has changed:");

                            DisplayQrCode(session.ChallengeURL);
                        };

                        // Draw initial QR code immediately
                        DisplayQrCode(session.ChallengeURL);
                    }
                    catch (TaskCanceledException)
                    {
                        return;
                    }
                    catch (Exception ex)
                    {
                        await Console.Error.WriteLineAsync("Failed to authenticate with Steam: " + ex.Message);
                        Abort(false);
                        return;
                    }
                }
            }

            if (authSession != null)
            {
                try
                {
                    var result = await authSession.PollingWaitForResultAsync();

                    logonDetails.Username    = result.AccountName;
                    logonDetails.Password    = null;
                    logonDetails.AccessToken = result.RefreshToken;

                    if (result.NewGuardData != null)
                    {
                        AccountSettingsStore.CONTAINER.Store.GuardData[result.AccountName] = result.NewGuardData;
                    }
                    else
                    {
                        AccountSettingsStore.CONTAINER.Store.GuardData.Remove(result.AccountName);
                    }
                    AccountSettingsStore.CONTAINER.Store.LoginTokens[result.AccountName] = result.RefreshToken;
                    AccountSettingsStore.CONTAINER.Save();
                }
                catch (TaskCanceledException)
                {
                    return;
                }
                catch (Exception ex)
                {
                    await Console.Error.WriteLineAsync("Failed to authenticate with Steam: " + ex.Message);
                    Abort(false);
                    return;
                }

                authSession = null;
            }

            SteamUser.LogOn(logonDetails);
        }
    }

    private void DisconnectedCallback(SteamClient.DisconnectedCallback disconnected)
    {
        if (SteamClient is null)
        {
            throw new InvalidOperationException("Cannot handle disconnected callback because SteamClient is not available.");
        }

        bDidDisconnect = true;

        DebugLog.WriteLine(nameof(Steam3Session), $"Disconnected: bIsConnectionRecovery = {bIsConnectionRecovery}, UserInitiated = {disconnected.UserInitiated}, bExpectingDisconnectRemote = {bExpectingDisconnectRemote}");

        // When recovering the connection, we want to reconnect even if the
        // remote disconnects us.
        if (!bIsConnectionRecovery && (disconnected.UserInitiated || bExpectingDisconnectRemote))
        {
            Console.WriteLine("Disconnected from Steam");

            // Any operations outstanding need to be aborted
            bAborted = true;
        }
        else if (connectionBackoff >= 10)
        {
            Console.WriteLine("Could not connect to Steam after 10 tries");
            Abort(false);
        }
        else if (!bAborted)
        {
            Console.WriteLine(bConnecting ? "Connection to Steam failed. Trying again" : "Lost connection to Steam. Reconnecting");

            Thread.Sleep(1000 * ++connectionBackoff);

            // Any connection related flags need to be reset here to match the state after Connect
            ResetConnectionFlags();
            SteamClient.Connect();
        }
    }

    private void LogOnCallback(SteamUser.LoggedOnCallback loggedOn)
    {
        var isSteamGuard = loggedOn.Result == EResult.AccountLogonDenied;
        var is2Fa        = loggedOn.Result == EResult.AccountLoginDeniedNeedTwoFactor;
        var isAccessToken = ContentDownloader.CONFIG.RememberPassword && logonDetails.AccessToken != null &&
                            loggedOn.Result is EResult.InvalidPassword
                                            or EResult.InvalidSignature
                                            or EResult.AccessDenied
                                            or EResult.Expired
                                            or EResult.Revoked;

        if (isSteamGuard || is2Fa || isAccessToken)
        {
            bExpectingDisconnectRemote = true;
            Abort(false);

            if (!isAccessToken)
            {
                Console.WriteLine("This account is protected by Steam Guard.");
            }

            if (is2Fa)
            {
                do
                {
                    Console.Write("Please enter your 2 factor auth code from your authenticator app: ");
                    logonDetails.TwoFactorCode = Console.ReadLine();
                }
                while (string.Empty == logonDetails.TwoFactorCode);
            }
            else if (isAccessToken)
            {
                Debug.Assert(logonDetails.Username is not null);
                AccountSettingsStore.CONTAINER.Store.LoginTokens.Remove(logonDetails.Username);
                AccountSettingsStore.CONTAINER.Save();

                // TODO: Handle gracefully by falling back to password prompt?
                Console.WriteLine($"Access token was rejected ({loggedOn.Result}).");
                Abort(false);
                return;
            }
            else
            {
                do
                {
                    Console.Write("Please enter the authentication code sent to your email address: ");
                    logonDetails.AuthCode = Console.ReadLine();
                }
                while (string.Empty == logonDetails.AuthCode);
            }

            Console.Write("Retrying Steam3 connection...");
            Connect();

            return;
        }

        if (loggedOn.Result == EResult.TryAnotherCM)
        {
            Console.Write("Retrying Steam3 connection (TryAnotherCM)...");

            Reconnect();

            return;
        }

        if (loggedOn.Result == EResult.ServiceUnavailable)
        {
            Console.WriteLine("Unable to login to Steam3: {0}", loggedOn.Result);
            Abort(false);

            return;
        }

        if (loggedOn.Result != EResult.OK)
        {
            Console.WriteLine("Unable to login to Steam3: {0}", loggedOn.Result);
            Abort();

            return;
        }

        Console.WriteLine(" Done!");

        seq++;
        IsLoggedOn = true;

        if (ContentDownloader.CONFIG.CellId == 0)
        {
            Console.WriteLine("Using Steam3 suggested CellID: " + loggedOn.CellID);
            ContentDownloader.CONFIG.CellId = (int)loggedOn.CellID;
        }
    }

    private void LicenseListCallback(SteamApps.LicenseListCallback licenseList)
    {
        if (licenseList.Result != EResult.OK)
        {
            Console.WriteLine("Unable to get license list: {0} ", licenseList.Result);
            Abort();

            return;
        }

        Console.WriteLine("Got {0} licenses for account!", licenseList.LicenseList.Count);
        Licenses = licenseList.LicenseList;

        foreach (var license in licenseList.LicenseList)
        {
            if (license.AccessToken > 0)
            {
                PackageTokens.TryAdd(license.PackageID, license.AccessToken);
            }
        }
    }

    private static void DisplayQrCode(string challengeUrl)
    {
        // Encode the link as a QR code
        using var qrGenerator      = new QRCodeGenerator();
        var       qrCodeData       = qrGenerator.CreateQrCode(challengeUrl, QRCodeGenerator.ECCLevel.L);
        using var qrCode           = new AsciiQRCode(qrCodeData);
        var       qrCodeAsAsciiArt = qrCode.GetGraphic(1, drawQuietZones: false);

        Console.WriteLine("Use the Steam Mobile App to sign in with this QR code:");
        Console.WriteLine(qrCodeAsAsciiArt);
    }
}