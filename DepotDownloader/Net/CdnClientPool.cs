// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using DepotDownloader.Stores;

using SteamKit2.CDN;

namespace DepotDownloader.Net;

/// <summary>
///     Provides a pool of connections to CDN endpoints, requesting CDN tokens
///     as needed.
/// </summary>
internal sealed class CdnClientPool
{
    private const int server_endpoint_minimum_size = 8;

    public Client CdnClient { get; }

    public Server? ProxyServer { get; private set; }

    public CancellationTokenSource? ExhaustedToken { get; set; }

    private readonly Steam3Session steamSession;
    private readonly uint          appId;

    private readonly ConcurrentStack<Server>    activeConnectionPool     = [];
    private readonly BlockingCollection<Server> availableServerEndpoints = [];

    private readonly AutoResetEvent          populatePoolEvent = new(true);
    private readonly Task                    monitorTask;
    private readonly CancellationTokenSource shutdownToken = new();

    public CdnClientPool(Steam3Session steamSession, uint appId)
    {
        if (steamSession.SteamClient is null)
        {
            throw new InvalidOperationException("Cannot create CDN client pool, Steam session as null Steam client!");
        }

        this.steamSession = steamSession;
        this.appId        = appId;
        CdnClient         = new Client(steamSession.SteamClient);

        monitorTask = Task.Factory.StartNew(ConnectionPoolMonitorAsync).Unwrap();
    }

    public void Shutdown()
    {
        shutdownToken.Cancel();
        monitorTask.Wait();
    }

    private async Task<IReadOnlyCollection<Server>?> FetchBootstrapServerListAsync()
    {
        try
        {
            Debug.Assert(steamSession.SteamContent is not null);

            var cdnServers = await steamSession.SteamContent.GetServersForSteamPipe();
            return cdnServers;
        }
        catch (Exception ex)
        {
            Console.WriteLine("Failed to retrieve content server list: {0}", ex.Message);
        }

        return null;
    }

    private async Task ConnectionPoolMonitorAsync()
    {
        Debug.Assert(steamSession.SteamClient is not null);

        var didPopulate = false;

        while (!shutdownToken.IsCancellationRequested)
        {
            populatePoolEvent.WaitOne(TimeSpan.FromSeconds(1));

            // We want the Steam session so we can take the CellID from the
            // session and pass it through to the ContentServer Directory
            // Service.
            if (availableServerEndpoints.Count < server_endpoint_minimum_size && steamSession.SteamClient.IsConnected)
            {
                var servers = await FetchBootstrapServerListAsync().ConfigureAwait(false);
                if (servers is null || servers.Count == 0)
                {
                    if (ExhaustedToken is not null)
                    {
                        await ExhaustedToken.CancelAsync();
                    }
                    return;
                }

                ProxyServer = servers.FirstOrDefault(x => x.UseAsProxy);

                var weightedCdnServers = servers
                                        .Where(
                                             server =>
                                             {
                                                 var isEligibleForApp = server.AllowedAppIds.Length == 0 || server.AllowedAppIds.Contains(appId);
                                                 return isEligibleForApp && server.Type is "SteamCache" or "CDN";
                                             }
                                         )
                                        .Select(
                                             server =>
                                             {
                                                 if (server.Host is null)
                                                 {
                                                     throw new InvalidOperationException("Server host is null");
                                                 }

                                                 AccountSettingsStore.CONTAINER.Store.ContentServerPenalty.TryGetValue(server.Host, out var penalty);
                                                 return (server, penalty);
                                             }
                                         )
                                        .OrderBy(pair => pair.penalty).ThenBy(pair => pair.server.WeightedLoad);

                foreach (var (server, _) in weightedCdnServers)
                {
                    for (var i = 0; i < server.NumEntries; i++)
                    {
                        availableServerEndpoints.Add(server);
                    }
                }

                didPopulate = true;
            }
            else if (availableServerEndpoints.Count == 0 && !steamSession.SteamClient.IsConnected && didPopulate)
            {
                if (ExhaustedToken is not null)
                {
                    await ExhaustedToken.CancelAsync();
                }
                return;
            }
        }
    }

    private Server BuildConnection(CancellationToken token)
    {
        if (availableServerEndpoints.Count < server_endpoint_minimum_size)
        {
            populatePoolEvent.Set();
        }

        return availableServerEndpoints.Take(token);
    }

    public Server GetConnection(CancellationToken token)
    {
        if (!activeConnectionPool.TryPop(out var connection))
        {
            connection = BuildConnection(token);
        }

        return connection;
    }

    public void ReturnConnection(Server server)
    {
        Debug.Assert(server is not null);
        activeConnectionPool.Push(server);
    }

    public void ReturnBrokenConnection(Server? server)
    {
        Debug.Assert(server is not null);
    }
}