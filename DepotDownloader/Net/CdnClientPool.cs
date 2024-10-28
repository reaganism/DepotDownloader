// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using DepotDownloader.Models;
using DepotDownloader.Stores;
using DepotDownloader.Utilities;

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

    private readonly DepotContext ctx;
    private readonly uint         appId;

    private readonly ConcurrentStack<Server>    activeConnectionPool     = [];
    private readonly BlockingCollection<Server> availableServerEndpoints = [];

    private readonly AutoResetEvent          populatePoolEvent = new(true);
    private readonly CancellationTokenSource shutdownToken     = new();

    private readonly Task monitorTask;

    public CdnClientPool(DepotContext ctx, uint appId)
    {
        this.ctx   = ctx;
        this.appId = appId;
        CdnClient  = new Client(ctx.Steam3.SteamClient);

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
            return await ctx.Steam3.SteamContent.GetServersForSteamPipe();
        }
        catch (Exception ex)
        {
            Console.WriteLine("Failed to retrieve content server list: {0}", ex.Message);
        }

        return null;
    }

    private async Task ConnectionPoolMonitorAsync()
    {
        var didPopulate = false;

        while (!shutdownToken.IsCancellationRequested)
        {
            populatePoolEvent.WaitOne(TimeSpan.FromSeconds(1));

            // We want the Steam session so we can take the CellID from the
            // session and pass it through to the ContentServer Directory
            // Service.
            if (availableServerEndpoints.Count < server_endpoint_minimum_size && ctx.Steam3.SteamClient.IsConnected)
            {
                var servers = await FetchBootstrapServerListAsync().ConfigureAwait(false);
                if (servers is not { Count: > 0 })
                {
                    await ExhaustedToken.CancelNullableAsync();
                    return;
                }

                ProxyServer = servers.FirstOrDefault(x => x.UseAsProxy);

                var weightedCdnServers = servers.Where(
                    x =>
                    {
                        var isEligibleForApp = x.AllowedAppIds.Length == 0 || x.AllowedAppIds.Contains(appId);
                        return isEligibleForApp && x.Type is "SteamCache" or "CDN";
                    }
                ).Select(
                    x =>
                    {
                        if (x.Host is null)
                        {
                            throw new InvalidOperationException("Server host is null");
                        }

                        ctx.AccountSettingsStore.ContentServerPenalty.TryGetValue(x.Host, out var penalty);
                        return (server: x, penalty);
                    }
                ).OrderBy(x => x.penalty).ThenBy(x => x.server.WeightedLoad);

                foreach (var (server, _) in weightedCdnServers)
                {
                    for (var i = 0; i < server.NumEntries; i++)
                    {
                        availableServerEndpoints.Add(server);
                    }
                }

                didPopulate = true;
            }
            else if (availableServerEndpoints.Count == 0 && !ctx.Steam3.SteamClient.IsConnected && didPopulate)
            {
                await ExhaustedToken.CancelNullableAsync();
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
        activeConnectionPool.Push(server);
    }

#pragma warning disable CA1822
    // ReSharper disable once MemberCanBeMadeStatic.Global
    public void ReturnBrokenConnection(Server? server) { }
#pragma warning restore CA1822
}