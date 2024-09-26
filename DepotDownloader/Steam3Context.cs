using System;

using DepotDownloader.Net.Http;

using SteamKit2;
using SteamKit2.Internal;

namespace DepotDownloader;

public readonly record struct Steam3Context(
    SteamUser.LogOnDetails                              LogOnDetails,
    bool                                                UseQrCode,
    SteamClient                                         SteamClient,
    SteamUser                                           SteamUser,
    SteamApps                                           SteamApps,
    SteamCloud                                          SteamCloud,
    SteamUnifiedMessages.UnifiedService<IPublishedFile> SteamPublishedFile,
    SteamContent                                        SteamContent
)
{
    public bool AuthenticatedUser => LogOnDetails.Username is not null || UseQrCode;

    public static Steam3Context FromLogOnDetails(
        SteamUser.LogOnDetails details,
        bool                   useQrCode
    )
    {
        var clientConfiguration = SteamConfiguration.Create(
            x => x.WithHttpClientFactory(WorkaroundHttpClientFactory.CreateHttpClient)
        );

        SteamUnifiedMessages.UnifiedService<IPublishedFile> steamPublishedFile;

        var steamClient          = new SteamClient(clientConfiguration);
        var steamUser            = steamClient.GetHandler<SteamUser>()            ?? throw new InvalidOperationException("Cannot get SteamUser handler");
        var steamApps            = steamClient.GetHandler<SteamApps>()            ?? throw new InvalidOperationException("Cannot get SteamApps handler");
        var steamCloud           = steamClient.GetHandler<SteamCloud>()           ?? throw new InvalidOperationException("Cannot get SteamCloud handler");
        var steamUnifiedMessages = steamClient.GetHandler<SteamUnifiedMessages>() ?? throw new InvalidOperationException("Cannot get SteamUnifiedMessages handler");
        {
            steamPublishedFile = steamUnifiedMessages.CreateService<IPublishedFile>() ?? throw new InvalidOperationException("Cannot create IPublishedFile service");
        }
        var steamContent = steamClient.GetHandler<SteamContent>() ?? throw new InvalidOperationException("Cannot get SteamContent handler");

        return new Steam3Context(
            details,
            useQrCode,
            steamClient,
            steamUser,
            steamApps,
            steamCloud,
            steamPublishedFile,
            steamContent
        );
    }
}