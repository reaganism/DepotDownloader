using DepotDownloader.Platform;
using DepotDownloader.Stores;

using SteamKit2;

namespace DepotDownloader.Models;

public sealed class DepotContext
{
    public Steam3Context Steam3 { get; }

    public AccountSettingsStore AccountSettingsStore { get; }

    public DepotConfigStore DepotConfigStore { get; }

    public IPlatform Platform { get; }

    internal Steam3Session Session { get; }

    private DepotContext(
        Steam3Context        steam3,
        AccountSettingsStore accountSettingsStore,
        DepotConfigStore     depotConfigStore,
        IPlatform            platform,
        Steam3Session        session
    )
    {
        Steam3               = steam3;
        AccountSettingsStore = accountSettingsStore;
        DepotConfigStore     = depotConfigStore;
        Platform             = platform;
        Session              = session;
    }

    public static DepotContext FromLogOnDetails(
        SteamUser.LogOnDetails details,
        bool                   useQrCode,
        AccountSettingsStore   accountSettingsStore,
        DepotConfigStore       depotConfigStore,
        IPlatform?             platform = null
    )
    {
        platform ??= PlatformHelper.CreatePlatform();

        var steam3  = Steam3Context.FromLogOnDetails(details, useQrCode);
        var session = new Steam3Session(steam3);

        return new DepotContext(
            steam3,
            accountSettingsStore,
            depotConfigStore,
            platform,
            session
        );
    }
}