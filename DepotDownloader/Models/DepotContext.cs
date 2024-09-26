using SteamKit2;

namespace DepotDownloader.Models;

public sealed class DepotContext
{
    public Steam3Context Steam3 { get; }

    internal Steam3Session Session { get; }

    internal DepotContext(Steam3Context steam3, Steam3Session session)
    {
        Steam3  = steam3;
        Session = session;
    }

    public static DepotContext FromLogOnDetails(
        SteamUser.LogOnDetails details,
        bool                   useQrCode
    )
    {
        var steam3  = Steam3Context.FromLogOnDetails(details, useQrCode);
        var session = new Steam3Session(steam3);

        return new DepotContext(steam3, session);
    }
}