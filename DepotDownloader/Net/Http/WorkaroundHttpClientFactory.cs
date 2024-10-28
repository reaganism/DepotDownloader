// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System.IO;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DepotDownloader.Net.Http;

// See <https://github.com/dotnet/runtime/issues/44686#issuecomment-733797994>
// for an explanation.
internal static class WorkaroundHttpClientFactory
{
    public static HttpClient CreateHttpClient()
    {
        var client = new HttpClient(
            new SocketsHttpHandler
            {
                ConnectCallback = Ipv4ConnectAsync,
            }
        );

        return client;
    }

    private static async ValueTask<Stream> Ipv4ConnectAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        // By default, we create dual-mode sockets:
        // var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);

        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true,
        };

        try
        {
            await socket.ConnectAsync(context.DnsEndPoint, cancellationToken).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}