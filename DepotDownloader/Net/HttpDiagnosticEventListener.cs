// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Diagnostics.Tracing;
using System.Text;

namespace DepotDownloader.Net;

/// <summary>
///     A simple HTTP event listener that writes events to the console.
/// </summary>
internal sealed class HttpDiagnosticEventListener : EventListener
{
    private const EventKeywords task_flows_activity_ids = (EventKeywords)0x80;

    protected override void OnEventSourceCreated(EventSource eventSource)
    {
        switch (eventSource.Name)
        {
            case "System.Net.Http":
            case "System.Net.Sockets":
            case "System.Net.Security":
            case "System.Net.NameResolution":
                EnableEvents(eventSource, EventLevel.LogAlways);
                break;

            case "System.Threading.Tasks.TplEventSource":
                EnableEvents(eventSource, EventLevel.LogAlways, task_flows_activity_ids);
                break;
        }
    }

    protected override void OnEventWritten(EventWrittenEventArgs eventData)
    {
        var sb = new StringBuilder();
        {
            sb.Append($"{eventData.TimeStamp:HH:mm:ss.fffffff}  {eventData.EventSource.Name}.{eventData.EventName}(");
            {
                for (var i = 0; i < eventData.Payload?.Count; i++)
                {
                    sb.Append(eventData.PayloadNames?[i]).Append(": ").Append(eventData.Payload[i]);
                    if (i < eventData.Payload?.Count - 1)
                    {
                        sb.Append(", ");
                    }
                }
            }
            sb.Append(')');
        }

        Console.WriteLine(sb.ToString());
    }
}