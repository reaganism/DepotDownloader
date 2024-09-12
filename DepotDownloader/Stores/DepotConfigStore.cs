// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;

using ProtoBuf;

namespace DepotDownloader.Stores;

/// <summary>
///     Store for depot configs.
/// </summary>
[ProtoContract]
internal sealed class DepotConfigStore
{
#region Proto members
    [ProtoMember(1)]
    public Dictionary<uint, ulong> InstalledManifestIDs { get; private set; } = [];
#endregion

    private string? fileName;

    private DepotConfigStore(string fileName)
    {
        this.fileName = fileName;
    }

    public void Save()
    {
        Debug.Assert(fileName is not null);

        using var fs = File.Open(fileName, FileMode.Create);
        using var ds = new DeflateStream(fs, CompressionMode.Compress);
        Serializer.Serialize(ds, this);
    }

    public static DepotConfigStore LoadFromFile(string fileName, bool throwIfLoaded)
    {
        if (!File.Exists(fileName))
        {
            return new DepotConfigStore(fileName);
        }

        using var fs = File.Open(fileName, FileMode.Open);
        using var ds = new DeflateStream(fs, CompressionMode.Decompress);
        {
            var store = Serializer.Deserialize<DepotConfigStore>(ds);
            store.fileName = fileName;
            return store;
        }
    }
}