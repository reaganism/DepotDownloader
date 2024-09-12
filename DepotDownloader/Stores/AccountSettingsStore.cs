// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.IO.IsolatedStorage;

using ProtoBuf;

namespace DepotDownloader.Stores;

/// <summary>
///     Store for account settings.
/// </summary>
[ProtoContract]
internal sealed class AccountSettingsStore
{
#region Proto members
    [ProtoMember(1, IsRequired = false)]
    public Dictionary<string, byte[]> SentryData { get; private set; } = [];

    [ProtoMember(2, IsRequired = false)]
    public ConcurrentDictionary<string, int> ContentServerPenalty { get; private set; } = [];

    [ProtoMember(3, IsRequired = false)]
    public Dictionary<string, string> LoginKeys { get; private set; } = [];

    [ProtoMember(4, IsRequired = false)]
    public Dictionary<string, string> LoginTokens { get; private set; } = [];

    [ProtoMember(5, IsRequired = false)]
    public Dictionary<string, string> GuardData { get; private set; } = [];
#endregion

    private string? fileName;

    private static readonly IsolatedStorageFile isolated_storage = IsolatedStorageFile.GetUserStoreForAssembly();

    private AccountSettingsStore(string fileName)
    {
        this.fileName = fileName;
    }

#region IStore impl
    public void Save()
    {
        Debug.Assert(fileName is not null);

        try
        {
            using var fs = isolated_storage.OpenFile(fileName, FileMode.Create, FileAccess.Write);
            using var ds = new DeflateStream(fs, CompressionMode.Compress);
            Serializer.Serialize(ds, this);
        }
        catch (IOException ex)
        {
            Console.WriteLine($"Failed to save store \"{GetType().FullName}\": {ex.Message}");
        }
    }

    public static AccountSettingsStore LoadFromFile(string fileName)
    {
        if (!isolated_storage.FileExists(fileName))
        {
            return new AccountSettingsStore(fileName);
        }

        try
        {
            using var fs = isolated_storage.OpenFile(fileName, FileMode.Open, FileAccess.Read);
            using var ds = new DeflateStream(fs, CompressionMode.Decompress);
            {
                var store = Serializer.Deserialize<AccountSettingsStore>(ds);
                store.fileName = fileName;
                return store;
            }
        }
        catch (IOException ex)
        {
            Console.WriteLine("Failed to load account settings: {0}", ex.Message);
            return new AccountSettingsStore(fileName);
        }
    }
#endregion
}