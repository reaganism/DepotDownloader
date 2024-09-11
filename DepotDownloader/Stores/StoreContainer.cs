using System;
using System.Diagnostics;

namespace DepotDownloader.Stores;

/// <summary>
///     A thin wrapper around <see cref="IStore{T}"/> types that handles
///     singleton management and provides direct access to saving and loading
///     store files.
/// </summary>
/// <typeparam name="T">The store type.</typeparam>
internal readonly record struct StoreContainer<T> where T : IStore<T>
{
    private static T? instance;

#pragma warning disable CA1822 // Instanced members for intuitive syntax.
    /// <summary>
    ///     The store instance.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    ///     If access is attempted before the store has been loaded.
    /// </exception>
    public T Store => instance ?? throw new InvalidOperationException("Store not loaded");

    /// <summary>
    ///     Whether the store has been loaded.
    /// </summary>
    public bool Loaded => instance is not null;

    /// <summary>
    ///     Saves the store instance to disk.
    /// </summary>
    public void Save()
    {
        Debug.Assert(instance is not null);

        instance.Save();
    }

    /// <summary>
    ///     Loads the store instance from disk.
    /// </summary>
    /// <param name="fileName">The file name to load from.</param>
    /// <param name="throwIfLoaded">
    ///     Whether to throw an exception if the store has already been loaded.
    /// </param>
    public void LoadFromFile(string fileName, bool throwIfLoaded)
    {
        instance = T.LoadFromFile(fileName, throwIfLoaded);
    }
#pragma warning restore CA1822
}