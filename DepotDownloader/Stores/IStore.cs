namespace DepotDownloader.Stores;

/// <summary>
///     A "store" contract providing simple saving and loading APIs.
/// </summary>
/// <typeparam name="T"></typeparam>
internal interface IStore<out T>
    where T : IStore<T>
{
    /// <summary>
    ///     Saves the store to disk.
    /// </summary>
    void Save();

    /// <summary>
    ///     Loads a store from a file.
    /// </summary>
    /// <param name="fileName">The file name to load from.</param>
    /// <param name="throwIfLoaded">
    ///     Whether to throw an exception if the store has already been loaded.
    /// </param>
    /// <returns>
    ///     The loaded store.
    /// </returns>
    static abstract T LoadFromFile(string fileName, bool throwIfLoaded);
}