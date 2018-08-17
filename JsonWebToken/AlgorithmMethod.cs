using System.Diagnostics.CodeAnalysis;

namespace JsonWebToken
{
    /// <summary>
    /// Algorithm methods supported by <see cref="JsonWebToken"/>.
    /// </summary>
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    public enum AlgorithmMethod
    {
        HS256,
        HS384,
        HS512
    }
}
