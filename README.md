# HKDF.NET
This is a port of [.NET HKDF](https://github.com/dotnet/runtime/blob/v5.0.11/src/libraries/System.Security.Cryptography.Algorithms/src/System/Security/Cryptography/HKDF.cs) to .NET Framework.

- This port keeps everything in a single, standalone file because my primary goal was to use it in PowerShell with `Add-Type`.
- The method signatures are the same as in .NET HKDF, except `Span<byte>` and `ReadOnlySpan<byte>` have been replace with `byte[]` with an offset and length.

## Disclaimer
I am not a cryptographer, so use this at your own risk.
