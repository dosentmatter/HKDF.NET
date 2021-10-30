// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Runtime.Versioning;

namespace System.Security.Cryptography
{
    /// <summary>
    /// RFC5869  HMAC-based Extract-and-Expand Key Derivation (HKDF)
    /// </summary>
    /// <remarks>
    /// In situations where the input key material is already a uniformly random bitstring, the HKDF standard allows the Extract
    /// phase to be skipped, and the master key to be used directly as the pseudorandom key.
    /// See <a href="https://tools.ietf.org/html/rfc5869">RFC5869</a> for more information.
    /// </remarks>
    public static class HKDF
    {
        private const string Cryptography_Prk_TooSmall = "The pseudo-random key length must be {0} bytes.";
        private const string Cryptography_Okm_TooLarge = "Output keying material length can be at most {0} bytes (255 * hash length)";
        private const string Arg_CryptographyException = "Error occurred during a cryptographic operation.";

        /// <summary>
        /// Performs the HKDF-Extract function.
        /// See section 2.2 of <a href="https://tools.ietf.org/html/rfc5869#section-2.2">RFC5869</a>
        /// </summary>
        /// <param name="hashAlgorithmName">The hash algorithm used for HMAC operations.</param>
        /// <param name="ikm">The input keying material.</param>
        /// <param name="salt">The optional salt value (a non-secret random value). If not provided it defaults to a byte array of <see cref="HashLength"/> zeros.</param>
        /// <returns>The pseudo random key (prk).</returns>
        public static byte[] Extract(HashAlgorithmName hashAlgorithmName, byte[] ikm, byte[] salt = null)
        {
            if (ikm == null)
                throw new ArgumentNullException("ikm");

            int hashLength = HashLength(hashAlgorithmName);
            byte[] prk = new byte[hashLength];

            Extract(hashAlgorithmName, hashLength, ikm, salt, prk);
            return prk;
        }

        /// <summary>
        /// Performs the HKDF-Extract function.
        /// See section 2.2 of <a href="https://tools.ietf.org/html/rfc5869#section-2.2">RFC5869</a>
        /// </summary>
        /// <param name="hashAlgorithmName">The hash algorithm used for HMAC operations.</param>
        /// <param name="ikm">The input keying material.</param>
        /// <param name="salt">The salt value (a non-secret random value).</param>
        /// <param name="prk">The destination buffer to receive the pseudo-random key (prk).</param>
        /// <returns>The number of bytes written to the <paramref name="prk"/> buffer.</returns>
        public static int Extract(
            HashAlgorithmName hashAlgorithmName,
            /* ReadOnly */ byte[] ikm,
            /* ReadOnly */ byte[] salt,
            byte[] prk,
            int ikmOffset = 0,
            int ikmLength = -1,
            int saltOffset = 0,
            int saltLength = -1,
            int prkOffset = 0,
            int prkLength = -1
        )
        {
            SanitizeSpan(ref prk, ref prkOffset, ref prkLength);

            int hashLength = HashLength(hashAlgorithmName);

            if (prkLength < hashLength)
            {
                throw new ArgumentException(string.Format(Cryptography_Prk_TooSmall, hashLength), "prk");
            }

            if (prkLength > hashLength)
            {
                prkLength = hashLength;
            }

            Extract(
                hashAlgorithmName,
                hashLength,
                ikm,
                salt,
                prk,
                ikmOffset,
                ikmLength,
                saltOffset,
                saltLength,
                prkOffset,
                prkLength
            );
            return hashLength;
        }

        private static void Extract(
            HashAlgorithmName hashAlgorithmName,
            int hashLength,
            /* ReadOnly */ byte[] ikm,
            /* ReadOnly */ byte[] salt,
            byte[] prk,
            int ikmOffset = 0,
            int ikmLength = -1,
            int saltOffset = 0,
            int saltLength = -1,
            int prkOffset = 0,
            int prkLength = -1
        )
        {
            SanitizeSpan(ref ikm, ref ikmOffset, ref ikmLength);
            SanitizeSpan(ref salt, ref saltOffset, ref saltLength);
            SanitizeSpan(ref prk, ref prkOffset, ref prkLength);

            Debug.Assert(HashLength(hashAlgorithmName) == hashLength);

            SliceSpan(ref salt, ref saltOffset, ref saltLength);
            using (IncrementalHash hmac = IncrementalHash.CreateHMAC(hashAlgorithmName, salt))
            {
                hmac.AppendData(ikm, ikmOffset, ikmLength);
                GetHashAndReset(hmac, prk, prkOffset, prkLength);
            }
        }

        /// <summary>
        /// Performs the HKDF-Expand function
        /// See section 2.3 of <a href="https://tools.ietf.org/html/rfc5869#section-2.3">RFC5869</a>
        /// </summary>
        /// <param name="hashAlgorithmName">The hash algorithm used for HMAC operations.</param>
        /// <param name="prk">The pseudorandom key of at least <see cref="HashLength"/> bytes (usually the output from Expand step).</param>
        /// <param name="outputLength">The length of the output keying material.</param>
        /// <param name="info">The optional context and application specific information.</param>
        /// <returns>The output keying material.</returns>
        public static byte[] Expand(HashAlgorithmName hashAlgorithmName, byte[] prk, int outputLength, byte[] info = null)
        {
            if (prk == null)
                throw new ArgumentNullException("prk");

            int hashLength = HashLength(hashAlgorithmName);

            // Constant comes from section 2.3 (the constraint on L in the Inputs section)
            int maxOkmLength = 255 * hashLength;
            if (outputLength <= 0 || outputLength > maxOkmLength)
                throw new ArgumentOutOfRangeException("outputLength", string.Format(Cryptography_Okm_TooLarge, maxOkmLength));

            byte[] result = new byte[outputLength];
            Expand(
                hashAlgorithmName,
                hashLength,
                prk,
                result,
                info
            );

            return result;
        }

        /// <summary>
        /// Performs the HKDF-Expand function
        /// See section 2.3 of <a href="https://tools.ietf.org/html/rfc5869#section-2.3">RFC5869</a>
        /// </summary>
        /// <param name="hashAlgorithmName">The hash algorithm used for HMAC operations.</param>
        /// <param name="prk">The pseudorandom key of at least <see cref="HashLength"/> bytes (usually the output from Expand step).</param>
        /// <param name="output">The destination buffer to receive the output keying material.</param>
        /// <param name="info">The context and application specific information (can be an empty span).</param>
        public static void Expand(
            HashAlgorithmName hashAlgorithmName,
            /* ReadOnly */ byte[] prk,
            byte[] output,
            /* ReadOnly */ byte[] info,
            int prkOffset = 0,
            int prkLength = -1,
            int outputOffset = 0,
            int outputLength = -1,
            int infoOffset = 0,
            int infoLength = -1
        )
        {
            SanitizeSpan(ref output, ref outputOffset, ref outputLength);

            int hashLength = HashLength(hashAlgorithmName);

            // Constant comes from section 2.3 (the constraint on L in the Inputs section)
            int maxOkmLength = 255 * hashLength;
            if (outputLength > maxOkmLength)
                throw new ArgumentException(string.Format(Cryptography_Okm_TooLarge, maxOkmLength), "output");

            Expand(
                hashAlgorithmName,
                hashLength,
                prk,
                output,
                info,
                prkOffset,
                prkLength,
                outputOffset,
                outputLength,
                infoOffset,
                infoLength
            );
        }

        private static void Expand(
            HashAlgorithmName hashAlgorithmName,
            int hashLength,
            /* ReadOnly */ byte[] prk,
            byte[] output,
            /* ReadOnly */ byte[] info,
            int prkOffset = 0,
            int prkLength = -1,
            int outputOffset = 0,
            int outputLength = -1,
            int infoOffset = 0,
            int infoLength = -1
        )
        {
            SanitizeSpan(ref prk, ref prkOffset, ref prkLength);
            SanitizeSpan(ref output, ref outputOffset, ref outputLength);
            SanitizeSpan(ref info, ref infoOffset, ref infoLength);

            Debug.Assert(HashLength(hashAlgorithmName) == hashLength);

            if (prkLength < hashLength)
                throw new ArgumentException(string.Format(Cryptography_Prk_TooSmall, hashLength), "prk");

            byte[] CounterArray = new byte[1];
            int tOffset = 0;
            int tLength = 0;

            SliceSpan(ref prk, ref prkOffset, ref prkLength);
            using (IncrementalHash hmac = IncrementalHash.CreateHMAC(hashAlgorithmName, prk))
            {
                for (int i = 1; ; i++)
                {
                    hmac.AppendData(output, tOffset, tLength);
                    hmac.AppendData(info, infoOffset, infoLength);
                    CounterArray[0] = (byte)i;
                    hmac.AppendData(CounterArray);

                    if (outputLength >= hashLength)
                    {
                        tOffset = outputOffset;
                        tLength = hashLength;
                        outputOffset += hashLength;
                        outputLength -= hashLength;
                        GetHashAndReset(hmac, output, tOffset, tLength);
                    }
                    else
                    {
                        if (outputLength > 0)
                        {
                            Debug.Assert(hashLength <= 512 / 8, "hashLength is larger than expected, consider increasing this value or using regular allocation");
                            GetHashAndReset(hmac, output, outputOffset, outputLength, truncate: true);
                        }

                        break;
                    }
                }
            }
        }

        /// <summary>
        /// Performs the key derivation HKDF Expand and Extract functions
        /// </summary>
        /// <param name="hashAlgorithmName">The hash algorithm used for HMAC operations.</param>
        /// <param name="ikm">The input keying material.</param>
        /// <param name="outputLength">The length of the output keying material.</param>
        /// <param name="salt">The optional salt value (a non-secret random value). If not provided it defaults to a byte array of <see cref="HashLength"/> zeros.</param>
        /// <param name="info">The optional context and application specific information.</param>
        /// <returns>The output keying material.</returns>
        public static byte[] DeriveKey(HashAlgorithmName hashAlgorithmName, byte[] ikm, int outputLength, byte[] salt = null, byte[] info = null)
        {
            if (ikm == null)
                throw new ArgumentNullException("ikm");

            int hashLength = HashLength(hashAlgorithmName);
            Debug.Assert(hashLength <= 512 / 8, "hashLength is larger than expected, consider increasing this value or using regular allocation");

            // Constant comes from section 2.3 (the constraint on L in the Inputs section)
            int maxOkmLength = 255 * hashLength;
            if (outputLength > maxOkmLength)
                throw new ArgumentOutOfRangeException("outputLength", string.Format(Cryptography_Okm_TooLarge, maxOkmLength));

            byte[] prk = new byte[hashLength];

            Extract(hashAlgorithmName, hashLength, ikm, salt, prk);

            byte[] result = new byte[outputLength];
            Expand(hashAlgorithmName, hashLength, prk, result, info);

            return result;
        }

        /// <summary>
        /// Performs the key derivation HKDF Expand and Extract functions
        /// </summary>
        /// <param name="hashAlgorithmName">The hash algorithm used for HMAC operations.</param>
        /// <param name="ikm">The input keying material.</param>
        /// <param name="output">The output buffer representing output keying material.</param>
        /// <param name="salt">The salt value (a non-secret random value).</param>
        /// <param name="info">The context and application specific information (can be an empty span).</param>
        public static void DeriveKey(
            HashAlgorithmName hashAlgorithmName,
            /* ReadOnly */ byte[] ikm,
            byte[] output,
            /* ReadOnly */ byte[] salt,
            /* ReadOnly */ byte[] info,
            int ikmOffset = 0,
            int ikmLength = -1,
            int outputOffset = 0,
            int outputLength = -1,
            int saltOffset = 0,
            int saltLength = -1,
            int infoOffset = 0,
            int infoLength = -1
        )
        {
            SanitizeSpan(ref output, ref outputOffset, ref outputLength);

            int hashLength = HashLength(hashAlgorithmName);

            // Constant comes from section 2.3 (the constraint on L in the Inputs section)
            int maxOkmLength = 255 * hashLength;
            if (outputLength > maxOkmLength)
                throw new ArgumentException(string.Format(Cryptography_Okm_TooLarge, maxOkmLength), "output");

            Debug.Assert(hashLength <= 512 / 8, "hashLength is larger than expected, consider increasing this value or using regular allocation");
            byte[] prk = new byte[hashLength];
            int prkOffset = 0;
            int prkLength = prk.Length;

            Extract(
                hashAlgorithmName,
                hashLength,
                ikm,
                salt,
                prk,
                ikmOffset,
                ikmLength,
                saltOffset,
                saltLength,
                prkOffset,
                prkLength
            );
            Expand(
                hashAlgorithmName,
                hashLength,
                prk,
                output,
                info,
                prkOffset,
                prkLength,
                outputOffset,
                outputLength,
                infoOffset,
                infoLength
            );
        }

        private static void SanitizeSpan(ref byte[] bytes, ref int byteOffset, ref int byteLength)
        {
            if (bytes == null)
            {
                bytes = new byte[0];
                byteOffset = 0;
                byteLength = 0;
                return;
            }

            if (byteLength == -1)
            {
                byteLength = bytes.Length - byteOffset;
            }

            if (byteOffset < 0 || bytes.Length < byteOffset) {
                throw new ArgumentOutOfRangeException("byteOffset", string.Format("The byte array offset must be in the range [{0}, {1}].", 0, bytes.Length));
            }
            if (byteLength < 0 || bytes.Length < byteLength) {
                throw new ArgumentOutOfRangeException("byteLength", string.Format("The byte array length must be in the range [{0}, {1}].", 0, bytes.Length));
            }
        }

        private static void SliceSpan(ref byte[] bytes, ref int byteOffset, ref int byteLength)
        {
            if (byteOffset == 0 && byteLength == bytes.Length) {
                return;
            }

            byte[] byteSlice = new byte[byteLength];
            Array.Copy(bytes, byteOffset, byteSlice, 0, byteLength);
            bytes = byteSlice;
            byteOffset = 0;
            byteLength = bytes.Length;
        }

        private static void GetHashAndReset(IncrementalHash hmac, byte[] output, int outputOffset = 0, int outputLength = -1, bool truncate = false)
        {
            byte[] hash = hmac.GetHashAndReset();
            int bytesWritten = hash.Length;
            if (!truncate && outputLength < bytesWritten)
            {
                Debug.Assert(false, "HMAC operation failed unexpectedly");
                throw new CryptographicException(Arg_CryptographyException);
            }
            Array.Copy(hash, 0, output, outputOffset, outputLength);

            Debug.Assert(bytesWritten == outputLength, string.Format("Bytes written is {0} bytes which does not match output length ({1} bytes)", bytesWritten, outputLength));
        }

        private static int HashLength(HashAlgorithmName hashAlgorithmName)
        {
            if (hashAlgorithmName == HashAlgorithmName.SHA1)
            {
                return 160 / 8;
            }
            else if (hashAlgorithmName == HashAlgorithmName.SHA256)
            {
                return 256 / 8;
            }
            else if (hashAlgorithmName == HashAlgorithmName.SHA384)
            {
                return 384 / 8;
            }
            else if (hashAlgorithmName == HashAlgorithmName.SHA512)
            {
                return 512 / 8;
            }
            else if (hashAlgorithmName == HashAlgorithmName.MD5)
            {
                return 128 / 8;
            }
            else
            {
                throw new ArgumentOutOfRangeException("hashAlgorithmName");
            }
        }
    }
}