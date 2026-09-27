using System.Security.Cryptography;
#if !NET6_0_OR_GREATER
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
#endif

namespace SApi.Protocol;

internal static class Runtime
{
    internal static bool Finite(double n) => !double.IsNaN(n) && !double.IsInfinity(n);
    internal static byte[] Random(int count)
    {
        var bytes = new byte[count]; using var rng = RandomNumberGenerator.Create(); rng.GetBytes(bytes); return bytes;
    }
    internal static byte[] Hash(byte[] bytes) { using var hash = SHA256.Create(); return hash.ComputeHash(bytes); }
    internal static byte[] Hmac(byte[] key, byte[] bytes) { using var hmac = new HMACSHA256(key); return hmac.ComputeHash(bytes); }
    internal static void Encrypt(byte[] key, byte[] iv, byte[] plain, byte[] cipher, byte[] tag, byte[] aad)
    {
#if NET8_0_OR_GREATER
        using var aes = new AesGcm(key, 16); aes.Encrypt(iv, plain, cipher, tag, aad);
#elif NET6_0_OR_GREATER
        using var aes = new AesGcm(key); aes.Encrypt(iv, plain, cipher, tag, aad);
#else
        var aes = new GcmBlockCipher(new AesEngine()); aes.Init(true, new AeadParameters(new KeyParameter(key), 128, iv, aad));
        var output = new byte[aes.GetOutputSize(plain.Length)]; var used = aes.ProcessBytes(plain, 0, plain.Length, output, 0); used += aes.DoFinal(output, used);
        if (used != plain.Length + 16) throw new SapiException();
        Array.Copy(output, 0, cipher, 0, cipher.Length); Array.Copy(output, cipher.Length, tag, 0, 16); Array.Clear(output, 0, output.Length);
#endif
    }
    internal static byte[] Decrypt(byte[] key, byte[] iv, byte[] cipher, byte[] tag, byte[] aad)
    {
        var plain = new byte[cipher.Length];
#if NET8_0_OR_GREATER
        using var aes = new AesGcm(key, 16); aes.Decrypt(iv, cipher, tag, plain, aad); return plain;
#elif NET6_0_OR_GREATER
        using var aes = new AesGcm(key); aes.Decrypt(iv, cipher, tag, plain, aad); return plain;
#else
        var aes = new GcmBlockCipher(new AesEngine()); aes.Init(false, new AeadParameters(new KeyParameter(key), 128, iv, aad));
        var input = new byte[cipher.Length + 16]; Array.Copy(cipher, input, cipher.Length); Array.Copy(tag, 0, input, cipher.Length, 16);
        // No plaintext leaves this method until the authentication tag is verified.
        try {var used = aes.ProcessBytes(input, 0, input.Length, plain, 0); used += aes.DoFinal(plain, used); if (used != plain.Length) throw new SapiException(); return plain;}
        catch {Array.Clear(plain, 0, plain.Length); throw;}
        finally {Array.Clear(input, 0, input.Length);}
#endif
    }
}
