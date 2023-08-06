using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using System.Collections.Generic;
using BessieDotNet;
using System.Linq;
using System;

namespace BessieDotNetTests;

[TestClass]
public class BessieTests
{
    // https://github.com/oconnor663/bessie/blob/main/python/test_bessie.py
    private static readonly int[] PlaintextSizes = { 0, 1, Bessie.ChunkSize - 1, Bessie.ChunkSize, Bessie.ChunkSize + 1, Bessie.ChunkSize * 2, Bessie.ChunkSize * 2 + 1, 50000 };

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { Bessie.NonceSize + 1 + Bessie.TagSize, 0, Bessie.KeySize };
        yield return new object[] { Bessie.NonceSize - 1 + Bessie.TagSize, 0, Bessie.KeySize };
        yield return new object[] { Bessie.NonceSize + Bessie.TagSize, 1, Bessie.KeySize };
        yield return new object[] { Bessie.NonceSize + Bessie.ChunkSize + 1 + Bessie.TagSize, Bessie.ChunkSize + 1, Bessie.KeySize };
        yield return new object[] { Bessie.NonceSize + Bessie.TagSize, 0, Bessie.KeySize + 1 };
        yield return new object[] { Bessie.NonceSize + Bessie.TagSize, 0, Bessie.KeySize - 1 };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, Bessie.KeySize);
        Assert.AreEqual(32, Bessie.TagSize);
        Assert.AreEqual(24, Bessie.NonceSize);
        Assert.AreEqual(16384, Bessie.ChunkSize);
        Assert.AreEqual(16416, Bessie.CiphertextChunkSize);
    }

    // A better way to test this would be having Encrypt/Decrypt functions that also take a nonce
    // However, there are no test vectors, so this probably isn't worth the effort
    [TestMethod]
    public void EncryptDecrypt_Valid()
    {
        Span<byte> k = RandomNumberGenerator.GetBytes(Bessie.KeySize);
        foreach (int plaintextSize in PlaintextSizes) {
            Span<byte> c = new byte[Bessie.GetCiphertextSize(plaintextSize)];
            Span<byte> m = RandomNumberGenerator.GetBytes(plaintextSize);

            Bessie.Encrypt(c, m, k);
            Span<byte> p = new byte[Bessie.GetPlaintextSize(c.Length)];
            Bessie.Decrypt(p, c, k);

            Assert.IsTrue(p.SequenceEqual(m));
        }
    }

    [TestMethod]
    public void Decrypt_Tampered()
    {
        foreach (int plaintextSize in PlaintextSizes) {
            var p = RandomNumberGenerator.GetBytes(plaintextSize);
            var parameters = new List<byte[]>
            {
                new byte[Bessie.GetCiphertextSize(plaintextSize)],
                RandomNumberGenerator.GetBytes(Bessie.KeySize)
            };
            Bessie.Encrypt(parameters[0], p, parameters[1]);
            Array.Clear(p);

            foreach (var param in parameters) {
                param[0]++;
                Assert.ThrowsException<CryptographicException>(() => Bessie.Decrypt(p, parameters[0], parameters[1]));
                param[0]--;
            }
            Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
        }
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void EncryptDecrypt_Invalid(int ciphertextSize, int plaintextSize, int keySize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Bessie.Encrypt(c, p, k));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Bessie.Decrypt(p, c, k));
    }
}
