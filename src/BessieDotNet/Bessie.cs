using System.Security.Cryptography;
using System.Buffers.Binary;
using Blake3;

namespace BessieDotNet;

public static class Bessie
{
    public const int KeySize = 32;
    public const int TagSize = 32;
    public const int NonceSize = 24;
    private const int ChunkIndexSize = 8;
    private const int FinalFlagSize = 1;
    public const int ChunkSize = 16384;
    public const int CiphertextChunkSize = ChunkSize + TagSize;

    public static int GetCiphertextSize(int plaintextSize)
    {
        if (plaintextSize < 0) { throw new ArgumentOutOfRangeException(nameof(plaintextSize), plaintextSize, $"{nameof(plaintextSize)} must be equal to or greater than 0."); }

        int chunkCount = ((plaintextSize != 0 ? plaintextSize : 1) + ChunkSize - 1) / ChunkSize;
        return NonceSize + plaintextSize + (chunkCount * TagSize);
    }

    public static int GetPlaintextSize(int ciphertextSize)
    {
        if (ciphertextSize < NonceSize + TagSize) { throw new ArgumentOutOfRangeException(nameof(ciphertextSize), ciphertextSize, $"{nameof(ciphertextSize)} must be at least {NonceSize + TagSize} bytes long."); }

        int chunkCount = ((ciphertextSize - NonceSize) + CiphertextChunkSize - 1) / CiphertextChunkSize;
        return ciphertextSize - NonceSize - (chunkCount * TagSize);
    }

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key)
    {
        int chunkCount = ((plaintext.Length != 0 ? plaintext.Length : 1) + ChunkSize - 1) / ChunkSize;
        if (ciphertext.Length != NonceSize + plaintext.Length + (chunkCount * TagSize)) { throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be {NonceSize + plaintext.Length + (chunkCount * TagSize)} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }

        Span<byte> nonce = stackalloc byte[NonceSize + ChunkIndexSize + FinalFlagSize];
        nonce.Clear();
        Span<byte> iv = nonce[..NonceSize], chunkIndex = nonce.Slice(NonceSize, ChunkIndexSize), finalFlag = nonce[^FinalFlagSize..];
        RandomNumberGenerator.Fill(iv);
        iv.CopyTo(ciphertext[..NonceSize]);

        Span<byte> chunkKeys = stackalloc byte[KeySize * 2], macKey = chunkKeys[..KeySize], encKey = chunkKeys[KeySize..];
        int plaintextStartIndex = 0;
        int ciphertextStartIndex = NonceSize;
        for (int i = 0; i < chunkCount; i++) {
            bool lastChunk = i == chunkCount - 1;
            if (lastChunk) {
                finalFlag[0] = 1;
            }
            DeriveKeys(chunkKeys, nonce, key);

            int ciphertextEndIndex = !lastChunk ? ciphertextStartIndex + ChunkSize : ciphertext.Length - TagSize;
            ReadOnlySpan<byte> plaintextChunk = !lastChunk ? plaintext.Slice(plaintextStartIndex, ChunkSize) : plaintext[plaintextStartIndex..];
            Span<byte> ciphertextChunk = ciphertext[ciphertextStartIndex..ciphertextEndIndex];
            Span<byte> tag = ciphertext.Slice(ciphertextEndIndex, TagSize);

            ComputeTag(tag, plaintextChunk, macKey);
            ComputeKeystream(ciphertextChunk, tag, encKey);
            Xor(ciphertextChunk, plaintextChunk);

            BinaryPrimitives.WriteUInt64LittleEndian(chunkIndex, (ulong)i + 1);
            plaintextStartIndex += ChunkSize;
            ciphertextStartIndex += CiphertextChunkSize;
        }
        CryptographicOperations.ZeroMemory(chunkKeys);
    }

    private static void DeriveKeys(Span<byte> chunkKeys, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
    {
        using var blake3 = Hasher.NewKeyed(key);
        blake3.Update(nonce);
        blake3.Finalize(chunkKeys);
    }

    private static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> plaintextChunk, ReadOnlySpan<byte> macKey)
    {
        using var blake3 = Hasher.NewKeyed(macKey);
        blake3.Update(plaintextChunk);
        blake3.Finalize(tag);
    }

    private static void ComputeKeystream(Span<byte> keystream, ReadOnlySpan<byte> tag, ReadOnlySpan<byte> encKey)
    {
        using var blake3 = Hasher.NewKeyed(encKey);
        blake3.Update(tag);
        blake3.Finalize(keystream);
    }

    private static unsafe void Xor(Span<byte> ciphertextChunk, ReadOnlySpan<byte> plaintextChunk)
    {
        int chunks = ciphertextChunk.Length / 8;
        fixed (byte* c = ciphertextChunk, p = plaintextChunk) {
            long* cPtr = (long*)c, pPtr = (long*)p;
            for (int i = 0; i < chunks; i++) {
                *cPtr ^= *pPtr;
                cPtr++;
                pPtr++;
            }
        }
        for (int index = chunks * 8; index < ciphertextChunk.Length; index++) {
            ciphertextChunk[index] ^= plaintextChunk[index];
        }
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key)
    {
        if (ciphertext.Length < NonceSize + TagSize) { throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be at least {NonceSize + TagSize} bytes long."); }
        int chunkCount = ((ciphertext.Length - NonceSize) + CiphertextChunkSize - 1) / CiphertextChunkSize;
        if (plaintext.Length != ciphertext.Length - NonceSize - (chunkCount * TagSize)) { throw new ArgumentOutOfRangeException(nameof(plaintext), plaintext.Length, $"{nameof(plaintext)} must be {ciphertext.Length - NonceSize - (chunkCount * TagSize)} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }

        Span<byte> nonce = stackalloc byte[NonceSize + ChunkIndexSize + FinalFlagSize];
        nonce.Clear();
        ciphertext[..NonceSize].CopyTo(nonce[..NonceSize]);
        Span<byte> chunkIndex = nonce.Slice(NonceSize, ChunkIndexSize), finalFlag = nonce[^FinalFlagSize..];

        Span<byte> chunkKeys = stackalloc byte[KeySize * 2], macKey = chunkKeys[..KeySize], encKey = chunkKeys[KeySize..];
        Span<byte> computedTag = stackalloc byte[TagSize];
        int plaintextStartIndex = 0;
        int ciphertextStartIndex = NonceSize;
        for (int i = 0; i < chunkCount; i++) {
            bool lastChunk = i == chunkCount - 1;
            if (lastChunk) {
                finalFlag[0] = 1;
            }
            DeriveKeys(chunkKeys, nonce, key);

            int ciphertextEndIndex = !lastChunk ? ciphertextStartIndex + ChunkSize : ciphertext.Length - TagSize;
            Span<byte> plaintextChunk = !lastChunk ? plaintext.Slice(plaintextStartIndex, ChunkSize) : plaintext[plaintextStartIndex..];
            ReadOnlySpan<byte> ciphertextChunk = ciphertext[ciphertextStartIndex..ciphertextEndIndex];
            ReadOnlySpan<byte> tag = ciphertext.Slice(ciphertextEndIndex, TagSize);

            ComputeKeystream(plaintextChunk, tag, encKey);
            Xor(plaintextChunk, ciphertextChunk);
            ComputeTag(computedTag, plaintextChunk, macKey);

            if (!CryptographicOperations.FixedTimeEquals(computedTag, tag)) {
                CryptographicOperations.ZeroMemory(chunkKeys);
                CryptographicOperations.ZeroMemory(computedTag);
                CryptographicOperations.ZeroMemory(plaintext);
                throw new CryptographicException();
            }

            BinaryPrimitives.WriteUInt64LittleEndian(chunkIndex, (ulong)i + 1);
            plaintextStartIndex += ChunkSize;
            ciphertextStartIndex += CiphertextChunkSize;
        }
        CryptographicOperations.ZeroMemory(chunkKeys);
    }
}
