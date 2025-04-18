using System;
using System.Security.Cryptography;

public class Crc32 : HashAlgorithm
{
    public const uint DefaultPolynomial = 0xEDB88320u;
    public const uint DefaultSeed = 0xFFFFFFFFu;

    private static readonly uint[] _defaultTable = InitializeTable(DefaultPolynomial);
    private uint _hash;
    private uint _seed;
    private readonly uint[] _table;

    public Crc32()
    {
        _table = _defaultTable;
        _seed = DefaultSeed;
        Initialize();
    }

    public override void Initialize()
    {
        _hash = _seed;
    }

    protected override void HashCore(byte[] buffer, int start, int length)
    {
        _hash = CalculateHash(_table, _hash, buffer, start, length);
    }

    protected override byte[] HashFinal()
    {
        byte[] hashBuffer = BitConverter.GetBytes(~_hash);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(hashBuffer);
        return hashBuffer;
    }

    public override int HashSize => 32;

    private static uint[] InitializeTable(uint polynomial)
    {
        var table = new uint[256];
        for (int i = 0; i < 256; i++)
        {
            uint entry = (uint)i;
            for (int j = 0; j < 8; j++)
            {
                if ((entry & 1) == 1)
                    entry = (entry >> 1) ^ polynomial;
                else
                    entry >>= 1;
            }
            table[i] = entry;
        }
        return table;
    }

    private static uint CalculateHash(uint[] table, uint seed, byte[] buffer, int start, int size)
    {
        uint crc = seed;
        for (int i = start; i < start + size; i++)
        {
            unchecked
            {
                crc = (crc >> 8) ^ table[buffer[i] ^ (crc & 0xFF)];
            }
        }
        return crc;
    }
}
