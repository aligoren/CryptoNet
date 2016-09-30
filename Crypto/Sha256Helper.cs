using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoNet
{
    public class Sha256Helper
    {
        protected static void DBL_INT_ADD(ref uint a, ref uint b, uint c)
        {
            if (a > 0xffffffff - c) ++b; a += c;
        }

        protected static uint ROTLEFT(uint a, byte b)
        {
            return ((a << b) | (a >> (32 - b)));
        }

        protected static uint ROTRIGHT(uint a, byte b)
        {
            return (((a) >> (b)) | ((a) << (32 - (b))));
        }

        protected static uint CH(uint x, uint y, uint z)
        {
            return (((x) & (y)) ^ (~(x) & (z)));
        }

        protected static uint MAJ(uint x, uint y, uint z)
        {
            return (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)));
        }

        protected static uint EP0(uint x)
        {
            return (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22));
        }

        protected static uint EP1(uint x)
        {
            return (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25));
        }

        protected static uint SIG0(uint x)
        {
            return (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3));
        }

        protected static uint SIG1(uint x)
        {
            return (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10));
        }

        struct SHA256_CTX
        {
            public byte[] data;
            public uint datalen;
            public uint[] bitlen;
            public uint[] state;
        }

        protected static uint[] k = {
	        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };

        static void SHA256Transform(ref SHA256_CTX ctx, byte[] data)
        {
            uint a, b, c, d, e, f, g, h, i, j, t1, t2;
            uint[] m = new uint[64];

            for (i = 0, j = 0; i < 16; ++i, j += 4)
                m[i] = (uint)((data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]));

            for (; i < 64; ++i)
                m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

            a = ctx.state[0];
            b = ctx.state[1];
            c = ctx.state[2];
            d = ctx.state[3];
            e = ctx.state[4];
            f = ctx.state[5];
            g = ctx.state[6];
            h = ctx.state[7];

            for (i = 0; i < 64; ++i)
            {
                t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
                t2 = EP0(a) + MAJ(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            ctx.state[0] += a;
            ctx.state[1] += b;
            ctx.state[2] += c;
            ctx.state[3] += d;
            ctx.state[4] += e;
            ctx.state[5] += f;
            ctx.state[6] += g;
            ctx.state[7] += h;
        }

        static void SHA256Init(ref SHA256_CTX ctx)
        {
            ctx.datalen = 0;
            ctx.bitlen[0] = 0;
            ctx.bitlen[1] = 0;
            ctx.state[0] = 0x6a09e667;
            ctx.state[1] = 0xbb67ae85;
            ctx.state[2] = 0x3c6ef372;
            ctx.state[3] = 0xa54ff53a;
            ctx.state[4] = 0x510e527f;
            ctx.state[5] = 0x9b05688c;
            ctx.state[6] = 0x1f83d9ab;
            ctx.state[7] = 0x5be0cd19;
        }

        static void SHA256Update(ref SHA256_CTX ctx, byte[] data, uint len)
        {
            for (uint i = 0; i < len; ++i)
            {
                ctx.data[ctx.datalen] = data[i];
                ctx.datalen++;

                if (ctx.datalen == 64)
                {
                    SHA256Transform(ref ctx, ctx.data);
                    DBL_INT_ADD(ref ctx.bitlen[0], ref ctx.bitlen[1], 512);
                    ctx.datalen = 0;
                }
            }
        }

        static void SHA256Final(ref SHA256_CTX ctx, byte[] hash)
        {
            uint i = ctx.datalen;

            if (ctx.datalen < 56)
            {
                ctx.data[i++] = 0x80;

                while (i < 56)
                    ctx.data[i++] = 0x00;
            }
            else
            {
                ctx.data[i++] = 0x80;

                while (i < 64)
                    ctx.data[i++] = 0x00;

                SHA256Transform(ref ctx, ctx.data);
            }

            DBL_INT_ADD(ref ctx.bitlen[0], ref ctx.bitlen[1], ctx.datalen * 8);
            ctx.data[63] = (byte)(ctx.bitlen[0]);
            ctx.data[62] = (byte)(ctx.bitlen[0] >> 8);
            ctx.data[61] = (byte)(ctx.bitlen[0] >> 16);
            ctx.data[60] = (byte)(ctx.bitlen[0] >> 24);
            ctx.data[59] = (byte)(ctx.bitlen[1]);
            ctx.data[58] = (byte)(ctx.bitlen[1] >> 8);
            ctx.data[57] = (byte)(ctx.bitlen[1] >> 16);
            ctx.data[56] = (byte)(ctx.bitlen[1] >> 24);
            SHA256Transform(ref ctx, ctx.data);

            for (i = 0; i < 4; ++i)
            {
                hash[i] = (byte)(((ctx.state[0]) >> (int)(24 - i * 8)) & 0x000000ff);
                hash[i + 4] = (byte)(((ctx.state[1]) >> (int)(24 - i * 8)) & 0x000000ff);
                hash[i + 8] = (byte)(((ctx.state[2]) >> (int)(24 - i * 8)) & 0x000000ff);
                hash[i + 12] = (byte)((ctx.state[3] >> (int)(24 - i * 8)) & 0x000000ff);
                hash[i + 16] = (byte)((ctx.state[4] >> (int)(24 - i * 8)) & 0x000000ff);
                hash[i + 20] = (byte)((ctx.state[5] >> (int)(24 - i * 8)) & 0x000000ff);
                hash[i + 24] = (byte)((ctx.state[6] >> (int)(24 - i * 8)) & 0x000000ff);
                hash[i + 28] = (byte)((ctx.state[7] >> (int)(24 - i * 8)) & 0x000000ff);
            }
        }

        protected static string SHA256Encoding(string data)
        {
            SHA256_CTX ctx = new SHA256_CTX();
            ctx.data = new byte[64];
            ctx.bitlen = new uint[2];
            ctx.state = new uint[8];

            byte[] hash = new byte[32];
            string hashStr = string.Empty;

            SHA256Init(ref ctx);
            SHA256Update(ref ctx, Encoding.Default.GetBytes(data), (uint)data.Length);
            SHA256Final(ref ctx, hash);

            for (int i = 0; i < 32; i++)
            {
                hashStr += string.Format("{0:X2}", hash[i]);
            }

            return hashStr;
        }
    }
}
