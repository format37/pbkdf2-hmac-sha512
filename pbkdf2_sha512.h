// The rotate operation for 64bits
#define ROR64(x,n) ((x >> n) | (x << (64 - n)))
#define CH(x,y,z)  (z ^ (x & (y ^ z)))
#define MAJ(x,y,z) ((x & y) | (z & (x | y)))
#define S0_64(x)   (ROR64((x), 28) ^ ROR64((x),  34) ^ ROR64((x), 39)) 
#define S1_64(x)   (ROR64((x), 14) ^ ROR64((x),  18) ^ ROR64((x), 41)) 
#define R0_64(x)   (ROR64((x), 1)  ^ ROR64((x),  8)  ^ ((x) >> 7)) 
#define R1_64(x)   (ROR64((x), 19) ^ ROR64((x), 61) ^ ((x) >> 6))

#ifndef PBKDF2_SHA512_INCLUDE
#define PBKDF2_SHA512_INCLUDE

#define SHA512_BLOCKLEN  128ul
#define SHA512_DIGESTLEN 64ul
#define SHA512_DIGESTINT 8ul

#ifndef PBKDF2_SHA512_STATIC
#define PBKDF2_SHA512_DEF extern
#else
#define PBKDF2_SHA512_DEF static
#endif

#include <stdint.h>
#include <string.h>

typedef struct sha512_ctx_t
{
    uint64_t len;  // Make sure this is uint64_t
    uint64_t h[SHA512_DIGESTINT];
    uint8_t buf[SHA512_BLOCKLEN];
} SHA512_CTX;

void sha512_init(SHA512_CTX *ctx);
void sha512_update(SHA512_CTX *ctx, const uint8_t *m, uint32_t mlen);
void sha512_final(SHA512_CTX *ctx, uint8_t *md);

typedef struct hmac_sha512_ctx_t
{
	uint8_t buf[SHA512_BLOCKLEN]; // key block buffer, not needed after init
	uint64_t h_inner[SHA512_DIGESTINT];
	uint64_t h_outer[SHA512_DIGESTINT];
	SHA512_CTX sha;
} HMAC_SHA512_CTX;

PBKDF2_SHA512_DEF void hmac_sha512_init(HMAC_SHA512_CTX *hmac, const uint8_t *key, uint32_t keylen);
PBKDF2_SHA512_DEF void hmac_sha512_update(HMAC_SHA512_CTX *hmac, const uint8_t *m, uint32_t mlen);
// resets state to hmac_sha512_init
PBKDF2_SHA512_DEF void hmac_sha512_final(HMAC_SHA512_CTX *hmac, uint8_t *md);

PBKDF2_SHA512_DEF void pbkdf2_sha512(HMAC_SHA512_CTX *ctx,
    const uint8_t *key, uint32_t keylen, const uint8_t *salt, uint32_t saltlen, uint32_t rounds,
    uint8_t *dk, uint32_t dklen);

#endif // PBKDF2_SHA512_INCLUDE

//------------------------------------------------------------------------------

#ifdef PBKDF2_SHA512_IMPLEMENTATION

#include <string.h>

/*static uint32_t ror(uint32_t n, uint32_t k)
{
	return (n >> k) | (n << (32 - k));
}*/

#define ROR(n,k) ror(n,k)

#define CH(x,y,z)  (z ^ (x & (y ^ z)))
#define MAJ(x,y,z) ((x & y) | (z & (x | y)))
#define S0(x)      (ROR(x, 2) ^ ROR(x,13) ^ ROR(x,22))
#define S1(x)      (ROR(x, 6) ^ ROR(x,11) ^ ROR(x,25))
#define R0(x)      (ROR(x, 7) ^ ROR(x,18) ^ (x>>3))
#define R1(x)      (ROR(x,17) ^ ROR(x,19) ^ (x>>10))

static const uint64_t K[80] = {
    UINT64_C(0x428a2f98d728ae22), UINT64_C(0x7137449123ef65cd),
    UINT64_C(0xb5c0fbcfec4d3b2f), UINT64_C(0xe9b5dba58189dbbc),
    UINT64_C(0x3956c25bf348b538), UINT64_C(0x59f111f1b605d019),
    UINT64_C(0x923f82a4af194f9b), UINT64_C(0xab1c5ed5da6d8118),
    UINT64_C(0xd807aa98a3030242), UINT64_C(0x12835b0145706fbe),
    UINT64_C(0x243185be4ee4b28c), UINT64_C(0x550c7dc3d5ffb4e2),
    UINT64_C(0x72be5d74f27b896f), UINT64_C(0x80deb1fe3b1696b1),
    UINT64_C(0x9bdc06a725c71235), UINT64_C(0xc19bf174cf692694),
    UINT64_C(0xe49b69c19ef14ad2), UINT64_C(0xefbe4786384f25e3),
    UINT64_C(0x0fc19dc68b8cd5b5), UINT64_C(0x240ca1cc77ac9c65),
    UINT64_C(0x2de92c6f592b0275), UINT64_C(0x4a7484aa6ea6e483),
    UINT64_C(0x5cb0a9dcbd41fbd4), UINT64_C(0x76f988da831153b5),
    UINT64_C(0x983e5152ee66dfab), UINT64_C(0xa831c66d2db43210),
    UINT64_C(0xb00327c898fb213f), UINT64_C(0xbf597fc7beef0ee4),
    UINT64_C(0xc6e00bf33da88fc2), UINT64_C(0xd5a79147930aa725),
    UINT64_C(0x06ca6351e003826f), UINT64_C(0x142929670a0e6e70),
    UINT64_C(0x27b70a8546d22ffc), UINT64_C(0x2e1b21385c26c926),
    UINT64_C(0x4d2c6dfc5ac42aed), UINT64_C(0x53380d139d95b3df),
    UINT64_C(0x650a73548baf63de), UINT64_C(0x766a0abb3c77b2a8),
    UINT64_C(0x81c2c92e47edaee6), UINT64_C(0x92722c851482353b),
    UINT64_C(0xa2bfe8a14cf10364), UINT64_C(0xa81a664bbc423001),
    UINT64_C(0xc24b8b70d0f89791), UINT64_C(0xc76c51a30654be30),
    UINT64_C(0xd192e819d6ef5218), UINT64_C(0xd69906245565a910),
    UINT64_C(0xf40e35855771202a), UINT64_C(0x106aa07032bbd1b8),
    UINT64_C(0x19a4c116b8d2d0c8), UINT64_C(0x1e376c085141ab53),
    UINT64_C(0x2748774cdf8eeb99), UINT64_C(0x34b0bcb5e19b48a8),
    UINT64_C(0x391c0cb3c5c95a63), UINT64_C(0x4ed8aa4ae3418acb),
    UINT64_C(0x5b9cca4f7763e373), UINT64_C(0x682e6ff3d6b2b8a3),
    UINT64_C(0x748f82ee5defb2fc), UINT64_C(0x78a5636f43172f60),
    UINT64_C(0x84c87814a1f0ab72), UINT64_C(0x8cc702081a6439ec),
    UINT64_C(0x90befffa23631e28), UINT64_C(0xa4506cebde82bde9),
    UINT64_C(0xbef9a3f7b2c67915), UINT64_C(0xc67178f2e372532b),
    UINT64_C(0xca273eceea26619c), UINT64_C(0xd186b8c721c0c207),
    UINT64_C(0xeada7dd6cde0eb1e), UINT64_C(0xf57d4f7fee6ed178),
    UINT64_C(0x06f067aa72176fba), UINT64_C(0x0a637dc5a2c898a6),
    UINT64_C(0x113f9804bef90dae), UINT64_C(0x1b710b35131c471b),
    UINT64_C(0x28db77f523047d84), UINT64_C(0x32caab7b40c72493),
    UINT64_C(0x3c9ebe0a15c9bebc), UINT64_C(0x431d67c49c100d4c),
    UINT64_C(0x4cc5d4becb3e42b6), UINT64_C(0x597f299cfc657e2a),
    UINT64_C(0x5fcb6fab3ad6faec), UINT64_C(0x6c44198c4a475817),
};

void my_cuda_memcpy_uint64(uint64_t *dst, const uint64_t *src, unsigned int n) {
    for (unsigned int i = 0; i < n / sizeof(uint64_t); ++i) {  // assuming n is in bytes
        dst[i] = src[i];
    }
}

void my_cuda_memcpy_unsigned_char(uint8_t *dst, const uint8_t *src, unsigned int n) {
    for (unsigned int i = 0; i < n; ++i) {
        dst[i] = src[i];
    }
}

static void sha512_transform(SHA512_CTX *s, const uint8_t *buf)
{
    // Debug line to print the block being transformed
    /*printf("Transforming block: ");
    for (int i = 0; i < SHA512_BLOCKLEN; ++i) {
        printf("%02x ", buf[i]);
    }
    printf("\n");*/

    uint64_t t1, t2, a, b, c, d, e, f, g, h, m[80]; // Change to uint64_t and m[80]
    uint32_t i, j;

    for (i = 0, j = 0; i < 16; i++, j += 8) // Modify loop to collect 8 bytes for each entry in m
    {
        m[i] = ((uint64_t)buf[j] << 56) | ((uint64_t)buf[j + 1] << 48) |
               ((uint64_t)buf[j + 2] << 40) | ((uint64_t)buf[j + 3] << 32) |
               ((uint64_t)buf[j + 4] << 24) | ((uint64_t)buf[j + 5] << 16) |
               ((uint64_t)buf[j + 6] << 8) | ((uint64_t)buf[j + 7]);
    }
    for (; i < 80; i++) // Increase loop limit to 80
    {
        m[i] = R1_64(m[i - 2]) + m[i - 7] + R0_64(m[i - 15]) + m[i - 16];
    }

    a = s->h[0];
    b = s->h[1];
    c = s->h[2];
    d = s->h[3];
    e = s->h[4];
    f = s->h[5];
    g = s->h[6];
    h = s->h[7];

    for (i = 0; i < 80; i++) // Increase loop limit to 80
    {
        t1 = h + S1_64(e) + CH(e, f, g) + K[i] + m[i];
        t2 = S0_64(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

	s->h[0] += a;
	s->h[1] += b;
	s->h[2] += c;
	s->h[3] += d;
	s->h[4] += e;
	s->h[5] += f;
	s->h[6] += g;
	s->h[7] += h;

    // Debug line to print the state after transformation
    /*printf("State after transformation: ");
    for (int i = 0; i < 8; ++i) {
        printf("%lx ", s->h[i]);
    }
    printf("\n");*/
}


void sha512_init(SHA512_CTX *s)
{
	s->len = 0;
	s->h[0] = 0x6a09e667f3bcc908ULL;
	s->h[1] = 0xbb67ae8584caa73bULL;
	s->h[2] = 0x3c6ef372fe94f82bULL;
	s->h[3] = 0xa54ff53a5f1d36f1ULL;
	s->h[4] = 0x510e527fade682d1ULL;
	s->h[5] = 0x9b05688c2b3e6c1fULL;
	s->h[6] = 0x1f83d9abfb41bd6bULL;
	s->h[7] = 0x5be0cd19137e2179ULL;

	// Debug line to print the initial state
    /*printf("Initial state: ");
    for (int i = 0; i < 8; ++i) {
        printf("%lx ", s->h[i]);
    }
    printf("\n");*/
}

void sha512_final(SHA512_CTX *s, uint8_t *md)
{
	uint32_t r = s->len % SHA512_BLOCKLEN;
	uint64_t totalBits = s->len * 8;  // Total bits
	uint64_t len_lower = totalBits & 0xFFFFFFFFFFFFFFFFULL;  // Lower 64 bits
    //uint64_t len_upper = totalBits >> 64;  // Upper 64 bits
	uint64_t len_upper = 0;  // Upper 64 bits are zero for 64-bit totalBits
	
    // Pad message
    s->buf[r++] = 0x80;
    while (r < 112)  // Padding until the total length is 112
    {
        s->buf[r++] = 0x00;
    }

    // Write 128 bit processed length in big-endian
    for (int i = 0; i < 8; ++i)
    {
		s->buf[r++] = (len_upper >> (8 * (7 - i))) & 0xFF;
	}

	for (int i = 0; i < 8; ++i)
    {
		s->buf[r++] = (len_lower >> (8 * (7 - i))) & 0xFF;
	}

	// Debug line to print the padded block
    /*printf("Padded block: ");
    for (int i = 0; i < SHA512_BLOCKLEN; ++i) {
        printf("%02x ", s->buf[i]);
    }
    printf("\n");*/

	sha512_transform(s, s->buf);
	
	for (uint32_t i = 0; i < SHA512_DIGESTINT; i++)
	{
		md[8 * i    ] = s->h[i] >> 56;
		md[8 * i + 1] = s->h[i] >> 48;
		md[8 * i + 2] = s->h[i] >> 40;
		md[8 * i + 3] = s->h[i] >> 32;
		md[8 * i + 4] = s->h[i] >> 24;
		md[8 * i + 5] = s->h[i] >> 16;
		md[8 * i + 6] = s->h[i] >> 8;
		md[8 * i + 7] = s->h[i];
	}
	sha512_init(s);
	// Debug line to print the final state
    /*printf("Final state: ");
    for (int i = 0; i < 8; ++i) {
        printf("%lx ", s->h[i]);
    }
    printf("\n");*/
}

void sha512_update(SHA512_CTX *s, const uint8_t *m, uint32_t len)
{
	const uint8_t *p = m;
	uint32_t r = s->len % SHA512_BLOCKLEN;
	
	s->len += len;
	if (r)
	{
		if (len + r < SHA512_BLOCKLEN)
		{
			//printf("sha512_update: len + r < SHA512_BLOCKLEN: %d\n", len + r);
			//memcpy(s->buf + r, p, len);
			//my_cuda_memcpy(s->buf + r, p, len);
			my_cuda_memcpy_unsigned_char(s->buf + r, p, len);
			//for (uint32_t i = 0; i < len; ++i) {s->buf[r + i] = p[i];}
			return;
		}
		//memcpy(s->buf + r, p, SHA512_BLOCKLEN - r);
		//my_cuda_memcpy(s->buf + r, p, SHA512_BLOCKLEN - r);
		my_cuda_memcpy_unsigned_char(s->buf + r, p, SHA512_BLOCKLEN - r);
		//for (uint32_t i = 0; i < SHA512_BLOCKLEN - r; ++i) {s->buf[r + i] = p[i];}
		len -= SHA512_BLOCKLEN - r;
		p += SHA512_BLOCKLEN - r;
		sha512_transform(s, s->buf);
	}
	for (; len >= SHA512_BLOCKLEN; len -= SHA512_BLOCKLEN, p += SHA512_BLOCKLEN)
	{
		sha512_transform(s, p);
	}
	//memcpy(s->buf, p, len);
	//my_cuda_memcpy(s->buf, p, len);
	my_cuda_memcpy_unsigned_char(s->buf, p, len);
	//for (uint32_t i = 0; i < len; ++i) {s->buf[i] = p[i];}
	// Debug line to print the block being processed
    /*printf("Processing block: ");
    for (int i = 0; i < SHA512_BLOCKLEN && i < len; ++i) {
        printf("%02x ", m[i]);
    }
    printf("\n");*/
}

#define INNER_PAD '\x36'
#define OUTER_PAD '\x5c'

PBKDF2_SHA512_DEF void hmac_sha512_init(HMAC_SHA512_CTX *hmac, const uint8_t *key, uint32_t keylen)
{
	SHA512_CTX *sha = &hmac->sha;
	/*printf("stage 0: ");
    for (int i = 0; i < SHA512_DIGESTLEN; ++i) {
        printf("%02x ", sha->h[i]);
    }
    printf("\n");*/
	
	if (keylen <= SHA512_BLOCKLEN)
	{
		printf("keylen <= SHA512_BLOCKLEN: %d\n", keylen);
		//memcpy(hmac->buf, key, keylen);
		//my_cuda_memcpy(hmac->buf, key, keylen);
		my_cuda_memcpy_unsigned_char(hmac->buf, key, keylen);
		//for (uint32_t i = 0; i < keylen; ++i) {hmac->buf[i] = key[i];}		
		memset(hmac->buf + keylen, '\0', SHA512_BLOCKLEN - keylen);
		//for (uint32_t i = keylen; i < SHA512_BLOCKLEN; ++i) {hmac->buf[i] = '\0';}
	}
	else
	{
		sha512_init(sha);
		sha512_update(sha, key, keylen);
		sha512_final(sha, hmac->buf);
		memset(hmac->buf + SHA512_DIGESTLEN, '\0', SHA512_BLOCKLEN - SHA512_DIGESTLEN);
		//for (uint32_t i = SHA512_DIGESTLEN; i < SHA512_BLOCKLEN; ++i) {hmac->buf[i] = '\0';}
	}
	
	uint32_t i;
	for (i = 0; i < SHA512_BLOCKLEN; i++)
	{
		hmac->buf[ i ] = hmac->buf[ i ] ^ OUTER_PAD;
	}

	/*printf("Before init: ");
    for (int i = 0; i < SHA512_DIGESTLEN; ++i) {
        printf("%02x ", sha->h[i]);
    }
    printf("\n");*/

	sha512_init(sha);
	sha512_update(sha, hmac->buf, SHA512_BLOCKLEN);
	
	// Before copying outer state
	/*printf("Before copying outer state: ");
	for (int i = 0; i < SHA512_DIGESTLEN; ++i) {
		printf("%02x ", sha->h[i]);
	}
	printf("\n");*/

	// copy outer state
	//memcpy(hmac->h_outer, sha->h, SHA512_DIGESTLEN);
	my_cuda_memcpy_uint64(hmac->h_outer, sha->h, SHA512_DIGESTLEN);
	//printf("SHA512_DIGESTLEN: %lx\n", SHA512_DIGESTLEN);
	//printf("Size of sha->h: %lu\n", sizeof(sha->h) / sizeof(sha->h[0]));
	//printf("Size of hmac->h_outer: %lu\n", sizeof(hmac->h_outer) / sizeof(hmac->h_outer[0]));
	//for (uint32_t i = 0; i < SHA512_DIGESTLEN; ++i) {hmac->h_outer[i] = sha->h[i];}
	// Make sure SHA512_DIGESTLEN and i have the same type
	/*for (size_t i = 0; i < SHA512_DIGESTLEN; ++i) {
		hmac->h_outer[i] = sha->h[i];
	}*/
	

	/*
	// After copying outer state
	printf("After copying outer state: ");
	for (int i = 0; i < SHA512_DIGESTLEN; ++i) {
		printf("%02x ", hmac->h_outer[i]);
	}
	printf("\n");*/
	
	for (i = 0; i < SHA512_BLOCKLEN; i++)
	{
		hmac->buf[ i ] = (hmac->buf[ i ] ^ OUTER_PAD) ^ INNER_PAD;
	}
	
	sha512_init(sha);
	sha512_update(sha, hmac->buf, SHA512_BLOCKLEN);
	// copy inner state
	//memcpy(hmac->h_inner, sha->h, SHA512_DIGESTLEN);
	my_cuda_memcpy_uint64(hmac->h_inner, sha->h, SHA512_DIGESTLEN);
	//for (uint32_t i = 0; i < SHA512_DIGESTLEN; ++i) {hmac->h_inner[i] = sha->h[i];}
}

PBKDF2_SHA512_DEF void hmac_sha512_update(HMAC_SHA512_CTX *hmac, const uint8_t *m, uint32_t mlen)
{
	sha512_update(&hmac->sha, m, mlen);
}

PBKDF2_SHA512_DEF void hmac_sha512_final(HMAC_SHA512_CTX *hmac, uint8_t *md)
{
	SHA512_CTX *sha = &hmac->sha;
	sha512_final(sha, md);
	
	// reset sha to outer state
	//memcpy(sha->h, hmac->h_outer, SHA512_DIGESTLEN);
	my_cuda_memcpy_uint64(sha->h, hmac->h_outer, SHA512_DIGESTLEN);
	//for (uint32_t i = 0; i < SHA512_DIGESTLEN; ++i) {sha->h[i] = hmac->h_outer[i];}
	sha->len = SHA512_BLOCKLEN;
	
	sha512_update(sha, md, SHA512_DIGESTLEN);
	sha512_final(sha, md); // md = D(outer || D(inner || msg))
	
	// reset sha to inner state -> reset hmac
	//memcpy(sha->h, hmac->h_inner, SHA512_DIGESTLEN);
	my_cuda_memcpy_uint64(sha->h, hmac->h_inner, SHA512_DIGESTLEN);
	//for (uint32_t i = 0; i < SHA512_DIGESTLEN; ++i) {sha->h[i] = hmac->h_inner[i];}
	sha->len = SHA512_BLOCKLEN;
}

PBKDF2_SHA512_DEF void pbkdf2_sha512(HMAC_SHA512_CTX *hmac,
    const uint8_t *key, uint32_t keylen, const uint8_t *salt, uint32_t saltlen, uint32_t rounds,
    uint8_t *dk, uint32_t dklen)
{
	uint32_t hlen = SHA512_DIGESTLEN;
	uint32_t l = dklen / hlen + ((dklen % hlen) ? 1 : 0);
	uint32_t r = dklen - (l - 1) * hlen;
	
	hmac_sha512_init(hmac, key, keylen);
	
	uint8_t *U = hmac->buf;
	uint8_t *T = dk;
	uint8_t count[4];
	
	uint32_t i, j, k;
	uint32_t len = hlen;
	for (i = 1; i <= l; i++)
	{
		if (i == l) { len = r; }
		count[0] = (i >> 24) & 0xFF;
		count[1] = (i >> 16) & 0xFF;
		count[2] = (i >>  8) & 0xFF;
		count[3] = (i) & 0xFF;
		hmac_sha512_update(hmac, salt, saltlen);
		hmac_sha512_update(hmac, count, 4);
		hmac_sha512_final(hmac, U);
		//memcpy(T, U, len);
		//my_cuda_memcpy(T, U, len);
		my_cuda_memcpy_unsigned_char(T, U, len);
		for (j = 1; j < rounds; j++)
		{
			hmac_sha512_update(hmac, U, hlen);
			hmac_sha512_final(hmac, U);
			for (k = 0; k < len; k++)
			{
				T[k] ^= U[k];
			}
		}
		T += len;
	}
	
}

#endif // PBKDF2_SHA512_IMPLEMENTATION

/*
------------------------------------------------------------------------------
This software is available under 2 licenses -- choose whichever you prefer.
------------------------------------------------------------------------------
ALTERNATIVE A - Public Domain (www.unlicense.org)
This is free and unencumbered software released into the public domain.
Anyone is free to copy, modify, publish, use, compile, sell, or distribute this
software, either in source code form or as a compiled binary, for any purpose,
commercial or non-commercial, and by any means.
In jurisdictions that recognize copyright laws, the author or authors of this
software dedicate any and all copyright interest in the software to the public
domain. We make this dedication for the benefit of the public at large and to
the detriment of our heirs and successors. We intend this dedication to be an
overt act of relinquishment in perpetuity of all present and future rights to
this software under copyright law.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
------------------------------------------------------------------------------
ALTERNATIVE B - MIT License
Copyright (c) 2019 monolifed
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
------------------------------------------------------------------------------
*/
