#pragma once

#ifdef WIN32
#define inline __inline
#endif
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
#define U64_C(c) (c ## ULL)

static const int be_number = 0x1;
static const char *be_numPtr = (char*)&be_number;
#define lcc_big_endian (be_numPtr[0] == 0)

// Rotate the 32 bit unsigned integer X by N bits left/right
static inline u32 rol(u32 x, int n)
{
	return ( (x << (n&(32-1))) | (x >> ((32-n)&(32-1))) );
}
static inline u32 ror(u32 x, int n)
{
	return ( (x >> (n&(32-1))) | (x << ((32-n)&(32-1))) );
}
// Byte swap for 32-bit and 64-bit integers.
static inline u32 bswap32(u32 x)
{
	if (lcc_big_endian)
		return ((rol(x, 8) & 0x00ff00ffL) | (ror(x, 8) & 0xff00ff00L));
	else
		return x;
}
static inline u64 bswap64(u64 x)
{
	if (lcc_big_endian)
		return ((u64)bswap32((u32)x) << 32) | (bswap32((u32)(x >> 32)));
	else
		return x;
}
