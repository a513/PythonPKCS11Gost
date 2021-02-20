#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct GOSTR3411_2012_CTX_st
{
	unsigned int digest_size;	// 32 or 64 - in bytes
	unsigned char block[64];
	unsigned int block_len;
	union
	{
		unsigned long long h[8];
		unsigned char result[64];
	} res;
	unsigned long long  N[8];
	unsigned long long  sigma[8];
} GOSTR3411_2012_CTX;

int GOSTR3411_2012_Init(
	GOSTR3411_2012_CTX *ctx, 
	unsigned int digest_size);

int GOSTR3411_2012_256_Init(
	GOSTR3411_2012_CTX *ctx);

int GOSTR3411_2012_512_Init(
	GOSTR3411_2012_CTX *ctx); 

// Хэшируемые данные должны поступать на вход 
// в виде массива октетов в порядке little-endian.
// Это означает, что байты будут загружаться в контекст 
// в порядке от нулевого индекса массива к старшему индексу. 
int GOSTR3411_2012_Update(
	GOSTR3411_2012_CTX *ctx, 
	const unsigned char *data,
	const unsigned int data_len);

int GOSTR3411_2012_256_Update(
	GOSTR3411_2012_CTX *ctx, 
	const unsigned char *data,
	const unsigned int data_len);

int GOSTR3411_2012_512_Update(
	GOSTR3411_2012_CTX *ctx, 
	const unsigned char *data,
	const unsigned int data_len);

// Результирующий дайджест также представлен 
// в виде массива октетов в порядке little-endian.
int GOSTR3411_2012_Final(
	GOSTR3411_2012_CTX	*ctx,
	unsigned char *digest);

int GOSTR3411_2012_256_Final(
	GOSTR3411_2012_CTX	*ctx,
	unsigned char *digest);

int GOSTR3411_2012_512_Final(
	GOSTR3411_2012_CTX	*ctx,
	unsigned char *digest);

int GOSTR3411_2012_Transform( 
	unsigned int digest_size,
	const unsigned char *data,
	const unsigned int data_len,
	unsigned char *digest);

int GOSTR3411_2012_256_Transform( 
	const unsigned char *data,
	const unsigned int data_len,
	unsigned char *digest);

int GOSTR3411_2012_512_Transform( 
	const unsigned char *data,
	const unsigned int data_len,
	unsigned char *digest);

#ifdef __cplusplus
}
#endif
