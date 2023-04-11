


// Тесты различных функций шифрования
// Головной модуль


//Размер тестовых данных
#define TEST_DATA_SIZE  128

#define TEST_OFFSET     0//63

#define INTEGRITY_IMAGE_SIZE 64


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "crypt.h"
#include "integrity.h"

#include "retvalues.h"

#include "bitmath.h"
#include "bytetools.h"

#include "dbgdef.h"

#include "mem_wrapper.h"

#include "cipher.h"


//--------------------------------------------------------------------------------------------------

/// в дальнейшем использовать на оригинальный RNG

//#include "rng.h"


#include "timereq.h"

#include "memory_nvcom_02t.h"


// Базовая структура генерации случайного числа
typedef struct SXorRngContext_t
{
	uint32_t rx;
	uint32_t ry;
	uint32_t rz;
	uint32_t rw;
} SXorRngContext;


//  генерация Случайного 32-разрядного целого числа без знака
uint32_t xor128(void* context)
{
	SXorRngContext* r = (SXorRngContext*)context;
	uint32_t t;
	t = r->rx ^ (r->rx << 11);
	r->rx = r->ry;
	r->ry = r->rz;
	r->rz = r->rw;
	return r->rw = r->rw ^ (r->rw >> 19) ^ t ^ (t >> 8);
}


//  генерация Случайного заполнеия полей структуры  SXorRngContext
SXorRngContext* initRng()
{
	SXorRngContext* context = (SXorRngContext*)lmalloc(sizeof(SXorRngContext));
	context->rx =  0xBEF27A17;
	context->ry =  0x137E2CF7;
	context->rz =  0xA721C0B7;

	uint32_t ticks_value[ARCH_TICKCOUNT_SZ] = {0};
	CDIE_IF(getTicksFromStart(ticks_value) != RET_OK);
	context->rw = ticks_value[0];

	xor128(context);
	xor128(context);

	CDIE_IF(getTicksFromStart(ticks_value) != RET_OK);
	context->rw += ticks_value[0];

	xor128(context);
	xor128(context);
	return context;
}


//--------------------------------------------------------------------------------------------------

static SXorRngContext*  rng = NULL;

// генегация случайного массива 32-битных целых без знака, размером  size32
static void getRandData(uint32_t* data, uint32_t size32)
{
	uint32_t i;

	for (i = 0; i < size32; i++)
	{
        data[i] = xor128(rng);
	}
}


static uint32_t pu_gamma[3] = {0};

uint8_t testEncryptGammaMode()
{
	uint32_t test_key[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t test_sync[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t test_data[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t result_data[TEST_DATA_SIZE / sizeof(uint32_t)];
	getRandData(test_key,  USTUP_KEY_SIZE / sizeof(uint32_t));
	getRandData(test_sync, USTUP_BLOCK_SIZE / sizeof(uint32_t));
	getRandData(test_data, TEST_DATA_SIZE / sizeof(uint32_t));
	getRandData(result_data, TEST_DATA_SIZE / sizeof(uint32_t));
	uint32_t cntl_key[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t cntl_sync[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t cntl_data[TEST_DATA_SIZE / sizeof(uint32_t)];
	lmemcpy(cntl_key, test_key, USTUP_KEY_SIZE);
	lmemcpy(cntl_sync, test_sync, USTUP_BLOCK_SIZE);
	lmemcpy(cntl_data, test_data, TEST_DATA_SIZE);

	encryptGammaModeNoMask(eCryptUstup, result_data, test_data, TEST_DATA_SIZE, test_key, test_sync, NULL);
	oldEncryptGammaModeNoMask(cntl_data, TEST_DATA_SIZE, cntl_key, cntl_sync);

	if (lmemcmp(result_data, cntl_data, TEST_DATA_SIZE) == 0)
	{
		DINF("Test encryptGammaMode()... \t\t\t\tSUCCESS");
		return RET_OK;
	}
	else
	{
		DINF("Test encryptGammaMode()... \t\t\t\tFAIL");
		return RET_FAIL;
	}
}

uint8_t testEncryptGammaModeMasked()
{

	uint32_t test_key[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t test_sync[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t test_data[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t result_data[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t test_mask[USTUP_KEY_SIZE / sizeof(uint32_t)];
	getRandData(test_key,  USTUP_KEY_SIZE / sizeof(uint32_t));
	getRandData(test_sync, USTUP_BLOCK_SIZE / sizeof(uint32_t));
	getRandData(test_data, TEST_DATA_SIZE / sizeof(uint32_t));
	getRandData(result_data, TEST_DATA_SIZE / sizeof(uint32_t));
	getRandData(test_mask, USTUP_KEY_SIZE / sizeof(uint32_t));
	uint32_t cntl_key[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t cntl_sync[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t cntl_data[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t cntl_mask[USTUP_KEY_SIZE / sizeof(uint32_t)];
	lmemcpy(cntl_key, test_key, USTUP_KEY_SIZE);
	lmemcpy(cntl_sync, test_sync, USTUP_BLOCK_SIZE);
	lmemcpy(cntl_data, test_data, TEST_DATA_SIZE);
	lmemcpy(cntl_mask, test_mask, USTUP_KEY_SIZE);

	encryptGammaMode(eCryptUstup, result_data, test_data, TEST_DATA_SIZE, test_mask, test_key, test_sync, pu_gamma);
	oldEncryptGammaMode(cntl_data, TEST_DATA_SIZE, cntl_mask, cntl_key, cntl_sync);

	if (lmemcmp(result_data, cntl_data, TEST_DATA_SIZE) == 0)
	{
		DINF("Test encryptGammaModeMasked()... \t\t\t\tSUCCESS");
		return RET_OK;
	}
	else
	{
		DINF("Test encryptGammaMasked()... \t\t\t\tFAIL");
		return RET_FAIL;
	}
}

uint8_t testEncryptWithImito()
{
	uint32_t test_key[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t test_sync[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t test_data[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t result_data[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t test_mask[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t test_imito[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	getRandData(test_key,  USTUP_KEY_SIZE / sizeof(uint32_t));
	getRandData(test_sync, USTUP_BLOCK_SIZE / sizeof(uint32_t));
	getRandData(test_data, TEST_DATA_SIZE / sizeof(uint32_t));
	getRandData(result_data, TEST_DATA_SIZE / sizeof(uint32_t));
	getRandData(test_mask, USTUP_KEY_SIZE / sizeof(uint32_t));
	lmemset(test_imito, 0x00, USTUP_BLOCK_SIZE);

	uint32_t cntl_key[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t cntl_sync[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t cntl_data[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t cntl_mask[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t cntl_imito[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	lmemcpy(cntl_key, test_key, USTUP_KEY_SIZE);
	lmemcpy(cntl_sync, test_sync, USTUP_BLOCK_SIZE);
	lmemcpy(cntl_data, test_data, TEST_DATA_SIZE);
	lmemcpy(cntl_mask, test_mask, USTUP_KEY_SIZE);
	lmemset(cntl_imito, 0x00, USTUP_BLOCK_SIZE);

	encryptFeedbackModeWithImito(eCryptUstup, result_data, test_data, TEST_DATA_SIZE, test_mask, test_key, test_sync, test_imito, pu_gamma);
	oldEncryptWithImito(cntl_data, TEST_DATA_SIZE, cntl_mask, cntl_key, cntl_sync, cntl_imito);

	if (lmemcmp(result_data, cntl_data, TEST_DATA_SIZE) != 0)
	{
		DINF("Test encryptWithImito()... \t\t\t\tFAIL (DATA)");
		return RET_FAIL;
	}

	if (lmemcmp(test_imito, cntl_imito, USTUP_BLOCK_SIZE) == 0)
	{
		DINF("Test encryptWithImito()... \t\t\t\tSUCCESS");
		return RET_OK;
	}
	else
	{
		DINF("Test encryptWithImito()... \t\t\t\tFAIL (IMIT)");
		return RET_FAIL;
	}
}




uint8_t testEncryptWithImitoCKvit()
{
	uint32_t test_key[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t test_sync[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t test_data[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t result_data[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t test_mask[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t test_imito[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t test_kvit[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	getRandData(test_key,  USTUP_KEY_SIZE / sizeof(uint32_t));
	getRandData(test_sync, USTUP_BLOCK_SIZE / sizeof(uint32_t));
	getRandData(test_data, TEST_DATA_SIZE / sizeof(uint32_t));
	getRandData(result_data, TEST_DATA_SIZE / sizeof(uint32_t));
	getRandData(test_mask, USTUP_KEY_SIZE / sizeof(uint32_t));
	lmemset(test_imito, 0x00, USTUP_BLOCK_SIZE);
	lmemset(test_kvit, 0x00, USTUP_BLOCK_SIZE);

	uint32_t cntl_key[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t cntl_sync[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t cntl_data[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t cntl_mask[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t cntl_imito[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t cntl_kvit[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	lmemcpy(cntl_key, test_key, USTUP_KEY_SIZE);
	lmemcpy(cntl_sync, test_sync, USTUP_BLOCK_SIZE);
	lmemcpy(cntl_data, test_data, TEST_DATA_SIZE);
	lmemcpy(cntl_mask, test_mask, USTUP_KEY_SIZE);
	lmemset(cntl_imito, 0x00, USTUP_BLOCK_SIZE);
	lmemset(cntl_kvit, 0x00, USTUP_BLOCK_SIZE);

	encryptFeedbackModeWithImitoKvit(eCryptUstup, result_data, test_data, TEST_DATA_SIZE, test_mask, test_key, test_sync, test_imito, test_kvit, pu_gamma);

	DHEX("test_data", result_data, TEST_DATA_SIZE);
	DHEX("test_mask", test_mask, USTUP_KEY_SIZE);
	DHEX("test_key", test_key, USTUP_KEY_SIZE);
	DHEX("test_sync", test_sync, USTUP_BLOCK_SIZE);
	DHEX("test_imito", test_imito, USTUP_BLOCK_SIZE);
	DHEX("test_kvit", test_kvit, USTUP_BLOCK_SIZE);


	oldEncryptWithImitoKvit(cntl_data, TEST_DATA_SIZE, cntl_mask, cntl_key, cntl_sync, cntl_imito, cntl_kvit);

	if (lmemcmp(result_data, cntl_data, TEST_DATA_SIZE) != 0)

	{
		DINF("Test encryptWithImitoCKvit()... \t\t\t\tFAIL (DATA)");
		return RET_FAIL;
	}

	if (lmemcmp(test_imito, cntl_imito, USTUP_BLOCK_SIZE) != 0)
	{
		DINF("Test encryptWithImitoCKvit()... \t\t\t\tFAIL (IMIT)");
		return RET_FAIL;
	}

	if (lmemcmp(test_kvit, cntl_kvit, USTUP_BLOCK_SIZE) == 0)
	{
		DINF("Test encryptWithImitoCKvit()... \t\t\t\tSUCCESS");
		return RET_OK;
	}
	else
	{
		DINF("Test encryptWithImitoCKvit()... \t\t\t\tFAIL (KVIT)");
		return RET_FAIL;
	}
}

//-------------------------------

uint8_t testDecryptWithImito()
{
	uint32_t test_key[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t test_sync[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t test_data[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t result_data[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t test_mask[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t test_imito[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	getRandData(test_key,  USTUP_KEY_SIZE / sizeof(uint32_t));
	getRandData(test_sync, USTUP_BLOCK_SIZE / sizeof(uint32_t));
	getRandData(test_data, TEST_DATA_SIZE / sizeof(uint32_t));
	getRandData(result_data, TEST_DATA_SIZE / sizeof(uint32_t));
	getRandData(test_mask, USTUP_KEY_SIZE / sizeof(uint32_t));
	lmemset(test_imito, 0x00, USTUP_BLOCK_SIZE);

	uint32_t cntl_key[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t cntl_sync[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t cntl_data[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t cntl_mask[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t cntl_imito[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	lmemcpy(cntl_key, test_key, USTUP_KEY_SIZE);
	lmemcpy(cntl_sync, test_sync, USTUP_BLOCK_SIZE);
	lmemcpy(cntl_data, test_data, TEST_DATA_SIZE);
	lmemcpy(cntl_mask, test_mask, USTUP_KEY_SIZE);
	lmemset(cntl_imito, 0x00, USTUP_BLOCK_SIZE);

	decryptFeedbackModeWithImito(eCryptUstup, result_data, test_data, TEST_DATA_SIZE, test_mask, test_key, test_sync, test_imito, pu_gamma);
	oldDecryptWithImito(cntl_data, TEST_DATA_SIZE, cntl_mask, cntl_key, cntl_sync, cntl_imito);

	if (lmemcmp(result_data, cntl_data, TEST_DATA_SIZE) != 0)
	{
		DINF("Test decryptWithImito()... \t\t\t\tFAIL (DATA)");
		return RET_FAIL;
	}

	if (lmemcmp(test_imito, cntl_imito, USTUP_BLOCK_SIZE) == 0)
	{
		DINF("Test decryptWithImito()... \t\t\t\tSUCCESS");
		return RET_OK;
	}
	else
	{
		DINF("Test decryptWithImito()... \t\t\t\tFAIL (IMIT)");
		return RET_FAIL;
	}
}



uint8_t testDecryptWithImitoCKvit()
{
	uint32_t test_key[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t test_sync[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t test_data[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t result_data[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t test_mask[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t test_imito[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t test_kvit[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	getRandData(test_key,  USTUP_KEY_SIZE / sizeof(uint32_t));
	getRandData(test_sync, USTUP_BLOCK_SIZE / sizeof(uint32_t));
	getRandData(test_data, TEST_DATA_SIZE / sizeof(uint32_t));
	getRandData(result_data, TEST_DATA_SIZE / sizeof(uint32_t));
	getRandData(test_mask, USTUP_KEY_SIZE / sizeof(uint32_t));
	lmemset(test_imito, 0x00, USTUP_BLOCK_SIZE);
	lmemset(test_kvit, 0x00, USTUP_BLOCK_SIZE);

	uint32_t cntl_key[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t cntl_sync[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t cntl_data[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t cntl_mask[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t cntl_imito[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t cntl_kvit[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	lmemcpy(cntl_key, test_key, USTUP_KEY_SIZE);
	lmemcpy(cntl_sync, test_sync, USTUP_BLOCK_SIZE);
	lmemcpy(cntl_data, test_data, TEST_DATA_SIZE);
	lmemcpy(cntl_mask, test_mask, USTUP_KEY_SIZE);
	lmemset(cntl_imito, 0x00, USTUP_BLOCK_SIZE);
	lmemset(cntl_kvit, 0x00, USTUP_BLOCK_SIZE);

	decryptFeedbackModeWithImitoKvit(eCryptUstup, result_data, test_data, TEST_DATA_SIZE, test_mask, test_key, test_sync, test_imito, test_kvit, pu_gamma);
	oldDecryptWithImitoKvit(cntl_data, TEST_DATA_SIZE, cntl_mask, cntl_key, cntl_sync, cntl_imito, cntl_kvit);

	if (lmemcmp(result_data, cntl_data, TEST_DATA_SIZE) != 0)

	{
		DINF("Test decryptWithImitoCKvit()... \t\t\t\tFAIL (DATA)");
		return RET_FAIL;
	}

	if (lmemcmp(test_imito, cntl_imito, USTUP_BLOCK_SIZE) != 0)
	{
		DINF("Test decryptWithImitoCKvit()... \t\t\t\tFAIL (IMIT)");
		return RET_FAIL;
	}

	if (lmemcmp(test_kvit, cntl_kvit, USTUP_BLOCK_SIZE) == 0)
	{
		DINF("Test decryptWithImitoCKvit()... \t\t\t\tSUCCESS");
		return RET_OK;
	}
	else
	{
		DINF("Test decryptWithImitoCKvit()... \t\t\t\tFAIL (KVIT)");
		return RET_FAIL;
	}
}
//--------------------------------------------

uint8_t testCheckWithImito()
{
	uint32_t test_key[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t test_sync[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t test_data[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t test_mask[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t test_imito[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	getRandData(test_key,  USTUP_KEY_SIZE / sizeof(uint32_t));
	getRandData(test_sync, USTUP_BLOCK_SIZE / sizeof(uint32_t));
	getRandData(test_data, TEST_DATA_SIZE / sizeof(uint32_t));
	getRandData(test_mask, USTUP_KEY_SIZE / sizeof(uint32_t));
	lmemset(test_imito, 0x00, USTUP_BLOCK_SIZE);

	uint32_t cntl_key[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t cntl_sync[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t cntl_data[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t cntl_mask[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t cntl_imito[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	lmemcpy(cntl_key, test_key, USTUP_KEY_SIZE);
	lmemcpy(cntl_sync, test_sync, USTUP_BLOCK_SIZE);
	lmemcpy(cntl_data, test_data, TEST_DATA_SIZE);
	lmemcpy(cntl_mask, test_mask, USTUP_KEY_SIZE);
	lmemset(cntl_imito, 0x00, USTUP_BLOCK_SIZE);

	checkImito(eCryptUstup, test_data, TEST_DATA_SIZE,
			   test_mask, test_key, test_sync, test_imito, pu_gamma);
	oldCheckWithImito(cntl_data, TEST_DATA_SIZE, 0,
					  cntl_mask, cntl_key, cntl_sync, cntl_imito);

	if (lmemcmp(test_data, cntl_data, TEST_DATA_SIZE) != 0)
	{
		DINF("Test checkWithImito()... \t\t\t\t\tFAIL (DATA)");
		return RET_FAIL;
	}

	if (lmemcmp(test_imito, cntl_imito, USTUP_BLOCK_SIZE) == 0)
	{
		DINF("Test checkWithImito()... \t\t\t\t\tSUCCESS");
		return RET_OK;
	}
	else
	{
		DINF("Test checkWithImito()... \t\t\t\t\tFAIL (IMIT)");
		return RET_FAIL;
	}
}
//-------------------------------------------

uint8_t testIntegrityCount()
{
	uint32_t test_image[INTEGRITY_IMAGE_SIZE / sizeof(uint32_t)];
	uint32_t test_key[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t test_sync[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t test_imito[USTUP_BLOCK_SIZE / sizeof(uint32_t)];

	SIntegrityState istate;
	lmemset(&istate, 0x00, sizeof(istate));
	istate.key = test_key;
	istate.internal_rgi = test_sync;
	istate.imito = test_imito;
	getRandData(test_image, INTEGRITY_IMAGE_SIZE / sizeof(uint32_t));
	getRandData(test_key, USTUP_KEY_SIZE / sizeof(uint32_t));

	uint32_t cntl_key[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t cntl_image[INTEGRITY_IMAGE_SIZE / sizeof(uint32_t)];
	uint32_t cntl_imito[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	lmemcpy(cntl_image, test_image, INTEGRITY_IMAGE_SIZE);
	lmemcpy(cntl_key, test_key, USTUP_KEY_SIZE);
	lmemset(cntl_imito, 0x00, USTUP_BLOCK_SIZE);

	integrityStartCount(eCryptUstup, &istate);
	integrityContinueCount(eCryptUstup, &istate, test_image, INTEGRITY_IMAGE_SIZE, NULL);
	integrityStopCount(eCryptUstup, &istate, NULL, 0, NULL);

	oldIntegrityStartCount();
	oldIntegrityContinueCount(cntl_key, cntl_image, INTEGRITY_IMAGE_SIZE);

	oldIntegrityStopCount(cntl_key, cntl_imito, NULL, 0);

	if (lmemcmp(istate.imito, cntl_imito, USTUP_BLOCK_SIZE) == 0)
	{
		DINF("Test IntegrityCount... \t\t\t\t\tSUCCESS");
		return RET_OK;
	}
	else
	{
		DINF("Test IntegrityCount... \t\t\t\t\tFAIL");
		return RET_FAIL;
	}
}

uint8_t testBitEncryption4Tetra ()
{
	uint32_t byte_prog[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t bit_mask_cipher[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t bit_mask_imit[TEST_DATA_SIZE / sizeof(uint32_t)];

	uint32_t i;

	for (i = 0; i < TEST_DATA_SIZE; i++)
	{
		u8(byte_prog)[i] = xor128(rng)&BIT_IMIT_AND_CIPHER;

		if (u8(byte_prog)[i] & BIT_CIHPER_ONLY)
		{
			u8(bit_mask_cipher)[i] = 0xFF;
		}
		else
		{
			u8(bit_mask_cipher)[i] = 0x00;
		}

		if (u8(byte_prog)[i] & BIT_IMITO_ONLY)
		{
			u8(bit_mask_imit)[i] = 0xFF;
		}
		else
		{
			u8(bit_mask_imit)[i] = 0x00;
		}
	}

	for (i = 0; i < TEST_DATA_SIZE; i++)
	{
		switch (u8(byte_prog)[i])
		{
			case (0):
				printf (" _ ");
				break;

			case (BIT_CIHPER_ONLY):
				printf (" C ");
				break;

			case (BIT_IMITO_ONLY):
				printf (" I ");
				break;

			case (BIT_IMITO_ONLY|BIT_CIHPER_ONLY):
				printf (" B ");
				break;

			default:
				printf (" ? ");
				break;
		}

		if ((i % 0x10) == 0xF)
		{
			printf ("\n");
		}
	}

	uint32_t test_data_byte[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t test_key_byte[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t test_rgi_byte[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t test_imito_byte[USTUP_BLOCK_SIZE / sizeof(uint32_t)];

	uint32_t test_data_bit[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t result_data_bit[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t test_key_bit[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t test_rgi_bit[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t test_imito_bit[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	lmemset (test_imito_byte, 0x00, USTUP_BLOCK_SIZE);

	getRandData(test_data_byte, TEST_DATA_SIZE / sizeof(uint32_t));
	getRandData(result_data_bit, TEST_DATA_SIZE / sizeof(uint32_t));
	getRandData(test_key_byte, USTUP_KEY_SIZE / sizeof(uint32_t));
	getRandData(test_rgi_byte, USTUP_BLOCK_SIZE / sizeof(uint32_t));

	lmemcpy (test_data_bit, test_data_byte, TEST_DATA_SIZE);
	lmemcpy (test_key_bit, test_key_byte, USTUP_KEY_SIZE);
	lmemcpy (test_rgi_bit, test_rgi_byte, USTUP_BLOCK_SIZE);
	lmemcpy (test_imito_bit, test_imito_byte, USTUP_BLOCK_SIZE);

	SCipherTask task;
	task.mode =  (eTetraEncryptionImito | TASK_BIT11_MAKE_CRYPT) & (~TASK_BIT9_CIPHER_IN_BIT_MODE);
	task.mask = NULL;
	task.key = test_key_byte;
	task.imito = test_imito_byte;
	task.sync = test_rgi_byte;
	task.src = test_data_byte;
	task.dst = test_data_byte;
	task.blocks = (TEST_DATA_SIZE >> USTUP_BLOCK_POWER);
	task.lastbytes = (TEST_DATA_SIZE & (USTUP_BLOCK_SIZE - 1));
	task.program = byte_prog;
	task.spec_params = NULL;
	cipherUstup(&task);
	bitEncryption4Tetra(eCryptUstup, test_key_bit, NULL, test_rgi_bit, test_imito_bit, result_data_bit, test_data_bit, TEST_DATA_SIZE,
						bit_mask_cipher, bit_mask_imit, pu_gamma);

	if (lmemcmp(test_imito_byte, test_imito_bit, USTUP_BLOCK_SIZE) != 0)
	{
		DINF("Test BitEnc4Tetra... \t\t\t\t\tFAIL(IMITO)");
		return RET_FAIL;
	}

	DHEX("test_data_byte", test_data_byte, TEST_DATA_SIZE);
	DHEX("test_data_bit", result_data_bit, TEST_DATA_SIZE);

	if (lmemcmp(test_data_byte, result_data_bit, TEST_DATA_SIZE) != 0)
	{
		DINF("Test BitEnc4Tetra... \t\t\t\t\tFAIL(DATA)");
		return RET_FAIL;
	}

	DINF("Test BitEnc4Tetra... \t\t\t\t\tSUCCESS");
	return RET_OK;
}


uint8_t testBitDecryption4Tetra ()
{
	uint32_t byte_prog[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t bit_mask_cipher[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t bit_mask_imit[TEST_DATA_SIZE / sizeof(uint32_t)];

	uint32_t i;

	for (i = 0; i < TEST_DATA_SIZE; i++)
	{
		u8(byte_prog)[i] = xor128(rng)&BIT_IMIT_AND_CIPHER;

		if (u8(byte_prog)[i] & BIT_CIHPER_ONLY)
		{
			u8(bit_mask_cipher)[i] = 0xFF;
		}
		else
		{
			u8(bit_mask_cipher)[i] = 0x00;
		}

		if (u8(byte_prog)[i] & BIT_IMITO_ONLY)
		{
			u8(bit_mask_imit)[i] = 0xFF;
		}
		else
		{
			u8(bit_mask_imit)[i] = 0x00;
		}
	}

	for (i = 0; i < TEST_DATA_SIZE; i++)
	{
		switch (u8(byte_prog)[i])
		{
			case (0):
				printf (" _ ");
				break;

			case (BIT_CIHPER_ONLY):
				printf (" C ");
				break;

			case (BIT_IMITO_ONLY):
				printf (" I ");
				break;

			case (BIT_IMITO_ONLY|BIT_CIHPER_ONLY):
				printf (" B ");
				break;

			default:
				printf (" ? ");
				break;
		}

		if ((i % 0x10) == 0xF)
		{
			printf ("\n");
		}
	}

	uint32_t test_data_byte[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t result_data_byte[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t test_key_byte[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t test_rgi_byte[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t test_imito_byte[USTUP_BLOCK_SIZE / sizeof(uint32_t)];

	uint32_t test_data_bit[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t result_data_bit[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t test_key_bit[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t test_rgi_bit[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t test_imito_bit[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
	lmemset (test_imito_byte, 0x00, USTUP_BLOCK_SIZE);

	getRandData(test_data_byte, TEST_DATA_SIZE / sizeof(uint32_t));
	getRandData(result_data_byte, TEST_DATA_SIZE / sizeof(uint32_t));
	getRandData(result_data_bit, TEST_DATA_SIZE / sizeof(uint32_t));
	getRandData(test_key_byte, USTUP_KEY_SIZE / sizeof(uint32_t));
	getRandData(test_rgi_byte, USTUP_BLOCK_SIZE / sizeof(uint32_t));

	lmemcpy (test_data_bit, test_data_byte, TEST_DATA_SIZE);
	lmemcpy (test_key_bit, test_key_byte, USTUP_KEY_SIZE);
	lmemcpy (test_rgi_bit, test_rgi_byte, USTUP_BLOCK_SIZE);
	lmemcpy (test_imito_bit, test_imito_byte, USTUP_BLOCK_SIZE);

	SCipherTask task;
	task.mode =  (eTetraEncryptionImito) & (~TASK_BIT9_CIPHER_IN_BIT_MODE);
	task.mask = NULL;
	task.key = test_key_byte;
	task.imito = test_imito_byte;
	task.sync = test_rgi_byte;
	task.src = test_data_byte;
	task.dst = result_data_byte;
	task.blocks = (TEST_DATA_SIZE >> USTUP_BLOCK_POWER);
	task.lastbytes = (TEST_DATA_SIZE & (USTUP_BLOCK_SIZE - 1));
	task.program = byte_prog;
	task.spec_params = NULL;
	cipherUstup(&task);
	bitDecryption4Tetra(eCryptUstup, test_key_bit, NULL, test_rgi_bit, test_imito_bit, result_data_bit, test_data_bit, TEST_DATA_SIZE,
						bit_mask_cipher, bit_mask_imit, pu_gamma);

	if (lmemcmp(test_imito_byte, test_imito_bit, USTUP_BLOCK_SIZE) != 0)
	{
		DINF("Test BitDec4Tetra... \t\t\t\t\tFAIL(IMITO)");
		return RET_FAIL;
	}

	DHEX("test_data_byte", result_data_byte, TEST_DATA_SIZE);
	DHEX("test_data_bit", result_data_bit, TEST_DATA_SIZE);

	if (lmemcmp(result_data_byte, result_data_bit, TEST_DATA_SIZE) != 0)
	{
		DINF("Test BitDec4Tetra... \t\t\t\t\tFAIL(DATA)");
		return RET_FAIL;
	}

	DINF("Test BitDec4Tetra... \t\t\t\t\tSUCCESS");
	return RET_OK;
}

uint8_t testBitGamming4Tetra ()
{
	uint32_t byte_prog[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t bit_mask_cipher[TEST_DATA_SIZE / sizeof(uint32_t)];

	uint32_t i;

	for (i = 0; i < TEST_DATA_SIZE; i++)
	{
		u8(byte_prog)[i] = (xor128(rng) & 1) << 1;

		if (u8(byte_prog)[i] & BIT_CIHPER_ONLY)
		{
			u8(bit_mask_cipher)[i] = 0xFF;
		}
		else
		{
			u8(bit_mask_cipher)[i] = 0x00;
		}
	}

	uint32_t test_data_byte[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t result_data_byte[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t test_key_byte[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t test_rgi_byte[USTUP_BLOCK_SIZE / sizeof(uint32_t)];

	uint32_t test_data_bit[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t result_data_bit[TEST_DATA_SIZE / sizeof(uint32_t)];
	uint32_t test_key_bit[USTUP_KEY_SIZE / sizeof(uint32_t)];
	uint32_t test_rgi_bit[USTUP_BLOCK_SIZE / sizeof(uint32_t)];

	getRandData(test_data_byte, TEST_DATA_SIZE / sizeof(uint32_t));
	getRandData(result_data_byte, TEST_DATA_SIZE / sizeof(uint32_t));
	getRandData(result_data_bit, TEST_DATA_SIZE / sizeof(uint32_t));
	getRandData(test_key_byte, USTUP_KEY_SIZE / sizeof(uint32_t));
	getRandData(test_rgi_byte, USTUP_BLOCK_SIZE / sizeof(uint32_t));

	lmemcpy (test_data_bit, test_data_byte, TEST_DATA_SIZE);
	lmemcpy (test_key_bit, test_key_byte, USTUP_KEY_SIZE);
	lmemcpy (test_rgi_bit, test_rgi_byte, USTUP_BLOCK_SIZE);

	SCipherTask task;
	task.mode =  (eTetraEncryptionGamming) & (~TASK_BIT9_CIPHER_IN_BIT_MODE);
	task.mask = NULL;
	task.key = test_key_byte;

	task.sync = test_rgi_byte;
	task.src = test_data_byte;
	task.dst = result_data_byte;
	task.blocks = (TEST_DATA_SIZE >> USTUP_BLOCK_POWER);
	task.lastbytes = (TEST_DATA_SIZE & (USTUP_BLOCK_SIZE - 1));
	task.program = byte_prog;
	task.spec_params = NULL;
	cipherUstup(&task);

	bitGamming4Tetra(eCryptUstup, test_key_bit, NULL, test_rgi_bit,
					 result_data_bit, test_data_bit, TEST_DATA_SIZE,
					 bit_mask_cipher, pu_gamma);

	DHEX("test_data_byte", result_data_byte, TEST_DATA_SIZE);
	DHEX("test_data_bit", result_data_bit, TEST_DATA_SIZE);

	if (lmemcmp(result_data_byte, result_data_bit, TEST_DATA_SIZE) != 0)
	{
		DINF("Test BitGamming4Tetra... \t\t\t\t\tFAIL(DATA)");
		return RET_FAIL;
	}

	DINF("Test BitGamming4Tetra... \t\t\t\t\tSUCCESS");
	return RET_OK;
}

uint8_t testReEncryption()
{
    uint32_t test_data_orig[TEST_DATA_SIZE / sizeof(uint32_t)];
    uint32_t test_data_byte[TEST_DATA_SIZE / sizeof(uint32_t)];
    uint32_t test_data_mask_byte[TEST_DATA_SIZE / sizeof(uint32_t)];
    uint32_t test_data_check[TEST_DATA_SIZE / sizeof(uint32_t)];

    uint32_t test_key1_byte[USTUP_KEY_SIZE / sizeof(uint32_t)];
    uint32_t test_rgi1_byte[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
    uint32_t test_imito1_byte[USTUP_BLOCK_SIZE / sizeof(uint32_t)] = {0,0};
    uint32_t test_imito_byte_check[USTUP_BLOCK_SIZE / sizeof(uint32_t)] = {0,0};
    uint32_t test_key2_byte[USTUP_KEY_SIZE / sizeof(uint32_t)];
    uint32_t test_rgi2_byte[USTUP_BLOCK_SIZE / sizeof(uint32_t)];
    uint32_t test_imito2_byte[USTUP_BLOCK_SIZE / sizeof(uint32_t)] = {0,0};

    getRandData(test_data_orig, TEST_DATA_SIZE / sizeof(uint32_t));
    DHEX("Data=", test_data_orig, TEST_DATA_SIZE);
    getRandData(test_key1_byte, USTUP_KEY_SIZE / sizeof(uint32_t));
    getRandData(test_rgi1_byte, USTUP_BLOCK_SIZE / sizeof(uint32_t));
    DHEX("K1=", test_key1_byte, USTUP_KEY_SIZE);
    DHEX("IV1=", test_rgi1_byte, USTUP_BLOCK_SIZE);
    getRandData(test_key2_byte, USTUP_KEY_SIZE / sizeof(uint32_t));
    getRandData(test_rgi2_byte, USTUP_BLOCK_SIZE / sizeof(uint32_t));
    /// 1. Исходное шифрование с обратной связью и ИЗВ
    encryptFeedbackModeWithImito(eCryptUstup, test_data_byte, test_data_orig, sizeof(test_data_orig), NULL, test_key1_byte, test_rgi1_byte, test_imito1_byte, NULL);

    DHEX("IMITO=", test_imito1_byte, USTUP_BLOCK_SIZE);
    DHEX("Enc=", test_data_byte, TEST_DATA_SIZE);
    /// 2. Подготовка данных для перешифрования и проверка ИЗВ
    SCipherTask task;
    task.mode =  TASK_BIT0_MAKE_PU | TASK_BIT1_CRYPT  |  TASK_BIT3_CRYPT_FEEDBACK | TASK_BIT4_CRYPT_IMITO |TASK_BIT5_CRYPT_SAVE | TASK_BIT11_MAKE_DECRYPT | TASK_BIT12_MAKE_GAMMA_OUT;
    task.mask = NULL;
    task.key = test_key1_byte;
    task.imito = test_imito_byte_check;
    task.sync = test_rgi1_byte;
    task.src = test_data_byte;
    task.dst = test_data_mask_byte;
    task.blocks = (TEST_DATA_SIZE >> USTUP_BLOCK_POWER);
    task.lastbytes = (TEST_DATA_SIZE & (USTUP_BLOCK_SIZE - 1));
    task.program = NULL;
    task.spec_params = NULL;
    cipher(eCryptUstup, &task);

    DHEX("MASK=", test_data_mask_byte, TEST_DATA_SIZE);
    DHEX("IMITO(CK)=", test_imito_byte_check, USTUP_BLOCK_SIZE);
    ///Это размаскирование для проверки выработанной маски
    xorBy3(test_data_check, test_data_byte, test_data_mask_byte, TEST_DATA_SIZE);
    if(lmemcmp(test_data_check, test_data_orig, TEST_DATA_SIZE)||
       lmemcmp(test_imito1_byte, test_imito_byte_check, USTUP_BLOCK_SIZE))
    {
        DINF("Test ReEncryption... \t\t\t\t\tFAIL(STAGE 1-2)");
        return RET_FAIL;
    }
    /// 3. Перешифрование и создание новой ИЗВ
    DHEX("K2=", test_key2_byte, USTUP_KEY_SIZE);
    DHEX("IV2=", test_rgi2_byte, USTUP_BLOCK_SIZE);


    task.mode =  TASK_BIT0_MAKE_PU | TASK_BIT1_CRYPT |  TASK_BIT3_CRYPT_FEEDBACK | TASK_BIT4_CRYPT_IMITO |TASK_BIT5_CRYPT_SAVE | TASK_BIT11_MAKE_CRYPT | TASK_BIT12_MAKE_GAMMA_OUT;
    task.mask = NULL;
    task.key = test_key2_byte;
    task.imito = test_imito2_byte;
    task.sync = test_rgi2_byte;
    task.src = test_data_byte;
    task.dst = test_data_mask_byte;
    task.blocks = (TEST_DATA_SIZE >> USTUP_BLOCK_POWER);
    task.lastbytes = (TEST_DATA_SIZE & (USTUP_BLOCK_SIZE - 1));
    task.program = NULL;
    task.spec_params = NULL;
    cipher(eCryptUstup, &task);

    DHEX("Enc2=", test_data_mask_byte, TEST_DATA_SIZE);
    DHEX("IMITO(CK)=", test_imito2_byte, USTUP_BLOCK_SIZE);

    /// 4. Расшифрование с проверкой ИЗВ
    decryptFeedbackModeWithImito(eCryptUstup, test_data_check, test_data_mask_byte, TEST_DATA_SIZE, NULL, test_key2_byte, test_rgi2_byte, test_imito_byte_check, NULL);
    if(lmemcmp(test_data_check, test_data_orig, TEST_DATA_SIZE)||
       lmemcmp(test_imito2_byte, test_imito_byte_check, USTUP_BLOCK_SIZE))
    {
        DINF("Test ReEncryption... \t\t\t\t\tFAIL(STAGE 3-4)");
        return RET_FAIL;
    }

    DINF("Test ReEncryption... \t\t\t\t\tSUCCESS");
    return RET_OK;
}



// Тесты функций шифрования
int main()
{

	DINF ("Ustup test started");

        rng = initRng();

	CDIE_IF(testEncryptGammaMode() != RET_OK);
        CDIE_IF(testEncryptGammaModeMasked() != RET_OK);
	CDIE_IF(testEncryptWithImito() != RET_OK);
	CDIE_IF(testEncryptWithImitoCKvit() != RET_OK);
	CDIE_IF(testDecryptWithImito() != RET_OK);
	CDIE_IF(testDecryptWithImitoCKvit() != RET_OK);
	CDIE_IF(testCheckWithImito() != RET_OK);
	CDIE_IF(testIntegrityCount() != RET_OK);
	CDIE_IF(testBitEncryption4Tetra() != RET_OK);
	CDIE_IF(testBitDecryption4Tetra() != RET_OK);
	CDIE_IF(testBitGamming4Tetra() != RET_OK);
        CDIE_IF(testReEncryption() != RET_OK);
	DINF ("Ustup test successfully finished");

        lfree(rng);
	return 0;
}


