#include "BlockChain.h"
#include "Base58.h"
#include "BitcoinAddress.h"
#include "HeapSort.h"
#include "RIPEMD160.h"
#include "SHA256.h"
#include "SimpleHash.h"

//
// Written by John W. Ratcliff : mailto: jratcliffscarab@gmail.com
//
// Website:  http://codesuppository.blogspot.com/
//
// Source contained in this project includes portions of source code from other open source projects; though that source may have
// been modified to be included here.  Original notices are left in where appropriate.
//
// Some of the hash and bignumber implementations are based on source code find in the 'cbitcoin' project; though it has been modified here to remove all memory allocations.
//
// http://cbitcoin.com/
//
// If you find this code snippet useful; you can tip me at this bitcoin address:
//
// BITCOIN TIP JAR: "1NY8SuaXfh8h5WHd4QnYwpgL1mNu9hHVBT"
//

#ifdef _MSC_VER // Disable the stupid ass absurd warning messages from Visual Studio telling you that using stdlib and stdio is 'not valid ANSI C'
#pragma warning(disable:4996)
#pragma warning(disable:4718)
#endif

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

// Note, to minimize dynamic memory allocation this parser pre-allocates memory for the maximum ever expected number
// of bitcoin addresses, transactions, inputs, outputs, and blocks.
// The numbers here are large enough to read the entire blockchain as of January 1, 2014 with a fair amount of room to grow.
// However, they will need to be increased over time as the blockchain grows.
// Dynamic memory allocation isn't free, every time you dynamically allocate memory there is a significant overhead; so by pre-allocating
// all of the memory needed into one contiguous block you actually save an enormous amount of memory overall and also make the code run
// orders of magnitude faster.

#define SMALL_MEMORY_PROFILE 0 // a debug option so I can run/test the code on a small memory configuration machine  If this is

static uint32_t ZOMBIE_DAYS=365*3;

#if SMALL_MEMORY_PROFILE

// Enough memory to process the first 200,000 blocks, useful for testing.
#define MAX_BITCOIN_ADDRESSES 14000000 //
#define MAX_TOTAL_TRANSACTIONS 14000000 //
#define MAX_TOTAL_INPUTS  45000000 //
#define MAX_TOTAL_OUTPUTS 45000000 //
#define MAX_TOTAL_BLOCKS 300000		//

#else

#define MAX_BITCOIN_ADDRESSES 70000000 // 60 million unique addresses.

#define MAX_TOTAL_TRANSACTIONS 90000000 // 90 million transactions.
#define MAX_TOTAL_INPUTS 350000000 // 260 million inputs.
#define MAX_TOTAL_OUTPUTS 350000000 // 260 million outputs
#define MAX_TOTAL_BLOCKS 600000		// 600,000 blocks.

#endif

#define MAX_PLOT_COUNT 2000000


// Some globals for error reporting.
static uint32_t	gBlockTime=0;
static uint32_t gBlockIndex=0;
static uint32_t gTransactionIndex=0;
//static uint8_t	gTransactionHash[256];
static uint32_t gOutputIndex=0;
static bool		gIsWarning=false;
static FILE		*gWeirdSignatureFile=NULL;
static FILE		*gAsciiSignatureFile=NULL;
static FILE		*gLogFile=NULL;
static bool		gReportTransactionHash=false;
static bool		gDumpBlock=false;

static const char *gDummyKeyAscii = "1BadkEyPaj5oW2Uw4nY5BkYbPRYyTyqs9A";
static uint8_t gDummyKey[25];
static const char *gZeroByteAscii = "1zeroBTYRExUcufrTkwg27LsAvrhehtCJ";
static uint8_t gZeroByte[25];

static bool inline isASCII(char c)
{
	bool ret = false;

	if ( (c >= 32 && c < 127) || c == 13 )
	{
		ret = true;
	}

	return ret;
}

static const char *getDateString(time_t t)
{
	static char scratch[1024];
	struct tm *gtm = gmtime(&t);
//	strftime(scratch, 1024, "%m, %d, %Y", gtm);
	sprintf(scratch,"%4d-%02d-%02d", gtm->tm_year+1900, gtm->tm_mon+1, gtm->tm_mday );
	return scratch;
}


static void logMessage(const char *fmt,...)
{
	char wbuff[2048];
	va_list arg;
	va_start( arg, fmt );
	vsprintf(wbuff,fmt, arg);
	va_end(arg);
	printf("%s",wbuff);
	if ( gLogFile == NULL )
	{
		gLogFile = fopen("blockchain.txt", "wb");
	}
	if ( gLogFile )
	{
		fprintf(gLogFile,"%s", wbuff );
		fflush(gLogFile);
	}
}

class Hash256
{
public:
	Hash256(void)
	{
		mWord0 = 0;
		mWord1 = 0;
		mWord2 = 0;
		mWord3 = 0;
	}

	Hash256(const Hash256 &h)
	{
		mWord0 = h.mWord0;
		mWord1 = h.mWord1;
		mWord2 = h.mWord2;
		mWord3 = h.mWord3;
	}

	inline Hash256(const uint8_t *src)
	{
		mWord0 = *(const uint64_t *)(src);
		mWord1 = *(const uint64_t *)(src+8);
		mWord2 = *(const uint64_t *)(src+16);
		mWord3 = *(const uint64_t *)(src+24);
	}

	inline uint32_t getHash(void) const
	{
		const uint32_t *h = (const uint32_t *)&mWord0;
		return h[0] ^ h[1] ^ h[2] ^ h[3] ^ h[4] ^ h[5] ^ h[6] ^ h[7];
	}

	inline bool operator==(const Hash256 &h) const
	{
		return mWord0 == h.mWord0 && mWord1 == h.mWord1 && mWord2 == h.mWord2 && mWord3 == h.mWord3;
	}


	uint64_t	mWord0;
	uint64_t	mWord1;
	uint64_t	mWord2;
	uint64_t	mWord3;
};

static void printReverseHash(const uint8_t *hash)
{
	if ( hash )
	{
		for (uint32_t i=0; i<32; i++)
		{
			logMessage("%02x", hash[31-i] );
		}
	}
	else
	{
		logMessage("NULL HASH");
	}
}

static void fprintReverseHash(FILE *fph,const uint8_t *hash)
{
	if ( hash )
	{
		for (uint32_t i=0; i<32; i++)
		{
			fprintf(fph,"%02x", hash[31-i] );
		}
	}
	else
	{
		fprintf(fph,"NULL HASH");
	}
}

class BlockHeader : public Hash256
{
public:
	BlockHeader(void)
	{
		mFileIndex = 0;
		mFileOffset = 0;
		mBlockLength = 0;
	}
	BlockHeader(const Hash256 &h) : Hash256(h)
	{
		mFileIndex = 0;
		mFileOffset = 0;
		mBlockLength = 0;
	}
	uint32_t	mFileIndex;
	uint32_t	mFileOffset;
	uint32_t	mBlockLength;
	uint8_t		mPreviousBlockHash[32];
};

struct BlockPrefix
{
	uint32_t	mVersion;					// The block version number.
	uint8_t		mPreviousBlock[32];			// The 32 byte (256 bit) hash of the previous block in the blockchain
	uint8_t		mMerkleRoot[32];			// The 32 bye merkle root hash
	uint32_t	mTimeStamp;					// The block time stamp
	uint32_t	mBits;						// The block bits field.
	uint32_t	mNonce;						// The block random number 'nonce' field.
};



static const char *getTimeString(uint32_t timeStamp)
{
	if ( timeStamp == 0 )
	{
		return "NEVER";
	}
	static char scratch[1024];
	time_t t(timeStamp);
	struct tm *gtm = gmtime(&t);
	strftime(scratch, 1024, "%m/%d/%Y %H:%M:%S", gtm);
	return scratch;
}


#define MAXNUMERIC 32  // JWR  support up to 16 32 character long numeric formated strings
#define MAXFNUM    16

static	char  gFormat[MAXNUMERIC*MAXFNUM];
static int32_t    gIndex=0;

static const char * formatNumber(int32_t number) // JWR  format this integer into a fancy comma delimited string
{
	char * dest = &gFormat[gIndex*MAXNUMERIC];
	gIndex++;
	if ( gIndex == MAXFNUM ) gIndex = 0;

	char scratch[512];

#ifdef _MSC_VER
	itoa(number,scratch,10);
#else
	snprintf(scratch, 10, "%d", number);
#endif

	char *source = scratch;
	char *str = dest;
	uint32_t len = (uint32_t)strlen(scratch);
	if ( scratch[0] == '-' )
	{
		*str++ = '-';
		source++;
		len--;
	}
	for (uint32_t i=0; i<len; i++)
	{
		int32_t place = (len-1)-i;
		*str++ = source[i];
		if ( place && (place%3) == 0 ) *str++ = ',';
	}
	*str = 0;

	return dest;
}

class FileLocation : public Hash256
{
public:
	FileLocation(void)
	{

	}
	FileLocation(const Hash256 &h,uint32_t fileIndex,uint32_t fileOffset,uint32_t fileLength,uint32_t transactionIndex) : Hash256(h)
	{
		mFileIndex = fileIndex;
		mFileOffset = fileOffset;
		mFileLength = fileLength;
		mTransactionIndex = transactionIndex;
	}
	uint32_t	mFileIndex;
	uint32_t	mFileOffset;
	uint32_t	mFileLength;
	uint32_t	mTransactionIndex;
};

typedef SimpleHash< FileLocation, 4194304, MAX_TOTAL_TRANSACTIONS > TransactionHashMap;
typedef SimpleHash< BlockHeader, 4194304, MAX_TOTAL_BLOCKS > BlockHeaderMap;

enum ScriptOpcodes
{
	OP_0 			=  0x00,
	OP_PUSHDATA1 	=  0x4c,
	OP_PUSHDATA2 	=  0x4d,
	OP_PUSHDATA4 	=  0x4e,
	OP_1NEGATE 		=  0x4f,
	OP_RESERVED 	=  0x50,
	OP_1 			=  0x51,
	OP_2 			=  0x52,
	OP_3 			=  0x53,
	OP_4 			=  0x54,
	OP_5 			=  0x55,
	OP_6 			=  0x56,
	OP_7 			=  0x57,
	OP_8 			=  0x58,
	OP_9 			=  0x59,
	OP_10 			=  0x5a,
	OP_11 			=  0x5b,
	OP_12 			=  0x5c,
	OP_13 			=  0x5d,
	OP_14 			=  0x5e,
	OP_15 			=  0x5f,
	OP_16 			=  0x60,
	OP_NOP 			=  0x61,
	OP_VER 			=  0x62,
	OP_IF 			=  0x63,
	OP_NOTIF 		=  0x64,
	OP_VERIF 		=  0x65,
	OP_VERNOTIF 	=  0x66,
	OP_ELSE 		=  0x67,
	OP_ENDIF 		=  0x68,
	OP_VERIFY 		=  0x69,
	OP_RETURN 		=  0x6a,
	OP_TOALTSTACK 	=  0x6b,
	OP_FROMALTSTACK =  0x6c,
	OP_2DROP 		=  0x6d,
	OP_2DUP 		=  0x6e,
	OP_3DUP 		=  0x6f,
	OP_2OVER 		=  0x70,
	OP_2ROT 		=  0x71,
	OP_2SWAP 		=  0x72,
	OP_IFDUP 		=  0x73,
	OP_DEPTH 		=  0x74,
	OP_DROP 		=  0x75,
	OP_DUP 			=  0x76,
	OP_NIP 			=  0x77,
	OP_OVER 		=  0x78,
	OP_PICK 		=  0x79,
	OP_ROLL 		=  0x7a,
	OP_ROT 			=  0x7b,
	OP_SWAP 		=  0x7c,
	OP_TUCK 		=  0x7d,
	OP_CAT 			=  0x7e,	// Currently disabled
	OP_SUBSTR 		=  0x7f,	// Currently disabled
	OP_LEFT 		=  0x80,	// Currently disabled
	OP_RIGHT 		=  0x81,	// Currently disabled
	OP_SIZE 		=  0x82,	// Currently disabled
	OP_INVERT 		=  0x83,	// Currently disabled
	OP_AND 			=  0x84,	// Currently disabled
	OP_OR 			=  0x85,	// Currently disabled
	OP_XOR 			=  0x86,	// Currently disabled
	OP_EQUAL 		=  0x87,
	OP_EQUALVERIFY 	=  0x88,
	OP_RESERVED1 	=  0x89,
	OP_RESERVED2 	=  0x8a,
	OP_1ADD 		=  0x8b,
	OP_1SUB 		=  0x8c,
	OP_2MUL 		=  0x8d,	// Currently disabled
	OP_2DIV 		=  0x8e,	// Currently disabled
	OP_NEGATE 		=  0x8f,
	OP_ABS 			=  0x90,
	OP_NOT 			=  0x91,
	OP_0NOTEQUAL 	=  0x92,
	OP_ADD 			=  0x93,
	OP_SUB 			=  0x94,
	OP_MUL 			=  0x95,	// Currently disabled
	OP_DIV 			=  0x96,	// Currently disabled
	OP_MOD 			=  0x97,	// Currently disabled
	OP_LSHIFT 		=  0x98,	// Currently disabled
	OP_RSHIFT 		=  0x99,	// Currently disabled
	OP_BOOLAND 		=  0x9a,
	OP_BOOLOR 		=  0x9b,
	OP_NUMEQUAL 	=  0x9c,
	OP_NUMEQUALVERIFY =  0x9d,
	OP_NUMNOTEQUAL 	=  0x9e,
	OP_LESSTHAN 	=  0x9f,
	OP_GREATERTHAN 	=  0xa0,
	OP_LESSTHANOREQUAL =  0xa1,
	OP_GREATERTHANOREQUAL =  0xa2,
	OP_MIN 			=  0xa3,
	OP_MAX 			=  0xa4,
	OP_WITHIN 		=  0xa5,
	OP_RIPEMD160 	=  0xa6,
	OP_SHA1 		=  0xa7,
	OP_SHA256		=  0xa8,
	OP_HASH160 		=  0xa9,
	OP_HASH256 		=  0xaa,
	OP_CODESEPARATOR =  0xab,
	OP_CHECKSIG 	=  0xac,
	OP_CHECKSIGVERIFY =  0xad,
	OP_CHECKMULTISIG =  0xae,
	OP_CHECKMULTISIGVERIFY = 0xaf,
	OP_NOP1 		=  0xb0,
	OP_NOP2 		=  0xb1,
	OP_NOP3 		=  0xb2,
	OP_NOP4 		=  0xb3,
	OP_NOP5 		=  0xb4,
	OP_NOP6 		=  0xb5,
	OP_NOP7 		=  0xb6,
	OP_NOP8 		=  0xb7,
	OP_NOP9 		=  0xb8,
	OP_NOP10 		=  0xb9,
	OP_SMALLINTEGER =  0xfa,
	OP_PUBKEYS 		=  0xfb,
	OP_PUBKEYHASH 	=  0xfd,
	OP_PUBKEY 		=  0xfe,
	OP_INVALIDOPCODE =  0xff
};

#define MAGIC_ID 0xD9B4BEF9
#define ONE_BTC 100000000
#define ONE_MBTC (ONE_BTC/1000)

#define MAX_BLOCK_FILES	512	// As of July 6, 2013 there are only about 70 .dat files; so it will be a long time before this overflows

// These defines set the limits this parser expects to ever encounter on the blockchain data stream.
// In a debug build there are asserts to make sure these limits are never exceeded.
// These limits work for the blockchain current as of July 1, 2013.
// The limits can be revised when and if necessary.
#define MAX_BLOCK_SIZE (1024*1024)*10	// never expect to have a block larger than 10mb
#define MAX_BLOCK_TRANSACTION 8192		// never expect more than 8192 transactions per block.
#define MAX_BLOCK_INPUTS 32768			// never expect more than 8192 total inputs
#define MAX_BLOCK_OUTPUTS 32768			// never expect more than 8192 total outputs

#define MAX_REASONABLE_SCRIPT_LENGTH (1024*32) // would never expect any script to be more than 16k in size; that would be very unusual!
#define MAX_REASONABLE_INPUTS 8192				// really can't imagine any transaction ever having more than 8192 inputs
#define MAX_REASONABLE_OUTPUTS 8192				// really can't imagine any transaction ever having more than 8192 outputs

class SignatureStat
{
public:
	SignatureStat(void)
	{
		mFlags = 0;
		mCount = 0;
		mValue = 0;
	}
	uint32_t	mFlags;
	uint32_t	mCount;
	uint64_t	mValue;
};

#define MAX_SIGNATURE_STAT 256

static uint32_t			gSignatureStatCount=0;
static SignatureStat	gSignatureStats[MAX_SIGNATURE_STAT];


//********************************************
//********************************************
#define MAX_TRANSACTION_STAT 30000000
class TransactionBlockStat
{
public:
	TransactionBlockStat(void)
	{
		mValues = NULL;
		init();
	}
	~TransactionBlockStat(void)
	{
		delete []mValues;
	}

	void init(void)
	{
		mBlockCount = 0;
		mBlockSize = 0;
		mTransactionCount = 0;
		mTransactionSize = 0;
		mInputCount = 0;
		mOutputCount = 0;
		mCoinBaseValue = 0;
		mInputValue = 0;
		mOutputValue = 0;
		mFeeValue = 0;
		mDustCount = 0;
	}
	uint32_t	mBlockCount;
	uint32_t	mBlockSize;
	uint32_t	mTransactionCount;
	uint32_t	mTransactionSize;
	uint32_t	mInputCount;
	uint32_t	mOutputCount;
	uint64_t	mCoinBaseValue;
	uint64_t	mInputValue;
	uint64_t	mOutputValue;
	uint64_t	mFeeValue;
	uint64_t	*mValues;
	uint32_t	mDustCount;
};


class BlockImpl : public BlockChain::Block
{
public:
	// Read one byte from the block-chain input stream.
	inline uint8_t readU8(void)
	{
		assert( (mBlockRead+sizeof(uint8_t)) <= mBlockEnd );
		uint8_t ret = *(uint8_t *)mBlockRead;
		mBlockRead+=sizeof(uint8_t);
		return ret;
	}

	// Read two bytes from the block-chain input stream.
	inline uint16_t readU16(void)
	{
		assert( (mBlockRead+sizeof(uint16_t)) <= mBlockEnd );
		uint16_t ret = *(uint16_t *)mBlockRead;
		mBlockRead+=sizeof(uint16_t);
		return ret;
	}

	// Read four bytes from the block-chain input stream.
	inline uint32_t readU32(void)
	{
		assert( (mBlockRead+sizeof(uint32_t)) <= mBlockEnd );
		uint32_t ret = *(uint32_t *)mBlockRead;
		mBlockRead+=sizeof(uint32_t);
		return ret;
	}

	// Read eight bytes from the block-chain input stream.
	inline uint64_t readU64(void)
	{
		assert( (mBlockRead+sizeof(uint64_t)) <= mBlockEnd );
		uint64_t ret = *(uint64_t *)mBlockRead;
		mBlockRead+=sizeof(uint64_t);
		return ret;
	}

	// Return the current stream pointer representing a 32byte hash and advance the read pointer accordingly
	inline const uint8_t *readHash(void)
	{
		const uint8_t *ret = mBlockRead;
		assert( (mBlockRead+32) <= mBlockEnd );
		mBlockRead+=32;
		return ret;
	}

	// reads a variable length integer.
	// See the documentation from here:  https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
	inline uint32_t readVariableLengthInteger(void)
	{
		uint32_t ret = 0;

		uint8_t v = readU8();
		if ( v < 0xFD ) // If it's less than 0xFD use this value as the unsigned integer
		{
			ret = (uint32_t)v;
		}
		else
		{
			uint16_t v = readU16();
			if ( v < 0xFFFF )
			{
				ret = (uint32_t)v;
			}
			else
			{
				uint32_t v = readU32();
				if ( v < 0xFFFFFFFF )
				{
					ret = (uint32_t)v;
				}
				else
				{
					assert(0); // never expect to actually encounter a 64bit integer in the block-chain stream; it's outside of any reasonable expected value
					uint64_t v = readU64();
					ret = (uint32_t)v;
				}
			}
		}
		return ret;
	}

	// Get the current read buffer address and advance the stream buffer by this length; used to get the address of input/output scripts
	inline const uint8_t * getReadBufferAdvance(uint32_t readLength)
	{
		const uint8_t *ret = mBlockRead;
		mBlockRead+=readLength;
		assert( mBlockRead <= mBlockEnd );
		return ret;
	}


	// Read a transaction input
	bool readInput(BlockChain::BlockInput &input)
	{
		bool ret = true;

		input.transactionHash = readHash();	// read the transaction hash
		input.transactionIndex = readU32();	// read the transaction index
		input.responseScriptLength = readVariableLengthInteger();	// read the length of the script
		assert( input.responseScriptLength < MAX_REASONABLE_SCRIPT_LENGTH );

		if ( input.responseScriptLength >= 8192 )
		{
			logMessage("Block: %d : Unreasonably large input script length of %d bytes.\r\n", gBlockIndex, input.responseScriptLength );
		}

		if ( input.responseScriptLength < MAX_REASONABLE_SCRIPT_LENGTH )
		{
			input.responseScript = input.responseScriptLength ? getReadBufferAdvance(input.responseScriptLength) : NULL;	// get the script buffer pointer; and advance the read location
			input.sequenceNumber = readU32();
		}
		else
		{
			logMessage("Block %d : Outrageous sized input script of %d bytes!  Shutting down.\r\n", gBlockIndex, input.responseScriptLength );
			exit(1);
		}
		return ret;
	}

	void getAsciiAddress(BlockChain::BlockOutput &o)
	{
		o.asciiAddress[0] = 0;
		char temp[256];

		switch ( o.keyType )
		{
			case BlockChain::KT_MULTISIG:
				sprintf(o.asciiAddress,"MultiSig[%d]",o.signatureCount );
				break;
			case BlockChain::KT_STEALTH:
				strcat(o.asciiAddress,"*STEALTH*");
				break;
			case BlockChain::KT_SCRIPT_HASH:
				strcat(o.asciiAddress,"*SCRIPT_HASH*");
				break;
            default:
                break;
		}
		for (uint32_t i=0; i<MAX_MULTISIG; i++)
		{
			if ( o.publicKey[i] )
			{
				if ( i )
				{
					strcat(o.asciiAddress,":");
				}
				bitcoinAddressToAscii(o.addresses[i].address,temp,256);
				strcat(o.asciiAddress,temp);
			}
			else
			{
				break;
			}
		}
		// If this is a multi-sig address, *then* we need to generate a multisig address for it.
		if ( o.keyType == BlockChain::KT_MULTISIG )
		{
			uint8_t hash[20];
			computeRIPEMD160(&o.addresses,25*MAX_MULTISIG,hash);
			bitcoinRIPEMD160ToAddress(hash,o.multisig.address);
		}
	}

	const char * getKeyType(BlockChain::KeyType k)
	{
		const char *ret = "UNKNOWN";
		switch ( k )
		{
			case BlockChain::KT_RIPEMD160:
				ret = "RIPEMD160";
				break;
			case BlockChain::KT_UNCOMPRESSED_PUBLIC_KEY:
				ret = "UNCOMPRESSED_PUBLIC_KEY";
				break;
			case BlockChain::KT_COMPRESSED_PUBLIC_KEY:
				ret = "COMPRESSED_PUBLIC_KEY";
				break;
			case BlockChain::KT_TRUNCATED_COMPRESSED_KEY:
				ret = "TRUNCATED_COMPRESSED_KEY";
				break;
			case BlockChain::KT_MULTISIG:
				ret = "MULTISIG";
				break;
			case BlockChain::KT_STEALTH:
				ret = "STEALTH";
				break;
			case BlockChain::KT_ZERO_LENGTH:
				ret = "ZERO_LENGTH";
				break;
			case BlockChain::KT_SCRIPT_HASH:
				ret = "SCRIPT_HASH";
				break;
            default:
                break;
		}
		return ret;
	}

	// Read an output block
	bool readOutput(BlockChain::BlockOutput &output)
	{
		bool ret = true;

		new ( &output ) BlockChain::BlockOutput;

		output.value = readU64();	// Read the value of the transaction
		blockReward+=output.value;
		output.challengeScriptLength = readVariableLengthInteger();
		assert ( output.challengeScriptLength < MAX_REASONABLE_SCRIPT_LENGTH );

		if ( output.challengeScriptLength >= 8192 )
		{
			logMessage("Block %d : Unreasonably large output script length of %d bytes.\r\n", gBlockIndex, output.challengeScriptLength );
		}
		else if ( output.challengeScriptLength > MAX_REASONABLE_SCRIPT_LENGTH )
		{
			logMessage("Block %d : output script too long %d bytes!\r\n", gBlockIndex, output.challengeScriptLength );
			exit(1);
		}

		output.challengeScript = output.challengeScriptLength ? getReadBufferAdvance(output.challengeScriptLength) : NULL; // get the script buffer pointer and advance the read location

		if ( output.challengeScript )
		{
			uint8_t lastInstruction = output.challengeScript[output.challengeScriptLength-1];
			if ( output.challengeScriptLength == 67 && output.challengeScript[0] == 65  && output.challengeScript[66]== OP_CHECKSIG )
			{
				output.publicKey[0] = output.challengeScript+1;
				output.keyType = BlockChain::KT_UNCOMPRESSED_PUBLIC_KEY;
			}
			if ( output.challengeScriptLength == 40 && output.challengeScript[0] == OP_RETURN )
			{
				output.publicKey[0] = &output.challengeScript[1];
				output.keyType = BlockChain::KT_STEALTH;
			}
			else if ( output.challengeScriptLength == 66 && output.challengeScript[65]== OP_CHECKSIG )
			{
				output.publicKey[0] = output.challengeScript;
				output.keyType = BlockChain::KT_UNCOMPRESSED_PUBLIC_KEY;
			}
			else if ( output.challengeScriptLength == 35 && output.challengeScript[34] == OP_CHECKSIG )
			{
				output.publicKey[0] = &output.challengeScript[1];
				output.keyType = BlockChain::KT_COMPRESSED_PUBLIC_KEY;
			}
			else if ( output.challengeScriptLength == 33 && output.challengeScript[0] == 0x20 )
			{
				output.publicKey[0] = &output.challengeScript[1];
				output.keyType = BlockChain::KT_TRUNCATED_COMPRESSED_KEY;
			}
			else if ( output.challengeScriptLength == 23 &&
				output.challengeScript[0] == OP_HASH160 &&
				output.challengeScript[1] == 20 &&
				output.challengeScript[22] == OP_EQUAL )
			{
				output.publicKey[0] = output.challengeScript+2;
				output.keyType = BlockChain::KT_SCRIPT_HASH;
			}
			else if ( output.challengeScriptLength >= 25 &&
					  output.challengeScript[0] == OP_DUP &&
					  output.challengeScript[1] == OP_HASH160 &&
					  output.challengeScript[2] == 20 )
			{
				output.publicKey[0] = output.challengeScript+3;
				output.keyType = BlockChain::KT_RIPEMD160;
			}
			else if ( output.challengeScriptLength == 5 &&
					  output.challengeScript[0] == OP_DUP &&
					  output.challengeScript[1] == OP_HASH160 &&
					  output.challengeScript[2] == OP_0 &&
					  output.challengeScript[3] == OP_EQUALVERIFY &&
					  output.challengeScript[4] == OP_CHECKSIG )
			{
				logMessage("WARNING: Unusual but expected output script. Block %s : Transaction: %s : OutputIndex: %s\r\n", formatNumber(gBlockIndex), formatNumber(gTransactionIndex), formatNumber(gOutputIndex) );
				gIsWarning = true;
			}
			else if ( lastInstruction == OP_CHECKMULTISIG && output.challengeScriptLength > 25 ) // looks to be a multi-sig
			{
				const uint8_t *scanBegin = output.challengeScript;
				const uint8_t *scanEnd = &output.challengeScript[output.challengeScriptLength-2];
				bool expectedPrefix = false;
				bool expectedPostfix = false;
				switch ( *scanBegin )
				{
					case OP_0:
					case OP_1:
					case OP_2:
					case OP_3:
					case OP_4:
					case OP_5:
						expectedPrefix = true;
						break;
					default:
//						assert(0); // unexpected
						break;
				}
				switch ( *scanEnd )
				{
					case OP_1:
					case OP_2:
					case OP_3:
					case OP_4:
					case OP_5:
						expectedPostfix = true;
						break;
					default:
//						assert(0); // unexpected
						break;
				}
				if ( expectedPrefix && expectedPostfix )
				{
					scanBegin++;
					uint32_t keyIndex = 0;
					while ( keyIndex < 5 && scanBegin < scanEnd )
					{
						if ( *scanBegin == 0x21 )
						{
							output.keyType = BlockChain::KT_MULTISIG;
							scanBegin++;
							output.publicKey[keyIndex] = scanBegin;
							scanBegin+=0x21;
							uint32_t bitMask = 1<<keyIndex;
							output.multiSigFormat|=bitMask; // turn this bit on if it is in compressed format
							keyIndex++;
						}
						else if ( *scanBegin == 0x41 )
						{
							output.keyType = BlockChain::KT_MULTISIG;
							scanBegin++;
							output.publicKey[keyIndex] = scanBegin;
							scanBegin+=0x41;
							keyIndex++;
						}
						else
						{
							break; //
						}
					}
				}
				if ( output.publicKey[0] == NULL )
				{
					logMessage("****MULTI_SIG WARNING: Unable to decipher multi-sig output. Block %s : Transaction: %s : OutputIndex: %s\r\n", formatNumber(gBlockIndex), formatNumber(gTransactionIndex), formatNumber(gOutputIndex) );
					gIsWarning = true;
				}
			}
			else
			{
				// Ok..we are going to scan for this pattern.. OP_DUP, OP_HASH160, 0x14 then exactly 20 bytes after 0x88,0xAC
				// 25...
				if ( output.challengeScriptLength > 25 )
				{
					uint32_t endIndex = output.challengeScriptLength-25;
					for (uint32_t i=0; i<endIndex; i++)
					{
						const uint8_t *scan = &output.challengeScript[i];
						if ( scan[0] == OP_DUP &&
							 scan[1] == OP_HASH160 &&
							 scan[2] == 20 &&
							 scan[23] == OP_EQUALVERIFY &&
							 scan[24] == OP_CHECKSIG )
						{
							output.publicKey[0] = &scan[3];
							output.keyType = BlockChain::KT_RIPEMD160;
							logMessage("WARNING: Unusual output script. Block %s : Transaction: %s : OutputIndex: %s\r\n", formatNumber(gBlockIndex), formatNumber(gTransactionIndex), formatNumber(gOutputIndex) );
							gIsWarning = true;
							break;
						}
					}
				}
			}
			if ( output.publicKey[0] == NULL )
			{
				logMessage("==========================================\r\n");
				logMessage("FAILED TO LOCATE PUBLIC KEY\r\n");
				logMessage("ChallengeScriptLength: %d bytes long\r\n", output.challengeScriptLength );
				for (uint32_t i=0; i<output.challengeScriptLength; i++)
				{
					logMessage("%02x ", output.challengeScript[i] );
					if ( ((i+16)&15) == 0 )
					{
						logMessage("\r\n");
					}
				}
				logMessage("\r\n");
				logMessage("==========================================\r\n");
				logMessage("\r\n");
			}
		}
		else
		{
			logMessage("Block %d : has a zero byte length output script?\r\n", gBlockIndex);
			gReportTransactionHash = true;
		}

		if ( !output.publicKey[0] )
		{
			if ( output.challengeScriptLength == 0 )
			{
				output.publicKey[0] = &gZeroByte[1];
			}
			else
			{
				output.publicKey[0] = &gDummyKey[1];
			}
			output.keyType = BlockChain::KT_RIPEMD160;
			logMessage("WARNING: Failed to decode public key in output script. Block %s : Transaction: %s : OutputIndex: %s scriptLength: %s\r\n", formatNumber(gBlockIndex), formatNumber(gTransactionIndex), formatNumber(gOutputIndex), formatNumber(output.challengeScriptLength) );
			gReportTransactionHash = true;
			gIsWarning = true;
		}


		switch ( output.keyType )
		{
			case BlockChain::KT_RIPEMD160:
				bitcoinRIPEMD160ToAddress(output.publicKey[0],output.addresses[0].address);
				break;
			case BlockChain::KT_SCRIPT_HASH:
				bitcoinRIPEMD160ToScriptAddress(output.publicKey[0],output.addresses[0].address);
				break;
			case BlockChain::KT_STEALTH:
				bitcoinRIPEMD160ToAddress(output.publicKey[0],output.addresses[0].address);
				break;
			case BlockChain::KT_UNCOMPRESSED_PUBLIC_KEY:
				{
					bitcoinPublicKeyToAddress(output.publicKey[0],output.addresses[0].address);
				}
				break;
			case BlockChain::KT_COMPRESSED_PUBLIC_KEY:
				{
					bitcoinCompressedPublicKeyToAddress(output.publicKey[0],output.addresses[0].address);
				}
				break;
			case BlockChain::KT_TRUNCATED_COMPRESSED_KEY:
				{
					uint8_t key[33];
					key[0] = 0x2;
					memcpy(&key,output.publicKey[0],32);
					bitcoinCompressedPublicKeyToAddress(key,output.addresses[0].address);
				}
				break;
			case BlockChain::KT_MULTISIG:
				{
					for (uint32_t i=0; i<MAX_MULTISIG; i++)
					{
						const uint8_t *key = output.publicKey[i];
						if ( key == NULL )
							break;
						uint32_t mask = 1<<i;
						if ( output.multiSigFormat & mask )
						{
							bitcoinCompressedPublicKeyToAddress(output.publicKey[i],output.addresses[i].address);
						}
						else
						{
							bitcoinPublicKeyToAddress(output.publicKey[i],output.addresses[i].address);
						}
					}
				}
				break;
            default:
                break;
		}
		output.keyTypeName = getKeyType(output.keyType);
		getAsciiAddress(output);

//		if ( output.keyType == BlockChain::KT_SCRIPT_HASH )
//		{
//			logMessage("ScriptHash: %s\r\n", output.asciiAddress );
//		}

		if ( gReportTransactionHash )
		{
			gIsWarning = true;
		}
		return ret;
	}

	// Read a single transaction
	bool readTransaction(BlockChain::BlockTransaction &transaction,
						uint32_t &transactionIndex,
						uint32_t tindex)
	{
		bool ret = false;

		const uint8_t *transactionBegin = mBlockRead;

		transaction.transactionVersionNumber = readU32(); // read the transaction version number; always expect it to be 1

		if ( transaction.transactionVersionNumber == 1 || transaction.transactionVersionNumber == 2 )
		{
		}
		else
		{
			gIsWarning = true;
			logMessage("Encountered unusual and unexpected transaction version number of [%d] for transaction #%d\r\n", transaction.transactionVersionNumber, tindex );
		}

		transaction.inputCount = readVariableLengthInteger();
		assert( transaction.inputCount < MAX_REASONABLE_INPUTS );
		if ( transaction.inputCount >= MAX_REASONABLE_INPUTS )
		{
			logMessage("Invalid number of inputs found! %d\r\n", transaction.inputCount );
			exit(1);
		}
		transaction.inputs = &mInputs[totalInputCount];
		totalInputCount+=transaction.inputCount;
		assert( totalInputCount < MAX_BLOCK_INPUTS );
		if ( totalInputCount >= MAX_BLOCK_INPUTS )
		{
			logMessage("Invalid number of block inputs: %d\r\n", totalInputCount );
			exit(1);
		}
		if ( totalInputCount < MAX_BLOCK_INPUTS )
		{
			for (uint32_t i=0; i<transaction.inputCount; i++)
			{
				BlockChain::BlockInput &input = transaction.inputs[i];
				ret = readInput(input);	// read the input
				if ( !ret )
				{
					logMessage("Failed to read input!\r\n");
					exit(1);
//					break;
				}
			}
		}
		if ( ret )
		{
			transaction.outputCount = readVariableLengthInteger();
			assert( transaction.outputCount < MAX_REASONABLE_OUTPUTS );
			if ( transaction.outputCount > MAX_REASONABLE_OUTPUTS )
			{
				logMessage("Exceeded maximum reasonable outputs.\r\n");
				exit(1);
			}
			transaction.outputs = &mOutputs[totalOutputCount];
			totalOutputCount+=transaction.outputCount;
			assert( totalOutputCount < MAX_BLOCK_OUTPUTS );
			if ( totalOutputCount >= MAX_BLOCK_OUTPUTS )
			{
				logMessage("Invalid number of block outputs. %d\r\n", totalOutputCount );
				exit(1);
			}
			if ( totalOutputCount < MAX_BLOCK_OUTPUTS )
			{
				for (uint32_t i=0; i<transaction.outputCount; i++)
				{
					gOutputIndex = i;
					BlockChain::BlockOutput &output = transaction.outputs[i];
					ret = readOutput(output);
					if ( !ret )
					{
						logMessage("Failed to read output.\r\n");
						exit(1);
//						break;
					}
				}

				transaction.lockTime = readU32();

				{
					transaction.transactionLength = (uint32_t)(mBlockRead - transactionBegin);
					transaction.fileIndex = fileIndex;
					transaction.fileOffset = fileOffset + (uint32_t)(transactionBegin-mBlockData);
					transaction.transactionIndex = transactionIndex;
					transactionIndex++;
					computeSHA256(transactionBegin,transaction.transactionLength,transaction.transactionHash);
					computeSHA256(transaction.transactionHash,32,transaction.transactionHash);

					if ( gReportTransactionHash )
					{
						logMessage("TRANSACTION HASH:" );
						printReverseHash(transaction.transactionHash);
						logMessage("\r\n");
						gReportTransactionHash = false;
					}

				}

			}
		}
		return ret;
	}

	// @see this link for detailed documentation:
	//
	// http://james.lab6.com/2012/01/12/bitcoin-285-bytes-that-changed-the-world/
	//
	// read a single block from the block chain into memory
	// Here is how a block is read.
	//
	// Step #1 : We read the block format version
	// Step #2 : We read the hash of the previous block
	// Step #3 : We read the merkle root hash
	// Step #4 : We read the block time stamp
	// Step #5 : We read a 'bits' field; internal use defined by the bitcoin software
	// Step #6 : We read the 'nonce' value; a randum number generated during the mining process.
	// Step #7 : We read the transaction count
	// Step #8 : For/Each Transaction
	//          : (a) We read the transaction version number.
	//          : (b) We read the number of inputs.
	//Step #8a : For/Each input
	//			: (a) Read the hash of the input transaction
	//			: (b) Read the input transaction index
	//			: (c) Read the response script length
	//			: (d) Read the response script data; parsed using the bitcoin scripting system; a little virtual machine.
	//			: Read the sequence number.
	//			: Read the number of outputs
	//Step #8b : For/Each Output
	//			: (a) Read the value of the output in BTC fixed decimal; see docs.
	//			: (b) Read the length of the challenge script.
	//			: (c) Read the challenge script
	//Step #9 Read the LockTime; a value currently always hard-coded to zero
	bool processBlockData(const void *blockData,uint32_t blockLength,uint32_t &transactionIndex)
	{
		bool ret = true;
		mBlockData = (const uint8_t *)blockData;
		mBlockRead = mBlockData;	// Set the block-read scan pointer.
		mBlockEnd = &mBlockData[blockLength]; // Mark the end of block pointer
		blockFormatVersion = readU32();	// Read the format version
		previousBlockHash = readHash();  // get the address of the hash
		merkleRoot = readHash();	// Get the address of the merkle root hash
		gBlockTime = timeStamp = readU32();	// Get the timestamp
		bits = readU32();	// Get the bits field
		nonce = readU32();	// Get the 'nonce' random number.
		transactionCount = readVariableLengthInteger();	// Read the number of transactions
		assert( transactionCount < MAX_BLOCK_TRANSACTION );
		if ( transactionCount >= MAX_BLOCK_TRANSACTION )
		{
			logMessage("Too many transactions in the block: %d\r\n", transactionCount );
			exit(1);
		}
		if ( transactionCount < MAX_BLOCK_TRANSACTION )
		{
			transactions = mTransactions;	// Assign the transactions buffer pointer
			for (uint32_t i=0; i<transactionCount; i++)
			{
				gTransactionIndex = i;
				BlockChain::BlockTransaction &b = transactions[i];
				if ( !readTransaction(b,transactionIndex,i) )	// Read the transaction; if it failed; then abort processing the block chain
				{
					ret = false;
					break;
				}
			}
		}

		return ret;
	}

	const BlockChain::BlockTransaction *processTransactionData(const void *transactionData,uint32_t transactionLength)
	{
		uint32_t transactionIndex=0;
		BlockChain::BlockTransaction *ret = &mTransactions[0];
		mBlockData = (const uint8_t *)transactionData;
		mBlockRead = mBlockData;	// Set the block-read scan pointer.
		mBlockEnd = &mBlockData[transactionLength]; // Mark the end of block pointer

		if ( !readTransaction(*ret,transactionIndex,0) )	// Read the transaction; if it failed; then abort processing the block chain
		{
			ret = NULL;
			logMessage("Failed to process transaction data!\r\n");
			exit(1);
		}
		return ret;
	}


	const uint8_t					*mBlockRead;				// The current read buffer address in the block
	const uint8_t					*mBlockEnd;					// The EOF marker for the block
	const uint8_t					*mBlockData;
	BlockChain::BlockTransaction	mTransactions[MAX_BLOCK_TRANSACTION];	// Holds the array of transactions
	BlockChain::BlockInput			mInputs[MAX_BLOCK_INPUTS];	// The input arrays
	BlockChain::BlockOutput			mOutputs[MAX_BLOCK_OUTPUTS]; // The output arrays

};

class Transaction;

class BitcoinAddressData
{
public:
	BitcoinAddressData(void)
	{
		memset(this,0,sizeof(BitcoinAddressData));
	}

	BitcoinAddressData *mNext;
	uint32_t		mBitcoinAddressFlags;
	uint32_t		mLastInputTime;
	uint32_t		mLastOutputTime;
	uint32_t		mFirstOutputTime;

	uint64_t		mTotalSent;
	uint64_t		mTotalReceived;

	uint32_t		mInputCount;
	uint32_t		mOutputCount;
	uint32_t		mTransactionIndex;
	uint32_t		mTransactionCount;
	Transaction		**mTransactions;	// The array of transactions associated with this bitcoin-address as either inputs or outputs or (sometimes) both.

	uint32_t		mMultiSig[5];
};

#define BITCOIN_ADDRESS_CHUNK_SIZE (1024*1024)

class BitcoinAddressDataChunk
{
public:
	BitcoinAddressDataChunk(void)
	{
		mCount = 0;
		mNext = NULL;
	}

	~BitcoinAddressDataChunk(void)
	{
	}

	BitcoinAddressData *getData(void)
	{
		BitcoinAddressData *ret = NULL;
		if ( mCount < BITCOIN_ADDRESS_CHUNK_SIZE )
		{
			ret = &mData[mCount];
			mCount++;
		}
		return ret;
	}

	BitcoinAddressDataChunk	*mNext;
	uint32_t				mCount;
	BitcoinAddressData		mData[BITCOIN_ADDRESS_CHUNK_SIZE];
};

class BitcoinAddressDataFactory
{
public:
	BitcoinAddressDataFactory(void)
	{
		mChunkHead = new BitcoinAddressDataChunk;
		mChunkCurrent = mChunkHead;
		mFreeList = NULL;
	}

	~BitcoinAddressDataFactory(void)
	{
		BitcoinAddressDataChunk *kill = mChunkHead;
		BitcoinAddressDataChunk *next = kill->mNext;
		while ( kill )
		{
			delete kill;
			kill = next;
			next = kill ? kill->mNext : NULL;
		}
	}

	BitcoinAddressData *getData(void)
	{
		BitcoinAddressData *ret = NULL;

		if ( mFreeList )
		{
			ret = mFreeList;
			mFreeList = ret->mNext;
		}
		else if ( mChunkCurrent )
		{
			ret = mChunkCurrent->getData();
			if ( ret == NULL )
			{
				BitcoinAddressDataChunk *newChunk = new BitcoinAddressDataChunk;
				mChunkCurrent->mNext = newChunk;
				mChunkCurrent = newChunk;
				ret = mChunkCurrent->getData();
			}
		}
		return ret;
	}

	void freeData(BitcoinAddressData *data)
	{
		data->mNext = mFreeList;
		mFreeList = data;
	}

	BitcoinAddressDataChunk	*mChunkHead;
	BitcoinAddressDataChunk *mChunkCurrent;
	BitcoinAddressData		*mFreeList;
};

BitcoinAddressDataFactory *gBitcoinAddressDataFactory=NULL;

// Contains a hash of just the 20 byte RIPEMD160 key; does not have the header or footer; which can be calculated.
class BitcoinAddress
{
public:
	enum Type
	{
		BAT_COINBASE_50			= (1<<0),
		BAT_COINBASE_25			= (1<<1),
		BAT_COINBASE_MULTIPLE	= (1<<2),
		BAT_HAS_SENDS			= (1<<3),
		BAT_BRAND_NEW			= (1<<4),
		BAT_MULTISIG			= (1<<5), // is a multi-sig address
		BAT_STEALTH				= (1<<6), // is a stealth address!
		BAT_SCRIPT_HASH			= (1<<7),
	};

	BitcoinAddress(void)
	{
		mWord0 = 0;
		mWord1 = 0;
		mWord2 = 0;
		mData = NULL; // todo...
	}

	BitcoinAddress(const uint8_t address[20])
	{
		mWord0 = *(const uint64_t *)(address);
		mWord1 = *(const uint64_t *)(address+8);
		mWord2 = *(const uint32_t *)(address+16);
		mData = NULL;
	}

	~BitcoinAddress(void)
	{
		if ( mData )
		{
			gBitcoinAddressDataFactory->freeData(mData);
		}
	}

	inline BitcoinAddressData& getData(void)
	{
		if ( mData == NULL )
		{
			mData = gBitcoinAddressDataFactory->getData();
			mData->mTransactionCount = 0;
			mData->mTransactionIndex = 0xFFFFFFFF;
			mData->mTransactions = NULL;
			mData->mTotalReceived = 0;
			mData->mTotalSent = 0;
			mData->mLastInputTime = 0;
			mData->mLastOutputTime = 0;
			mData->mFirstOutputTime = 0;
			mData->mInputCount = 0;
			mData->mOutputCount = 0;
			mData->mBitcoinAddressFlags = BAT_BRAND_NEW;
		}
		return *mData;
	}

	bool isBrandNew(void) const
	{
		return (mData->mBitcoinAddressFlags & BAT_BRAND_NEW) ? true : false;
	}

	void clearBrandNew(void)
	{
		mData->mBitcoinAddressFlags&=~BAT_BRAND_NEW;
	}

	bool operator==(const BitcoinAddress &a) const
	{
		return mWord0 == a.mWord0 && mWord1 == a.mWord1 && mWord2 == a.mWord2;
	}

	bool isCoinBase(void)
	{
		getData();
		return (mData->mBitcoinAddressFlags & (BAT_COINBASE_25 | BAT_COINBASE_50)) ? true : false;
	}

	bool hasSends(void)
	{
		getData();
		return (mData->mBitcoinAddressFlags & BAT_HAS_SENDS) ? true : false;
	}

	bool isMultiSig(void)
	{
		getData();
		return (mData->mBitcoinAddressFlags & BAT_MULTISIG) ? true : false;
	}

	bool isStealth(void)
	{
		getData();
		return (mData->mBitcoinAddressFlags & BAT_STEALTH) ? true : false;
	}

	bool isScriptHash(void)
	{
		getData();
		return (mData->mBitcoinAddressFlags & BAT_SCRIPT_HASH) ? true : false;
	}


	bool isMultipleCoinBase(void)
	{
		getData();
		return (mData->mBitcoinAddressFlags & BAT_COINBASE_MULTIPLE) ? true : false;
	}

	uint32_t getHash(void) const
	{
		const uint32_t *h = (const uint32_t *)&mWord0;
		return h[0] ^ h[1] ^ h[2] ^ h[3] ^ h[4];
	}

	uint32_t getLastUsedTime(void)
	{
		getData();
		uint32_t lastUsed = mData->mLastInputTime; // the last time we sent money (not received because anyone can send us money).
		if ( mData->mLastInputTime == 0 ) // if it has never had a spend.. then we use the time of first receive..
		{
			lastUsed = mData->mFirstOutputTime;
		}
		return lastUsed;
	}

	uint32_t getDaysSinceLastUsed(uint32_t refTime)
	{
		getData();
		time_t currentTime(refTime);
		if ( refTime == 0 )
		{
			time(&currentTime); // get the current time.
		}
		uint32_t lastUsed = mData->mLastInputTime; // the last time we sent money (not received because anyone can send us money).
		if ( mData->mLastInputTime == 0 ) // if it has never had a spend.. then we use the time of first receive..
		{
			lastUsed = mData->mFirstOutputTime;
		}
		uint32_t days = 0;
		if ( lastUsed != 0 )
		{
			double seconds = difftime(currentTime,time_t(lastUsed));
			double minutes = seconds/60;
			double hours = minutes/60;
			days = (uint32_t) (hours/24);
		}
		return days;
	}

	uint32_t getInputCount(void)
	{
		getData();
		return mData->mInputCount;
	}

	uint32_t getOutputCount(void)
	{
		getData();
		return mData->mOutputCount;
	}

	uint64_t getBalance(void)
	{
		getData();
		return mData->mTotalReceived - mData->mTotalSent;
	}

	uint64_t		mWord0; // 8
	uint64_t		mWord1; // 16
	uint32_t		mWord2; // 20
private:
	BitcoinAddressData	*mData;
};



#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4100)
#endif


class TransactionOutput
{
public:
	TransactionOutput(void)
	{
		mValue = 0;
		mAddress = 0;
	}
	uint64_t	mValue;		// value of the output.
	uint32_t	mAddress;	// address of the output.
};

class TransactionInput
{
public:
	TransactionInput(void)
	{
		mOutput = NULL;
		mSignatureFormat = BlockChain::SF_ABNORMAL;
	}
	uint32_t			mSignatureFormat;
	TransactionOutput	*mOutput;	// All inputs are the result of a previous output or block-reward mining fee (otherwise known as 'coinbase')
};

class Transaction
{
public:
	Transaction(void)
	{
		mInputCount = 0;
		mOutputCount = 0;
		mInputs = 0;
		mOutputCount = 0;
	}
	uint32_t			mBlock;
	uint32_t			mTime;
	uint32_t			mInputCount;
	uint32_t			mOutputCount;
	TransactionInput	*mInputs;
	TransactionOutput	*mOutputs;
};


typedef SimpleHash< BitcoinAddress, 4194304, MAX_BITCOIN_ADDRESSES > BitcoinAddressHashMap;

enum AgeMarker
{
	AM_ONE_DAY,
	AM_ONE_WEEK,
	AM_ONE_MONTH,
	AM_THREE_MONTHS,
	AM_SIX_MONTHS,
	AM_ONE_YEAR,
	AM_TWO_YEARS,
	AM_THREE_YEARS,
	AM_FOUR_YEARS,
	AM_FIVE_YEARS,
	AM_LAST
};

const char * getAgeString(AgeMarker m)
{
	const char *ret = "UNKNOWN";
	switch ( m )
	{
		case AM_ONE_DAY: ret = "One Day"; break;
		case AM_ONE_WEEK: ret = "One Week"; break;
		case AM_ONE_MONTH: ret = "One Month"; break;
		case AM_THREE_MONTHS: ret = "1-3 Months"; break;
		case AM_SIX_MONTHS: ret = "3-6 Months"; break;
		case AM_ONE_YEAR: ret = "Six Months to One Year"; break;
		case AM_TWO_YEARS: ret = "One to Two Years"; break;
		case AM_THREE_YEARS: ret = "Two to Three Years"; break;
		case AM_FOUR_YEARS: ret = "Three to Four Years"; break;
		case AM_FIVE_YEARS: ret = "Four to Six Years"; break;
		default:
            break;
	}
	return ret;
}

class AgeStat
{
public:
	AgeStat(void)
	{
		mTotalValue = 0;
		mCount = 0;
	}
	void addValue(uint64_t b)
	{
		mTotalValue+=b;
		if ( b >= ONE_BTC )
		{
			mCount++;
		}
	}
	uint64_t	mTotalValue;
	uint32_t	mCount;
};

enum StatSize
{
	SS_ZERO,			// addresses with a balance of exactly zero
	SS_ONE_MBTC,		// addresses with a balance of one MBTC or less but not zero
	SS_FIVE_MBTC,

	SS_TEN_MBTC,		// addresses with a balance of ten MBTC
	SS_FIFTY_MBTC,

	SS_HUNDRED_MBTC,		// addresses with 100 mbtc
	SS_FIVE_HUNDRED_MBTC,

	SS_ONE_BTC,		// addresses with one BTC
	SS_FIVE_BTC,		// address with between 2 and 5 btc

	SS_TEN_BTC,	// addresses with ten BTC
	SS_FIFTY_BTC,

	SS_HUNDRED_BTC,
	SS_FIVE_HUNDRED_BTC,

	SS_ONE_THOUSAND_BTC,
	SS_FIVE_THOUSAND_BTC,

	SS_TEN_THOUSAND_BTC,
	SS_FIFTY_THOUSAND_BTC,
	SS_HUNDRED_THOUSAND_BTC,
	SS_MAX_BTC,

	SS_ONE_DAY,
	SS_ONE_WEEK,
	SS_ONE_MONTH,
	SS_THREE_MONTHS,
	SS_SIX_MONTHS,
	SS_ONE_YEAR,
	SS_TWO_YEARS,
	SS_THREE_YEARS,
	SS_FOUR_YEARS,
	SS_FIVE_YEARS,

	SS_COUNT,
};

#define MAX_DAYS 4000
#define DAYS_PER 7
#define MAX_DAY_INDEX (MAX_DAYS/DAYS_PER)

class StatValue
{
public:
	StatValue(void)
	{
		mCount  = 0;
		mValue = 0;
	}
	uint32_t	mCount;
	uint64_t	mValue;
};

class StatAddress
{
public:
	StatAddress(void)
	{
		mAddress = 0;
		mTotalReceived = 0;
		mTotalSent = 0;
		mLastTime = 0;
		mTransactionCount = 0;
		mInputCount = 0;
		mOutputCount = 0;
	}

	bool operator==(const StatAddress &a) const
	{
		return mAddress == a.mAddress &&
			   mTotalSent == a.mTotalSent &&
			   mTotalReceived == a.mTotalReceived &&
			   mFirstTime == a.mFirstTime &&
			   mLastTime == a.mLastTime &&
			   mTransactionCount == a.mTransactionCount &&
			   mInputCount == a.mInputCount &&
			   mOutputCount == a.mOutputCount;
	}

	uint32_t getBalance(void) const
	{
		return mTotalReceived - mTotalSent;
	}

	uint32_t	mAddress;			// the address index.
	uint32_t	mTotalSent;			// total number of bitcoins sent
	uint32_t	mTotalReceived;
	uint32_t	mFirstTime;			// first time this address was used
	uint32_t	mLastTime;			// Last time a spend transaction occurred.
	uint8_t		mTransactionCount;	// total number of transactions
	uint8_t		mInputCount;		// total number of inputs.
	uint8_t		mOutputCount;		// total number of outputs
};

class StatRow
{
public:
	StatRow(void)
	{
		mTime = 0;
		mCount = 0;
		mValue = 0;
		mZombieTotal = 0;
		mZombieCount = 0;
		mAddressCount = 0;
		mAddresses = NULL;
		mNewAddressCount = 0;
		mDeleteAddressCount = 0;
		mChangeAddressCount = 0;
		mSameAddressCount = 0;
		mRiseFromDeadCount = 0;
		mRiseFromDeadAmount = 0;
		mNewAddresses = NULL;
		mChangedAddresses = NULL;
		mDeletedAddresses = NULL;
	}

	~StatRow(void)
	{
		delete []mAddresses;
		delete []mNewAddresses;
		delete []mChangedAddresses;
		delete []mDeletedAddresses;
	}
	uint64_t	mZombieTotal;		// Total number of zombie counts
	uint32_t	mZombieCount;		// Total number of zomie addresses
	uint32_t	mTime;
	uint32_t	mCount;
	uint64_t	mValue;
	StatValue	mStats[SS_COUNT];

	uint32_t	mAddressCount;		// number of addreses recorded
	StatAddress	*mAddresses;

	uint32_t	mNewAddressCount;
	uint32_t	mDeleteAddressCount;
	uint32_t	mChangeAddressCount;
	uint32_t	mSameAddressCount;
	uint32_t	mRiseFromDeadCount;
	uint32_t	mRiseFromDeadAmount;

	StatAddress	*mNewAddresses;
	StatAddress	*mChangedAddresses;
	uint32_t	*mDeletedAddresses;
};

#define MAX_STAT_COUNT (365*10) // reserve room for up to 6 years of 365 days entries...


class SortByBalance : public HeapSortPointers
{
public:
	SortByBalance(BitcoinAddress **addresses,uint32_t count)
	{
		HeapSortPointers::heapSort((void **)addresses,(int32_t)count);
	}

	// -1 less, 0 equal, +1 greater.
	virtual int32_t compare(void *p1,void *p2)
	{
		BitcoinAddress *a1 = (BitcoinAddress *)p1;
		BitcoinAddress *a2 = (BitcoinAddress *)p2;
		uint64_t balance1 = a1->getData().mTotalReceived-a1->getData().mTotalSent;
		uint64_t balance2 = a2->getData().mTotalReceived-a2->getData().mTotalSent;
		if ( balance1 == balance2 ) return 0;
		return balance1 > balance2 ? -1 : 1;
	}
};

class SortByAge : public HeapSortPointers
{
public:
	SortByAge(BitcoinAddress **addresses,uint32_t count)
	{
		HeapSortPointers::heapSort((void **)addresses,(int32_t)count);
	}

	// -1 less, 0 equal, +1 greater.
	virtual int32_t compare(void *p1,void *p2)
	{
		BitcoinAddress *a1 = (BitcoinAddress *)p1;
		BitcoinAddress *a2 = (BitcoinAddress *)p2;
		uint32_t age1 = a1->getDaysSinceLastUsed(0);
		uint32_t age2 = a2->getDaysSinceLastUsed(0);
		if ( age1 == age2 ) return 0;
		return age1 > age2 ? -1 : 1;
	}

};

static void logSignatureFormat(uint32_t ret,FILE *fph)
{
	if ( ret & BlockChain::SF_ABNORMAL ) fprintf(fph,"SF_ABNORMAL ");
	if ( ret & BlockChain::SF_COINBASE ) fprintf(fph,"SF_COINBASE ");
	if ( ret & BlockChain::SF_DER_ONLY ) fprintf(fph,"SF_DER_ONLY ");
	if ( ret & BlockChain::SF_SIGHASH_ZERO ) fprintf(fph,"SF_SIGHASH_ZERO ");
	if ( ret & BlockChain::SF_SIGHASH_ALL ) fprintf(fph,"SF_SIGHASH_ALL ");
	if ( ret & BlockChain::SF_SIGHASH_NONE ) fprintf(fph,"SF_SIGHASH_NONE ");
	if ( ret & BlockChain::SF_WEIRD_90_00 ) fprintf(fph,"SF_WEIRD_90_00 ");
	if ( ret & BlockChain::SF_NORMAL_SIGNATURE_PUSH41 ) fprintf(fph,"SF_NORMAL_SIGNATURE_PUSH41 ");
	if ( ret & BlockChain::SF_NORMAL_SIGNATURE_PUSH21 ) fprintf(fph,"SF_NORMAL_SIGNATURE_PUSH21 ");
	if ( ret & BlockChain::SF_SIGNATURE_LEADING_ZERO ) fprintf(fph,"SF_SIGNATURE_LEADING_ZERO ");
	if ( ret & BlockChain::SF_SIGNATURE_LEADING_STRANGE ) fprintf(fph,"SF_SIGNATURE_LEADING_STRANGE ");
	if ( ret & BlockChain::SF_SIGNATURE_21 ) fprintf(fph,"SF_SIGNATURE_21 ");
	if ( ret & BlockChain::SF_SIGNATURE_41 ) fprintf(fph,"SF_SIGNATURE_41 ");
	if ( ret & BlockChain::SF_PUSHDATA1 ) fprintf(fph,"SF_PUSHDATA1 ");
	if ( ret & BlockChain::SF_PUSHDATA0 ) fprintf(fph,"SF_PUSHDATA0 ");
	if ( ret & BlockChain::SF_UNUSUAL_SIGNATURE_LENGTH ) fprintf(fph,"SF_UNUSUAL_SIGNATURE_LENGTH ");
	if ( ret & BlockChain::SF_EXTRA_STUFF ) fprintf(fph,"SF_EXTRA_STUFF ");
	if ( ret & BlockChain::SF_SIGHASH_PAY_ANY_ALL ) fprintf(fph,"SF_SIGHASH_PAY_ANY_ALL ");
	if ( ret & BlockChain::SF_SIGHASH_PAY_ANY_SINGLE ) fprintf(fph,"SF_SIGHASH_PAY_ANY_SINGLE ");
	if ( ret & BlockChain::SF_SIGHASH_SINGLE ) fprintf(fph,"SF_SIGHASH_SINGLE ");
	if ( ret & BlockChain::SF_SIGHASH_PAY_ANY_NONE ) fprintf(fph,"SF_SIGHASH_PAY_ANY_NONE ");
	if ( ret & BlockChain::SF_TRANSACTION_MALLEABILITY ) fprintf(fph,"**** SF_TRANSACTION_MALLEABILITY **** ");
	if ( ret & BlockChain::SF_PUSHDATA2 ) fprintf(fph,"SF_PUSHDATA2 ");
	if ( ret & BlockChain::SF_ASCII ) fprintf(fph,"SF_ASCII ");

	if ( ret & BlockChain::SF_DER_X_1E ) fprintf(fph,"SF_DER_X_1E ");
	if ( ret & BlockChain::SF_DER_X_1F ) fprintf(fph,"SF_DER_X_1F ");
	if ( ret & BlockChain::SF_DER_X_20 ) fprintf(fph,"SF_DER_X_20 ");
	if ( ret & BlockChain::SF_DER_X_21 ) fprintf(fph,"SF_DER_X_21 ");

	if ( ret & BlockChain::SF_DER_Y_1E ) fprintf(fph,"SF_DER_Y_1E ");
	if ( ret & BlockChain::SF_DER_Y_1F ) fprintf(fph,"SF_DER_Y_1F ");
	if ( ret & BlockChain::SF_DER_Y_20 ) fprintf(fph,"SF_DER_Y_20 ");
	if ( ret & BlockChain::SF_DER_Y_21 ) fprintf(fph,"SF_DER_Y_21 ");
}

class ZombieFinder
{
public:
	ZombieFinder(void)
	{
		mLastBalance = 0;
		mLastAge = 0;
		mLastDate = 0;
		mAddress = NULL;
	}
	uint64_t		mLastBalance;
	uint32_t		mLastDate;
	uint32_t		mLastAge;
	BitcoinAddress	*mAddress;
};


class BitcoinTransactionFactory
{
public:
	BitcoinTransactionFactory(void)
	{
		mTransactionReferences = NULL;
		mTransactions = NULL;
		mInputs = NULL;
		mOutputs = NULL;
		mBlocks = NULL;
		mTransactionCount = 0;
		mTotalInputCount = 0;
		mTotalOutputCount = 0;
		mBlockCount = 0;
		mStatCount = 0;

		mAddresses.setMemoryMapFileName("@BitcoinAddresses.mmap");

		mStatLimits[SS_ZERO] = 0;
		mStatLimits[SS_ONE_MBTC] = ONE_MBTC;
		mStatLimits[SS_FIVE_MBTC] = ONE_MBTC*5;

		mStatLimits[SS_TEN_MBTC] = ONE_MBTC*10;
		mStatLimits[SS_FIFTY_MBTC] = ONE_MBTC*50;

		mStatLimits[SS_HUNDRED_MBTC] = ONE_MBTC*100;
		mStatLimits[SS_FIVE_HUNDRED_MBTC] = ONE_MBTC*500;


		mStatLimits[SS_ONE_BTC] = ONE_BTC;
		mStatLimits[SS_FIVE_BTC] = ONE_BTC*5;

		mStatLimits[SS_TEN_BTC] = ONE_BTC*10;
		mStatLimits[SS_FIFTY_BTC] = (uint64_t)ONE_BTC*(uint64_t)50;

		mStatLimits[SS_HUNDRED_BTC] = (uint64_t)ONE_BTC*(uint64_t)100;
		mStatLimits[SS_FIVE_HUNDRED_BTC] = (uint64_t)ONE_BTC*(uint64_t)500;

		mStatLimits[SS_ONE_THOUSAND_BTC] = (uint64_t)ONE_BTC*(uint64_t)1000;
		mStatLimits[SS_FIVE_THOUSAND_BTC] = (uint64_t)ONE_BTC*(uint64_t)5000;

		mStatLimits[SS_TEN_THOUSAND_BTC] = (uint64_t)ONE_BTC*(uint64_t)10000;
		mStatLimits[SS_FIFTY_THOUSAND_BTC] = (uint64_t)ONE_BTC*(uint64_t)50000;
		mStatLimits[SS_HUNDRED_THOUSAND_BTC] = (uint64_t)ONE_BTC*(uint64_t)100000;
		mStatLimits[SS_MAX_BTC] = (uint64_t)ONE_BTC*(uint64_t)21000000;


		mStatLabel[SS_ZERO] = "ZERO";
		mStatLabel[SS_ONE_MBTC] = "<1MBTC";
		mStatLabel[SS_FIVE_MBTC] = "<5MBTC";
		mStatLabel[SS_TEN_MBTC] = "<10MBTC";
		mStatLabel[SS_FIFTY_MBTC] = "<50MBTC";
		mStatLabel[SS_HUNDRED_MBTC] = "<100MBTC";
		mStatLabel[SS_FIVE_HUNDRED_MBTC] = "<500MBTC";
		mStatLabel[SS_ONE_BTC] = "<1BTC";
		mStatLabel[SS_FIVE_BTC] = "<5BTC";
		mStatLabel[SS_TEN_BTC] = "<10BTC";
		mStatLabel[SS_FIFTY_BTC] = "<50BTC";
		mStatLabel[SS_HUNDRED_BTC] = "<100BTC";
		mStatLabel[SS_FIVE_HUNDRED_BTC] = "<500BTC";
		mStatLabel[SS_ONE_THOUSAND_BTC] = "<1KBTC";
		mStatLabel[SS_FIVE_THOUSAND_BTC] = "<5KBTC";
		mStatLabel[SS_TEN_THOUSAND_BTC] = "<10KBTC";
		mStatLabel[SS_FIFTY_THOUSAND_BTC] = "<50KBTC";
		mStatLabel[SS_HUNDRED_THOUSAND_BTC] = "<100KBTC";
		mStatLabel[SS_MAX_BTC] = ">100KBTC";
		mStatLabel[SS_ONE_DAY] = "One Day";
		mStatLabel[SS_ONE_WEEK] = "One Week";
		mStatLabel[SS_ONE_MONTH] = "One Month";
		mStatLabel[SS_THREE_MONTHS] = "Three Months";
		mStatLabel[SS_SIX_MONTHS] = "Six Months";
		mStatLabel[SS_ONE_YEAR] = "One Year";
		mStatLabel[SS_TWO_YEARS] = "Two Years";
		mStatLabel[SS_THREE_YEARS] = "Three Years";
		mStatLabel[SS_FOUR_YEARS] = "Four Years";
		mStatLabel[SS_FIVE_YEARS] = "Five Years";

		mZombieFinder = new ZombieFinder[MAX_BITCOIN_ADDRESSES];
		mZombieOutput = NULL;
		mKeyReport = NULL;
		mLastBitcoinTotal = 0;
	}

	virtual ~BitcoinTransactionFactory(void)
	{
		if ( mZombieOutput )
		{
			fclose(mZombieOutput);
		}
		if ( mKeyReport )
		{
			fclose(mKeyReport);
		}
		delete []mBlocks;
		free(mTransactions);
		free(mInputs);
		free(mOutputs);
		delete []mTransactionReferences;
		delete []mZombieFinder;
	}

	void init(void)
	{
		if ( mTransactions == NULL )
		{
			logMessage("Allocating %d MB of memory for transactions.\r\n", (sizeof(Transaction)*MAX_TOTAL_TRANSACTIONS) / (1024*1024) );
			mTransactions = (Transaction *)malloc(sizeof(Transaction)*MAX_TOTAL_TRANSACTIONS);
			if ( mTransactions == NULL )
			{
				printf("Failed to allocate memory for transactions.\r\n");
				exit(1);
			}
			for (uint32_t i=0; i<MAX_TOTAL_TRANSACTIONS; i++)
			{
				new ( &mTransactions[i] ) Transaction;
			}
			logMessage("Allocating %d MB of memory for inputs.\r\n", (sizeof(TransactionInput)*MAX_TOTAL_INPUTS) / (1024*1024) );
			mInputs = (TransactionInput *)malloc(sizeof(TransactionInput)*MAX_TOTAL_INPUTS);
			if ( mInputs == NULL )
			{
				printf("Failed to allocate memory for inputs\r\n");
				exit(1);
			}
			for (uint32_t i=0; i<MAX_TOTAL_INPUTS; i++)
			{
				new ( &mInputs[i] ) TransactionInput;
			}
			logMessage("Allocating %d MB of memory for outputs.\r\n", (sizeof(TransactionOutput)*MAX_TOTAL_OUTPUTS) / (1024*1024) );
			mOutputs = (TransactionOutput *)malloc(sizeof(TransactionOutput)*MAX_TOTAL_OUTPUTS);
			if ( mOutputs == NULL )
			{
				printf("Failed to allocate memory for outputs\r\n");
				exit(1);
			}
			for (uint32_t i=0; i<MAX_TOTAL_OUTPUTS; i++)
			{
				new ( &mOutputs[i] ) TransactionOutput;
			}
			mBlocks = new Transaction *[MAX_TOTAL_BLOCKS];
		}
	}

	void markBlock(Transaction *t)
	{
		assert( mBlockCount < MAX_TOTAL_BLOCKS );
		if ( mBlockCount < MAX_TOTAL_BLOCKS )
		{
			mBlocks[mBlockCount] = t;
			mBlockCount++;
		}
	}

	Transaction * getBlock(uint32_t index,uint32_t &tcount) const
	{
		Transaction *ret = NULL;
		assert( index < mBlockCount );
		if ( index < mBlockCount )
		{
			ret = mBlocks[index];
			if ( (index+1) == mBlockCount )
			{
				tcount = (uint32_t)(&mTransactions[mTransactionCount] - ret);
			}
			else
			{
				tcount = (uint32_t)(mBlocks[index+1] - ret);
			}
		}
		return ret;
	}

	BitcoinAddress * getMultiSigAddress(const uint8_t from[20],uint32_t &adr,uint32_t a1,uint32_t a2,uint32_t a3,uint32_t a4,uint32_t a5)
	{
		BitcoinAddress *ret = NULL;

		BitcoinAddress h(from);
		ret = mAddresses.find(h);
		if ( ret == NULL )
		{
			ret = mAddresses.insert(h);
		}
		if ( ret )
		{
			adr = mAddresses.getIndex(ret) + 1;
			ret->getData().mBitcoinAddressFlags|=BitcoinAddress::BAT_MULTISIG;
			ret->getData().mMultiSig[0] = a1;
			ret->getData().mMultiSig[1] = a2;
			ret->getData().mMultiSig[2] = a3;
			ret->getData().mMultiSig[3] = a4;
			ret->getData().mMultiSig[4] = a5;
		}
		return ret;
	}


	BitcoinAddress * getAddress(const uint8_t from[20],uint32_t &adr)
	{
		BitcoinAddress *ret = NULL;

		BitcoinAddress h(from);
		ret = mAddresses.find(h);

		if ( ret == NULL )
		{
			ret = mAddresses.insert(h);
		}
		if ( ret )
		{
			adr = mAddresses.getIndex(ret) + 1;
		}
		return ret;
	}

	uint32_t getAddressCount(void) const
	{
		return (uint32_t)mAddresses.size();
	}

	Transaction * getSingleTransaction(uint32_t index)
	{
		Transaction *ret = NULL;
		assert( index < MAX_TOTAL_TRANSACTIONS );
		assert( index < mTransactionCount );
		if ( index < mTransactionCount )
		{
			ret = &mTransactions[index];
		}
		return ret;
	}


	Transaction *getTransactions(uint32_t count)
	{
		init();
		Transaction *ret = NULL;
		assert( (mTransactionCount+count) < MAX_TOTAL_TRANSACTIONS );
		if ( (mTransactionCount+count) < MAX_TOTAL_TRANSACTIONS )
		{
			ret = &mTransactions[mTransactionCount];
			mTransactionCount+=count;
		}
		else
		{
			logMessage("Overflowed maximum transactions allowed.\r\n");
			exit(1);
		}
		return ret;
	}

	TransactionInput * getInputs(uint32_t count)
	{
		TransactionInput *ret = NULL;
		assert( (mTotalInputCount+count) < MAX_TOTAL_INPUTS );
		if ( (mTotalInputCount+count) < MAX_TOTAL_INPUTS )
		{
			ret = &mInputs[mTotalInputCount];
			mTotalInputCount+=count;
		}
		else
		{
			logMessage("Exceeded maximum total inputs.\r\n");
			exit(1);
		}
		return ret;
	}

	TransactionOutput *getOutputs(uint32_t count)
	{
		TransactionOutput *ret = NULL;
		assert( (mTotalOutputCount+count) < MAX_TOTAL_OUTPUTS );
		if ( (mTotalOutputCount+count) < MAX_TOTAL_OUTPUTS )
		{
			ret = &mOutputs[mTotalOutputCount];
			mTotalOutputCount+=count;
		}
		else
		{
			logMessage("Exceeded maximum total outputs.\r\n");
			exit(1);
		}
		return ret;
	}

	TransactionOutput * getOutput(uint32_t index)
	{
		TransactionOutput *ret = NULL;
		assert( index < mTotalOutputCount );
		if ( index < mTotalOutputCount )
		{
			ret = &mOutputs[index];
		}
		else
		{
			logMessage("Invalid ouput index\r\n");
			exit(1);
		}
		return ret;
	}

	const char *quickKey(uint32_t a) const
	{
		static char scratch[1024];
		const char *ret = "UNKNOWN ADDRESS";
		if ( a )
		{
			BitcoinAddress *ba = mAddresses.getKey(a-1);
			uint8_t address1[25];
			bitcoinRIPEMD160ToAddress((const uint8_t *)ba,address1);
			bitcoinAddressToAscii(address1,scratch,256);
			ret = scratch;
		}
		return ret;
	}

	const char *getKey(uint32_t a) const
	{
		static char scratch[1024];
		scratch[0] = 0;
		const char *ret = "UNKNOWN ADDRESS";
		if ( a )
		{
			BitcoinAddress *ba = mAddresses.getKey(a-1);
			BitcoinAddressData &data = ba->getData();

			if ( data.mBitcoinAddressFlags & BitcoinAddress::BAT_MULTISIG )
			{
				uint32_t sigCount = 0;
				for (uint32_t i=0; i<MAX_MULTISIG; i++)
				{
					if ( data.mMultiSig[i] )
					{
						sigCount++;
					}
					else
					{
						break;
					}
				}
				sprintf(scratch,"MultiSig[%d]", sigCount );
				for (uint32_t i=0; i<MAX_MULTISIG; i++)
				{
					if ( data.mMultiSig[i] )
					{
						if ( i )
						{
							strcat(scratch,":");
						}
						strcat(scratch,quickKey(data.mMultiSig[i]));
					}
					else
					{
						break;
					}
				}
			}
			else if ( data.mBitcoinAddressFlags & BitcoinAddress::BAT_STEALTH )
			{
				strcpy(scratch,"*STEALTH*");
				uint8_t address1[25];
				char temp[256];
				bitcoinRIPEMD160ToAddress((const uint8_t *)ba,address1);
				bitcoinAddressToAscii(address1,temp,256);
				strcat(scratch,temp);
			}
			else if ( data.mBitcoinAddressFlags & BitcoinAddress::BAT_SCRIPT_HASH )
			{
				uint8_t address1[25];
				bitcoinRIPEMD160ToScriptAddress((const uint8_t *)ba,address1);
				bitcoinAddressToAscii(address1,scratch,256);
			}
			else
			{
				uint8_t address1[25];
				bitcoinRIPEMD160ToAddress((const uint8_t *)ba,address1);
				bitcoinAddressToAscii(address1,scratch,256);
			}
			ret = scratch;
		}
		return ret;
	}

	void dumpByAge(float minBalance)
	{
		FILE *fph = fopen("DumpByAge.csv", "wb");

		if ( fph == NULL )
		{
			logMessage("Failed to open file 'DumpByAge.csv' for write access.\r\n");
			return;
		}
		tipJar(fph);
		uint32_t plotCount = mAddresses.size();
		BitcoinAddress **sortPointers = new BitcoinAddress*[plotCount];
		plotCount = 0;


		uint64_t mbtc = (uint64_t)(minBalance*ONE_BTC);
		logMessage("Scanning %s public key addresses looking for ones with a balance greater than or equal to %0.4f.\r\n", formatNumber(mAddresses.size()), minBalance );

		for (uint32_t i=0; i<mAddresses.size(); i++) // print one in every 10,000 addresses (just for testing right now)
		{
			BitcoinAddress *ba = mAddresses.getKey(i);
			uint64_t balance = ba->getBalance();
			if ( balance >= mbtc )
			{
				sortPointers[plotCount] = ba;
				plotCount++;
			}
		}

		logMessage("Sorting %s public key addresses by age.\r\n", formatNumber(plotCount) );

		SortByAge sb(sortPointers,plotCount);

		time_t currentTime;
		time(&currentTime); // get the current time.

		logMessage("Saving %s public key addresses sorted by age with a balance greater than or equal to %0.4f\r\n", formatNumber(plotCount), minBalance);
		fprintf(fph,"Saving %s public key addresses sorted by age with a balance greater than or equal to %0.4f\r\n", formatNumber(plotCount), minBalance);


		fprintf(fph,"Address,Balance,DaysLastSent\r\n");
		for (uint32_t i=0; i<plotCount; i++)
		{
			BitcoinAddress *ba = sortPointers[i];
			uint64_t balance = ba->getData().mTotalReceived-ba->getData().mTotalSent;
			uint32_t lastUsed = ba->getData().mLastInputTime; // the last time we sent money (not received because anyone can send us money).
			if ( ba->getData().mLastInputTime == 0 ) // if it has never had a spend.. then we use the time of first receive..
			{
				lastUsed = ba->getData().mFirstOutputTime;
			}
			double seconds = difftime(currentTime,time_t(lastUsed));
			double minutes = seconds/60;
			double hours = minutes/60;
			uint32_t days = (uint32_t) (hours/24);
			uint32_t adr = mAddresses.getIndex(ba)+1;
			fprintf(fph,"%s,%0.4f,%4d\r\n", getKey(adr), (float) balance / ONE_BTC, days );
		}
		delete []sortPointers;
		fclose(fph);
	}


	void dumpByBalance(float minBalance)
	{
		FILE *fph = fopen("DumpByBalance.csv", "wb");

		if ( fph == NULL )
		{
			logMessage("Failed to open file 'DumpByBalance.csv' for write access.\r\n");
			return;
		}
		tipJar(fph);


		uint64_t mbtc = (uint64_t)(minBalance*ONE_BTC);
		logMessage("Scanning %s public key addresses looking for ones with a balance greater than or equal to %0.4f.\r\n", formatNumber(mAddresses.size()), minBalance );

		uint32_t plotCount = mAddresses.size();
		BitcoinAddress **sortPointers = new BitcoinAddress*[plotCount];
		plotCount = 0;
		for (uint32_t i=0; i<mAddresses.size(); i++) // print one in every 10,000 addresses (just for testing right now)
		{
			BitcoinAddress *ba = mAddresses.getKey(i);
			uint64_t balance = ba->getBalance();
			if ( balance >= mbtc )
			{
				sortPointers[plotCount] = ba;
				plotCount++;
			}
		}

		logMessage("Sorting %s public key addresses by balance.\r\n", formatNumber(plotCount) );

		SortByBalance sb(sortPointers,plotCount);

		time_t currentTime;
		time(&currentTime); // get the current time.

		logMessage("Saving %s public key addresses with a balance greater than or equal to %0.4f and sorted by balance\r\n", formatNumber(plotCount), minBalance);
		fprintf(fph,"Saving %s public key addresses with a balance greater than or equal to %0.4f and sorted by balance\r\n", formatNumber(plotCount), minBalance);

		fprintf(fph,"Address,Balance,DaysLastSent\r\n");
		for (uint32_t i=0; i<plotCount; i++)
		{
			BitcoinAddress *ba = sortPointers[i];
			uint64_t balance = ba->getData().mTotalReceived-ba->getData().mTotalSent;
			uint32_t lastUsed = ba->getData().mLastInputTime; // the last time we sent money (not received because anyone can send us money).
			if ( ba->getData().mLastInputTime == 0 ) // if it has never had a spend.. then we use the time of first receive..
			{
				lastUsed = ba->getData().mFirstOutputTime;
			}
			double seconds = difftime(currentTime,time_t(lastUsed));
			double minutes = seconds/60;
			double hours = minutes/60;
			uint32_t days = (uint32_t) (hours/24);
			uint32_t adr = mAddresses.getIndex(ba)+1;
			fprintf(fph,"%s,%0.4f,%4d\r\n", getKey(adr), (float) balance / ONE_BTC, days );
		}
		delete []sortPointers;
		fclose(fph);
	}

	void printTransaction(uint32_t index,Transaction *t,uint32_t address)
	{

		uint64_t totalInput=0;
		uint64_t totalOutput=0;
		uint64_t coinBase=0;

		for (uint32_t i=0; i<t->mOutputCount; i++)
		{
			TransactionOutput &o = t->mOutputs[i];
			totalOutput+=o.mValue;
		}
		for (uint32_t i=0; i<t->mInputCount; i++)
		{
			TransactionInput &input = t->mInputs[i];
			if ( input.mOutput )
			{
				TransactionOutput &o = *input.mOutput;
				totalInput+=o.mValue;
			}
		}

		logMessage("    Transaction #%s From Block: %s has %s inputs and %s outputs time: %s.\r\n", formatNumber(index), formatNumber(t->mBlock), formatNumber(t->mInputCount), formatNumber(t->mOutputCount), getTimeString(t->mTime) );

		logMessage("    Total Input: %0.9f Total Output: %0.9f : Fees: %0.9f\r\n",
			(float)totalInput / ONE_BTC,
			(float) totalOutput / ONE_BTC,
			(float)((totalOutput-totalInput)-coinBase) / ONE_BTC );

		for (uint32_t i=0; i<t->mInputCount; i++)
		{
			TransactionInput &input = t->mInputs[i];
			if ( input.mOutput )
			{
				TransactionOutput &o = *input.mOutput;
				if ( o.mAddress == address )
				{
					logMessage("        [Input] ");
				}
				else
				{
					logMessage("         Input  ");
				}
				logMessage("%d : %s[%d] : Value %0.9f\r\n", i, getKey(o.mAddress),o.mAddress, (float)o.mValue / ONE_BTC );
			}
			else
			{
				logMessage("        [Input] %d : COINBASE\r\n", i );
			}
		}

		for (uint32_t i=0; i<t->mOutputCount; i++)
		{
			TransactionOutput &o = t->mOutputs[i];
			if ( o.mAddress == address )
			{
				logMessage("        [Output] ");
			}
			else
			{
				logMessage("         Output  ");
			}
			logMessage("%d : %s[%d] : Value %0.9f\r\n", i, getKey(o.mAddress),o.mAddress, (float)o.mValue / ONE_BTC );
		}
	}

	void printTransactions(uint32_t blockIndex)
	{
		uint32_t tcount;
		Transaction *t = getBlock(blockIndex,tcount);
		if ( t )
		{
			logMessage("===================================================\r\n");
			logMessage("Block #%s has %s transactions.\r\n", formatNumber(blockIndex), formatNumber(tcount) );
			for (uint32_t j=0; j<tcount; j++)
			{
				printTransaction(j,t,0);
				t++;
			}
			logMessage("===================================================\r\n");
			logMessage("\r\n");
		}
	}

	void reportCounts(void)
	{

		if ( mTransactionCount )
		{
			logMessage("%s transactions.\r\n", formatNumber(mTransactionCount) );
			logMessage("%s inputs.\r\n", formatNumber(mTotalInputCount) );
			logMessage("%s outputs.\r\n", formatNumber(mTotalOutputCount) );
			logMessage("%s addresses.\r\n", formatNumber(mAddresses.size()) );

			enum StatType
			{
				ST_ZERO,
				ST_DUST,
				ST_LESSONE,
				ST_LESSTEN,
				ST_LESS_HUNDRED,
				ST_LESS_THOUSAND,
				ST_LESS_TEN_THOUSAND,
				ST_LESS_HUNDRED_THOUSAND,
				ST_GREATER_HUNDRED_THOUSAND,
				ST_LAST
			};
			uint32_t counts[ST_LAST];
			uint64_t balances[ST_LAST];
			for (uint32_t i=0; i<ST_LAST; i++)
			{
				counts[i] = 0;
				balances[i] = 0;
			}

			for (uint32_t i=0; i<mAddresses.size(); i++)
			{
				BitcoinAddress *ba = mAddresses.getKey(i);
				uint64_t balance = ba->getData().mTotalReceived-ba->getData().mTotalSent;
				uint32_t btc = (uint32_t)(balance/ONE_BTC);
				if ( balance == 0 )
				{
					counts[ST_ZERO]++;
				}
				else if ( balance < ONE_MBTC )
				{
					counts[ST_DUST]++;
					balances[ST_DUST]+=balance;
				}
				else if ( balance < ONE_BTC )
				{
					counts[ST_LESSONE]++;
					balances[ST_LESSONE]+=balance;
				}
				else if ( btc < 10 )
				{
					counts[ST_LESSTEN]++;
					balances[ST_LESSTEN]+=btc;
				}
				else if ( btc < 100 )
				{
					counts[ST_LESS_HUNDRED]++;
					balances[ST_LESS_HUNDRED]+=btc;
				}
				else if ( btc < 1000 )
				{
					counts[ST_LESS_THOUSAND]++;
					balances[ST_LESS_THOUSAND]+=btc;
				}
				else if ( btc < 10000 )
				{
					counts[ST_LESS_TEN_THOUSAND]++;
					balances[ST_LESS_TEN_THOUSAND]+=btc;
				}
				else if ( btc < 100000 )
				{
					counts[ST_LESS_HUNDRED_THOUSAND]++;
					balances[ST_LESS_HUNDRED_THOUSAND]+=btc;
				}
				else
				{
					counts[ST_GREATER_HUNDRED_THOUSAND]++;
					balances[ST_GREATER_HUNDRED_THOUSAND]+=btc;
				}
			}
			logMessage("Found %s addresses which have ever been used.\r\n", formatNumber(mAddresses.size()) );

			logMessage("Found %s addresses with a zero balance.\r\n", formatNumber( counts[ST_ZERO]) );

			logMessage("Found %s 'dust' addresses (less than 1mbtc) with a total balance of %0.5f BTC\r\n",
				formatNumber( counts[ST_DUST] ),
				(float)balances[ST_DUST] / ONE_BTC );

			logMessage("Found %s addresses with a balance greater than 1mbtc but less than 1btc, total balance %0.5f\r\n",
				formatNumber(counts[ST_LESSONE]),
				(float)balances[ST_LESSONE]/ONE_BTC );

			logMessage("Found %s addresses with a balance greater than 1btc but less than 10btc, total btc: %s\r\n",
				formatNumber(counts[ST_LESSTEN]),
				formatNumber((uint32_t)balances[ST_LESSTEN]));

			logMessage("Found %s addresses with a balance greater than 10btc but less than 100btc, total: %s\r\n",
				formatNumber(counts[ST_LESS_HUNDRED]),
				formatNumber((uint32_t)balances[ST_LESS_HUNDRED]));

			logMessage("Found %s addresses with a balance greater than 100btc but less than 1,000btc, total: %s\r\n",
				formatNumber(counts[ST_LESS_THOUSAND]),
				formatNumber((uint32_t)balances[ST_LESS_THOUSAND]));

			logMessage("Found %s addresses with a balance greater than 1,000btc but less than 10,000btc, total: %s\r\n",
				formatNumber(counts[ST_LESS_TEN_THOUSAND]),
				formatNumber((uint32_t)balances[ST_LESS_TEN_THOUSAND]));

			logMessage("Found %s addresses with a balance greater than 10,000btc but less than 100,000btc, total: %s\r\n",
				formatNumber(counts[ST_LESS_HUNDRED_THOUSAND]),
				formatNumber((uint32_t)balances[ST_LESS_HUNDRED_THOUSAND]));

			logMessage("Found %s addresses with a balance greater than 100,000btc, total: %s\r\n",
				formatNumber(counts[ST_GREATER_HUNDRED_THOUSAND]),
				formatNumber((uint32_t)balances[ST_GREATER_HUNDRED_THOUSAND]));


		}

		{
			logMessage("Found %d unique input signature formats.\r\n", gSignatureStatCount );
			for (uint32_t i=0; i<gSignatureStatCount; i++)
			{
				SignatureStat &s = gSignatureStats[i];

				logMessage("===================================================================\r\n");
				logMessage("Signature Format %d was encountered %s times and has the following states\r\n", i+1, formatNumber(s.mCount) );
				logMessage("Signatures inputs of this format referred to outputs totaling this much value. %0.9f\r\n", (float) s.mValue / ONE_BTC );

				if ( s.mFlags & BlockChain::SF_ABNORMAL ) logMessage("SF_ABNORMAL\r\n");
				if ( s.mFlags & BlockChain::SF_COINBASE ) logMessage("SF_COINBASE\r\n");
				if ( s.mFlags & BlockChain::SF_DER_ONLY ) logMessage("SF_DER_ONLY\r\n");
				if ( s.mFlags & BlockChain::SF_SIGHASH_ZERO ) logMessage("SF_SIGHASH_ZERO\r\n");
				if ( s.mFlags & BlockChain::SF_SIGHASH_ALL ) logMessage("SF_SIGHASH_ALL\r\n");
				if ( s.mFlags & BlockChain::SF_SIGHASH_NONE ) logMessage("SF_SIGHASH_NONE\r\n");
				if ( s.mFlags & BlockChain::SF_WEIRD_90_00 ) logMessage("SF_WEIRD_90_00\r\n");
				if ( s.mFlags & BlockChain::SF_NORMAL_SIGNATURE_PUSH41 ) logMessage("SF_NORMAL_SIGNATURE_PUSH41\r\n");
				if ( s.mFlags & BlockChain::SF_NORMAL_SIGNATURE_PUSH21 ) logMessage("SF_NORMAL_SIGNATURE_PUSH21\r\n");
				if ( s.mFlags & BlockChain::SF_SIGNATURE_LEADING_ZERO ) logMessage("SF_SIGNATURE_LEADING_ZERO\r\n");
				if ( s.mFlags & BlockChain::SF_SIGNATURE_LEADING_STRANGE ) logMessage("SF_SIGNATURE_LEADING_STRANGE\r\n");
				if ( s.mFlags & BlockChain::SF_SIGNATURE_21 ) logMessage("SF_SIGNATURE_21\r\n");
				if ( s.mFlags & BlockChain::SF_SIGNATURE_41 ) logMessage("SF_SIGNATURE_41\r\n");
				if ( s.mFlags & BlockChain::SF_PUSHDATA1 ) logMessage("SF_PUSHDATA1\r\n");
				if ( s.mFlags & BlockChain::SF_PUSHDATA0 ) logMessage("SF_PUSHDATA0\r\n");
				if ( s.mFlags & BlockChain::SF_UNUSUAL_SIGNATURE_LENGTH ) logMessage("SF_UNUSUAL_SIGNATURE_LENGTH\r\n");
				if ( s.mFlags & BlockChain::SF_EXTRA_STUFF ) logMessage("SF_EXTRA_STUFF\r\n");
				if ( s.mFlags & BlockChain::SF_SIGHASH_PAY_ANY_ALL ) logMessage("SF_SIGHASH_PAY_ANY_ALL\r\n");
				if ( s.mFlags & BlockChain::SF_SIGHASH_PAY_ANY_SINGLE ) logMessage("SF_SIGHASH_PAY_ANY_SINGLE\r\n");
				if ( s.mFlags & BlockChain::SF_SIGHASH_SINGLE ) logMessage("SF_SIGHASH_SINGLE\r\n");
				if ( s.mFlags & BlockChain::SF_SIGHASH_PAY_ANY_NONE ) logMessage("SF_SIGHASH_PAY_ANY_NONE\r\n");
				if ( s.mFlags & BlockChain::SF_TRANSACTION_MALLEABILITY ) logMessage("**** SF_TRANSACTION_MALLEABILITY ****\r\n");
				if ( s.mFlags & BlockChain::SF_PUSHDATA2 ) logMessage("SF_PUSHDATA2\r\n");
				if ( s.mFlags & BlockChain::SF_ASCII ) logMessage("SF_ASCII\r\n");

				if ( s.mFlags & BlockChain::SF_DER_X_1E ) logMessage("SF_DER_X_1E\r\n");
				if ( s.mFlags & BlockChain::SF_DER_X_1F ) logMessage("SF_DER_X_1F\r\n");
				if ( s.mFlags & BlockChain::SF_DER_X_20 ) logMessage("SF_DER_X_20\r\n");
				if ( s.mFlags & BlockChain::SF_DER_X_21 ) logMessage("SF_DER_X_21\r\n");

				if ( s.mFlags & BlockChain::SF_DER_Y_1E ) logMessage("SF_DER_Y_1E\r\n");
				if ( s.mFlags & BlockChain::SF_DER_Y_1F ) logMessage("SF_DER_Y_1F\r\n");
				if ( s.mFlags & BlockChain::SF_DER_Y_20 ) logMessage("SF_DER_Y_20\r\n");
				if ( s.mFlags & BlockChain::SF_DER_Y_21 ) logMessage("SF_DER_Y_21\r\n");

				logMessage("===================================================================\r\n");
				logMessage("\r\n");
			}
		}

	}


	void gatherTransaction(BitcoinAddress *ba,Transaction *t,uint32_t tindex)
	{
		if ( ba && ba->getData().mTransactionIndex != tindex )
		{
			ba->getData().mTransactionIndex = tindex;
			ba->getData().mTransactions[ba->getData().mTransactionCount] = t;
			ba->getData().mTransactionCount++;
		}
	}

	void countTransaction(BitcoinAddress *ba,
						  uint32_t tindex,
						  uint32_t &transactionReferenceCount)
	{
		if ( ba && ba->getData().mTransactionIndex != tindex )
		{
			ba->getData().mTransactionIndex = tindex;
			ba->getData().mTransactionCount++;
			transactionReferenceCount++;
		}
	}

	BitcoinAddress *getAddress(uint32_t a)
	{
		BitcoinAddress *ret = NULL;
		if ( a )
		{
			ret = mAddresses.getKey(a-1);
		}
		return ret;
	}


	void gatherAddresses(uint32_t refTime)
	{
		delete []mTransactionReferences;
		mTransactionReferences = NULL;

//		printf("Gathering bitcoin addresses relative to this date: %s\r\n", getTimeString(refTime));

		// We are going to rebuild all of the transactions associated with every single bitcoin address
		// We zero out the current state and we mark in the 'zombie finder' the state of the address 'before'

		for (uint32_t i=0; i<mAddresses.size(); i++)
		{
			BitcoinAddress *ba = mAddresses.getKey(i);

			ZombieFinder &z = mZombieFinder[i];
			if ( z.mAddress == NULL )
			{
				z.mAddress = ba;
			}

			z.mLastDate = ba->getLastUsedTime();
			z.mLastAge = ba->getDaysSinceLastUsed(refTime);	// assign the days since last used before we rebuild all of the transactions
			z.mLastBalance = ba->getBalance();				// assign the balance before we rebuild all of the transaction

			ba->getData().mTransactionCount = 0;
			ba->getData().mTransactionIndex = 0xFFFFFFFF;
			ba->getData().mTransactions = NULL;
			ba->getData().mLastInputTime = 0;
			ba->getData().mLastOutputTime = 0;
			ba->getData().mFirstOutputTime = 0;
			ba->getData().mTotalReceived = 0;
			ba->getData().mTotalSent = 0;
			ba->getData().mInputCount = 0;
			ba->getData().mOutputCount = 0;
			ba->getData().mBitcoinAddressFlags&=~(BitcoinAddress::BAT_COINBASE_50 | BitcoinAddress::BAT_COINBASE_25 | BitcoinAddress::BAT_COINBASE_MULTIPLE | BitcoinAddress::BAT_HAS_SENDS);
		}

		uint32_t transactionReferenceCount=0;

		// ok..we.now it's time to add all transactions to all addresses...
		for (uint32_t i=0; i<mTransactionCount; i++)
		{
			Transaction &t = mTransactions[i];

			for (uint32_t j=0; j<t.mOutputCount; j++)
			{
				TransactionOutput &o = t.mOutputs[j];
				BitcoinAddress *ba = getAddress(o.mAddress);
				countTransaction(ba,i,transactionReferenceCount);
			}

			for (uint32_t j=0; j<t.mInputCount; j++)
			{
				TransactionInput &input = t.mInputs[j];
				if ( input.mOutput )
				{
					TransactionOutput &o = *input.mOutput;
					BitcoinAddress *ba = getAddress(o.mAddress);
					countTransaction(ba,i,transactionReferenceCount);
				}
			}

		}

		mTransactionReferences = new Transaction*[transactionReferenceCount];
		transactionReferenceCount=0;
		for (uint32_t i=0; i<mAddresses.size(); i++)
		{
			BitcoinAddress *ba = mAddresses.getKey(i);
			ba->getData().mTransactions = &mTransactionReferences[transactionReferenceCount];
			transactionReferenceCount+=ba->getData().mTransactionCount;
			ba->getData().mTransactionIndex = 0xFFFFFFFF; // which transaction we have stored yet so far...
			ba->getData().mTransactionCount = 0;
		}

		// ok..we.now it's time to add all transactions to all addresses...
		for (uint32_t i=0; i<mTransactionCount; i++)
		{
			Transaction &t = mTransactions[i];

			for (uint32_t j=0; j<t.mOutputCount; j++)
			{
				TransactionOutput &o = t.mOutputs[j];
				BitcoinAddress *ba = getAddress(o.mAddress);
				if ( ba )
				{

					bool isCoinBase = false;

					if ( t.mInputCount )
					{
						TransactionInput &input = t.mInputs[0];
						if ( input.mOutput == NULL )
						{
							isCoinBase = true;
						}
					}

					if ( isCoinBase )
					{
						uint64_t btc50 = (uint64_t)ONE_BTC*(uint64_t)50;
						uint64_t btc25 = (uint64_t)ONE_BTC*(uint64_t)25;
						if ( o.mValue >= btc50 )
						{
							if ( ba->getData().mBitcoinAddressFlags & (BitcoinAddress::BAT_COINBASE_50 | BitcoinAddress::BAT_COINBASE_25) )
							{
								ba->getData().mBitcoinAddressFlags|=BitcoinAddress::BAT_COINBASE_MULTIPLE;
							}
							ba->getData().mBitcoinAddressFlags|=BitcoinAddress::BAT_COINBASE_50;
						}
						else if ( o.mValue >= btc25 )
						{
							if ( ba->getData().mBitcoinAddressFlags & (BitcoinAddress::BAT_COINBASE_50 | BitcoinAddress::BAT_COINBASE_25) )
							{
								ba->getData().mBitcoinAddressFlags|=BitcoinAddress::BAT_COINBASE_MULTIPLE;
							}
							ba->getData().mBitcoinAddressFlags|=BitcoinAddress::BAT_COINBASE_25;
						}
					}

					gatherTransaction(ba,&t,i);

					ba->getData().mTotalReceived+=o.mValue;
					ba->getData().mOutputCount++;
					if ( t.mTime > ba->getData().mLastOutputTime ) // if the transaction time is more recnet than the last output time..
					{
						ba->getData().mLastOutputTime = t.mTime;
						if ( ba->getData().mFirstOutputTime == 0 ) // if this is the first output encountered, then mark it as the first output time.
						{
							ba->getData().mFirstOutputTime = t.mTime;
						}
					}

				}
			}


			for (uint32_t j=0; j<t.mInputCount; j++)
			{
				TransactionInput &input = t.mInputs[j];

				if ( input.mOutput )
				{
					TransactionOutput &o = *input.mOutput;
					BitcoinAddress *ba = getAddress(o.mAddress);
					if ( ba )
					{
						ba->getData().mBitcoinAddressFlags|=BitcoinAddress::BAT_HAS_SENDS;
						gatherTransaction(ba,&t,i);
						ba->getData().mTotalSent+=o.mValue;
						ba->getData().mInputCount++;
						if ( t.mTime > ba->getData().mLastInputTime ) // if the transaction time is newer than the last input/spent time..
						{
							ba->getData().mLastInputTime = t.mTime;
						}
					}
				}

			}
		}

		if ( mKeyReport == NULL )
		{
			mKeyReport = fopen("KeyReport.csv", "wb");
			if ( mKeyReport )
			{
				tipJar(mKeyReport);
				fprintf(mKeyReport,"An Explanation of the Column Headings\r\n");

				fprintf(mKeyReport,"Date : Date of data\r\n");
				fprintf(mKeyReport,"\r\n");
				fprintf(mKeyReport,"Daily Statistics about brand new public keys created on this day\r\n");
				fprintf(mKeyReport,"\r\n");
				fprintf(mKeyReport,"NewKeyDustCount : The number of new keys which were created on this date which, at the end of the day, only contained dust (defined as less than one millibt.\r\n");
				fprintf(mKeyReport,"NewKeyZeroCount : The number of new keys created on this date which, at the end of the day, had a zero balance.\r\n");
				fprintf(mKeyReport,"NewKeyValueCount : The number of new keys created on this date which, at the end of the day, still held more than one millibit of value.\r\n");

				fprintf(mKeyReport,"\r\n");
				fprintf(mKeyReport,"Daily Statistics about public keys which had existed previously\r\n");
				fprintf(mKeyReport,"\r\n");
				fprintf(mKeyReport,"OldKeyDustCount : The number of old keys modified which, at the end of the day, contained dust (less than one millibit)\r\n");
				fprintf(mKeyReport,"OldKeyZeroCount : The number of old keys (existed prior to this day) which contained more than dust which, at the end of the day, had been emptied.\r\n");
				fprintf(mKeyReport,"OldKeyValueCount : The number of old keys which were modified and still had more than one millibit of value at the end of the day\r\n");

				fprintf(mKeyReport,"\r\n");
				fprintf(mKeyReport,"Statistics about value change on this date\r\n");
				fprintf(mKeyReport,"\r\n");
				fprintf(mKeyReport,"NewKeyValue : How many bitcoins of value was moved to new keys on this date.\r\n");
				fprintf(mKeyReport,"OldKeyValueIncrease : The number of bitcoins of increased value for old bitcoin addresses\r\n");
				fprintf(mKeyReport,"OldKeyValueDecrease : The number of bitcoins of decreased value for old bitcoin addresses\r\n");

				fprintf(mKeyReport,"\r\n");
				fprintf(mKeyReport,"Statistics about the presence of multi-signature keys on this date\r\n");
				fprintf(mKeyReport,"\r\n");
				fprintf(mKeyReport,"MultiSigCount : The total number of multi-signature keys *ever* in the block chain, including zero balance keys\r\n");
				fprintf(mKeyReport,"MultiSigValueCount : The total number of multi-signature keys in the block chain, on this date, with a non-zero balance\r\n");
				fprintf(mKeyReport,"MultiSigValue : The amount of value currently stored in multisig keys on this date\r\n");

				fprintf(mKeyReport,"\r\n");
				fprintf(mKeyReport,"Statistics about the status of stealth keys in the blockchain on this date.\r\n");
				fprintf(mKeyReport,"\r\n");
				fprintf(mKeyReport,"StealthCount : The total number of stealth keys *ever* in the block chain, including zero balance keys\r\n");
				fprintf(mKeyReport,"StealthValueCount : The total number of stealth keys in the block chain, on this date, with a non-zero balance\r\n");
				fprintf(mKeyReport,"StealthValue : The amount of value currently stored in stealth keys on this date\r\n");

				fprintf(mKeyReport,"\r\n");
				fprintf(mKeyReport,"Statistics about the status of pay-to-script hash keys in the blockchain on this date.\r\n");
				fprintf(mKeyReport,"\r\n");
				fprintf(mKeyReport,"ScriptHashCount : The total number of pay-to-script (P2S) hash keys *ever* in the block chain, including zero balance keys\r\n");
				fprintf(mKeyReport,"ScriptHashValueCount : The total number of P2S keys in the block chain, on this date, with a non-zero balance\r\n");
				fprintf(mKeyReport,"ScriptHashValue : The amount of value currently stored in P2S keys on this date\r\n");

				fprintf(mKeyReport,"\r\n");
				fprintf(mKeyReport,"BitcoinTotal : The total number of bitcoins in the blockchain on this date.\r\n");
				fprintf(mKeyReport,"\r\n");
				fprintf(mKeyReport,"\r\n");


				fprintf(mKeyReport,"Date,NewKeyDustCount,NewKeyZeroCount,NewKeyValueCount,OldKeyDustCount,OldKeyZeroCount,OldKeyValueCount,NewKeyValue,OldKeyValueIncrease,OldKeyValueDecrease,MultiSigCount,MultiSigValueCount,MultiSigValue,StealthCount,StealthValueCount,StealthValue,ScriptHashCount,ScriptHashValueCount,ScriptHashValue,BitcoinTotal\r\n");
			}
		}

		if ( mKeyReport )
		{
			uint64_t bitcoinTotal = 0;

			uint32_t newKeyCount = 0;
			uint32_t newKeyZero = 0;
			uint32_t newDustCount = 0;
			uint32_t oldKeyDust=0;
			uint32_t oldKeyZero=0;
			uint32_t oldKeyValue=0;
			uint64_t newKeyValue = 0;

			uint64_t oldKeyValueIncrease = 0;
			uint64_t oldKeyValueDecrease = 0;

			uint32_t multiSigCount = 0;
			uint32_t multiSigValueCount = 0;
			uint64_t multiSigValue = 0;

			uint32_t stealthCount = 0;
			uint32_t stealthValueCount = 0;
			uint64_t stealthValue = 0;

			uint32_t scriptHashCount = 0;
			uint32_t scriptHashValueCount = 0;
			uint64_t scriptHashValue = 0;


			for (uint32_t i=0; i<mAddresses.size(); i++)
			{
				BitcoinAddress *ba = mAddresses.getKey(i);

				if ( ba->isMultiSig() )
				{
					multiSigCount++;
					if ( ba->getBalance() != 0 )
					{
						multiSigValueCount++;
						multiSigValue+=ba->getBalance();
					}
				}

				if ( ba->isStealth() )
				{
					stealthCount++;
					if ( ba->getBalance() != 0 )
					{
						stealthValueCount++;
						stealthValue+=ba->getBalance();
					}
				}

				if ( ba->isScriptHash() )
				{
					scriptHashCount++;
					if ( ba->getBalance() != 0 )
					{
						scriptHashValueCount++;
						scriptHashValue+=ba->getBalance();
					}
				}


				if ( ba->isBrandNew() )
				{
					newKeyValue+=ba->getBalance();
					newKeyCount++;
					ba->clearBrandNew();
					if ( ba->getBalance() == 0 )
					{
						newKeyZero++;
					}
					else if ( ba->getBalance() <= ONE_MBTC )
					{
						newDustCount++;
					}
				}
				else
				{
					ZombieFinder &z = mZombieFinder[i];
					if ( z.mAddress )
					{
						uint64_t balance = ba->getBalance();
						if ( balance >= z.mLastBalance )
						{
							oldKeyValueIncrease+=(balance-z.mLastBalance);
						}
						else
						{
							oldKeyValueDecrease+=(z.mLastBalance-balance);
						}
						if ( z.mLastAge > 1 && ba->getDaysSinceLastUsed(refTime) <= 1 ) // used within the past 24 hours..
						{
							if ( ba->getBalance() == 0 )
							{
								oldKeyZero++;
							}
							else if ( ba->getBalance() <= ONE_MBTC )
							{
								oldKeyDust++;
							}
							else
							{
								oldKeyValue++;
							}
						}
					}
				}
				bitcoinTotal+=ba->getBalance();
			}
			fprintf(mKeyReport,"%s,", getDateString(refTime));
			fprintf(mKeyReport,"%d,", newDustCount );
			fprintf(mKeyReport,"%d,", newKeyZero );
			fprintf(mKeyReport,"%d,", newKeyCount-(newDustCount+newKeyZero) );
			fprintf(mKeyReport,"%d,", oldKeyDust );
			fprintf(mKeyReport,"%d,", oldKeyZero );
			fprintf(mKeyReport,"%d,", oldKeyValue );
			fprintf(mKeyReport,"%0.2f,", (float) newKeyValue / ONE_BTC );
			fprintf(mKeyReport,"%0.2f,", (float) oldKeyValueIncrease / ONE_BTC );
			fprintf(mKeyReport,"%0.2f,", (float) oldKeyValueDecrease / ONE_BTC );

			fprintf(mKeyReport,"%d,", multiSigCount );
			fprintf(mKeyReport,"%d,", multiSigValueCount );
			fprintf(mKeyReport,"%0.2f,", (float) multiSigValue / ONE_BTC );

			fprintf(mKeyReport,"%d,", stealthCount );
			fprintf(mKeyReport,"%d,", stealthValueCount );
			fprintf(mKeyReport,"%0.2f,", (float) stealthValue / ONE_BTC );

			fprintf(mKeyReport,"%d,", scriptHashCount );
			fprintf(mKeyReport,"%d,", scriptHashValueCount );
			fprintf(mKeyReport,"%0.2f,", (float) scriptHashValue / ONE_BTC );



			fprintf(mKeyReport,"%0.2f,", (float)bitcoinTotal / ONE_BTC );

			if ( bitcoinTotal < mLastBitcoinTotal )
			{
				fprintf(mKeyReport,",BOGUS BITCOIN BALANCE WENT DOWN!!");
			}

			fprintf(mKeyReport,"\r\n");
			fflush(mKeyReport);

			mLastBitcoinTotal = bitcoinTotal;
		}

		if ( mZombieOutput == NULL )
		{
			mZombieOutput = fopen("ZombieOutput.csv", "wb");
			if ( mZombieOutput )
			{
				tipJar(mZombieOutput);
				fprintf(mZombieOutput,"Date,LastDate,PublicKey,Type,BalanceBefore,BalanceAfter,ValueChange,Age,ZombieScore,TotalZombieCount,TotalZombieValue,TotalZombieValueChange,TotalZombieScore\r\n");
			}
		}
		if ( mZombieOutput )
		{

			uint32_t totalZombieCount=0;
			uint64_t totalZombieValue=0;
			uint64_t totalZombieValueChange=0;
			float totalZombieScore=0;

			for (uint32_t i=0; i<mAddresses.size(); i++)
			{
				BitcoinAddress *ba = mAddresses.getKey(i);
				ZombieFinder &z = mZombieFinder[i];
				if ( z.mAddress )
				{
					if ( z.mLastAge > ZOMBIE_DAYS && ba->getDaysSinceLastUsed(refTime) < ZOMBIE_DAYS )
					{
						// Just came to life!
						uint64_t valueChange = 0;

						if ( ba->getBalance() < valueChange )
						{
							valueChange = z.mLastBalance - ba->getBalance();
						}

						totalZombieCount++;
						totalZombieValue+=z.mLastBalance;
						totalZombieValueChange+=valueChange;


						fprintf(mZombieOutput,"%s,", getDateString(refTime) );
						fprintf(mZombieOutput,"%s,", getDateString(z.mLastDate) );
						fprintf(mZombieOutput,"%s,", getAddressString(ba) );
						if ( ba->getData().mBitcoinAddressFlags & BitcoinAddress::BAT_COINBASE_50 )
						{
							fprintf(mZombieOutput,"COINBASE50,");
						}
						else if ( ba->getData().mBitcoinAddressFlags & BitcoinAddress::BAT_COINBASE_25 )
						{
							fprintf(mZombieOutput,"COINBASE25,");
						}
						else
						{
							fprintf(mZombieOutput,"NORMAL,");
						}
						fprintf(mZombieOutput,"%0.4f,", (float)z.mLastBalance / ONE_BTC );
						fprintf(mZombieOutput,"%0.4f,", (float) ba->getBalance() / ONE_BTC );
						fprintf(mZombieOutput,"%0.4f,", (float) valueChange / ONE_BTC );
						fprintf(mZombieOutput,"%d,", z.mLastAge );
						float zombieScore = (float)z.mLastAge*(float)z.mLastAge*(float)z.mLastBalance / ONE_BTC;
						totalZombieScore+=zombieScore;
						fprintf(mZombieOutput,"%0.1f", zombieScore );
						fprintf(mZombieOutput,"\r\n");
						fflush(mZombieOutput);
					}
				}
			}
			fprintf(mZombieOutput,"\r\n");
			fprintf(mZombieOutput,"%s,,SubTotals,,,,,,,", getDateString(refTime));
			fprintf(mZombieOutput,"%d,", totalZombieCount );
			fprintf(mZombieOutput,"%0.4f,", (float)totalZombieValue / ONE_BTC );
			fprintf(mZombieOutput,"%0.4f,", (float)totalZombieValueChange / ONE_BTC );
			fprintf(mZombieOutput,"%0.1f,", totalZombieScore );
			fprintf(mZombieOutput,"\r\n");
			fprintf(mZombieOutput,"\r\n");
		}
	}

	void printTopBalances(uint32_t tcount,float minBalance)
	{
		uint32_t plotCount = 0;
		uint64_t mbtc = (uint64_t)(minBalance*ONE_BTC);
		for (uint32_t i=0; i<mAddresses.size(); i++) // print one in every 10,000 addresses (just for testing right now)
		{
			BitcoinAddress *ba = mAddresses.getKey(i);
			uint64_t balance = ba->getBalance();
			if ( balance >= mbtc )
			{
				plotCount++;
			}
		}

		if ( !plotCount )
		{
			logMessage("No addresses found with a balance more than %d bitcoins\r\n", minBalance );
			return;
		}

		BitcoinAddress **sortPointers = new BitcoinAddress*[plotCount];
		plotCount = 0;
		for (uint32_t i=0; i<mAddresses.size(); i++) // print one in every 10,000 addresses (just for testing right now)
		{
			BitcoinAddress *ba = mAddresses.getKey(i);
			uint64_t balance = ba->getBalance();
			if ( balance >= mbtc )
			{
				sortPointers[plotCount] = ba;
				plotCount++;
			}
		}
		SortByBalance sb(sortPointers,plotCount);
		time_t currentTime;
		time(&currentTime); // get the current time.

		if ( plotCount < tcount )
		{
			tcount = plotCount;
		}
		logMessage("Displaying the top %d addresses by balance.\r\n", tcount );
		logMessage("==============================================\r\n");
		logMessage(" Address           : Balance  : Days Since Last Use\r\n");
		logMessage("==============================================\r\n");
		for (uint32_t i=0; i<tcount; i++)
		{
			BitcoinAddress *ba = sortPointers[i];
			uint64_t balance = ba->getData().mTotalReceived-ba->getData().mTotalSent;
			uint32_t lastUsed = ba->getData().mLastInputTime; // the last time we sent money (not received because anyone can send us money).
			if ( ba->getData().mLastInputTime == 0 ) // if it has never had a spend.. then we use the time of first receive..
			{
				lastUsed = ba->getData().mFirstOutputTime;
			}
			double seconds = difftime(currentTime,time_t(lastUsed));
			double minutes = seconds/60;
			double hours = minutes/60;
			uint32_t days = (uint32_t) (hours/24);
			uint32_t adr = mAddresses.getIndex(ba)+1;
			logMessage("%40s,  %8d,  %4d\r\n", getKey(adr), (uint32_t)( balance / ONE_BTC ), days );
		}
		delete []sortPointers;
	}

	virtual uint32_t getUsage(uint32_t baseTime,uint32_t daysMin,uint32_t daysMax,uint32_t &btcTotal,float minBalance)
	{
		uint32_t ret = 0;

		uint64_t btcValue = 0;
		uint64_t mbtc = (uint64_t)(minBalance*ONE_BTC);
		time_t currentTime(baseTime);

		for (uint32_t i=0; i<mAddresses.size(); i++) // print one in every 10,000 addresses (just for testing right now)
		{
			BitcoinAddress *ba = mAddresses.getKey(i);
			uint64_t balance = ba->getData().mTotalReceived-ba->getData().mTotalSent;
			if ( balance > mbtc )
			{
				uint32_t lastUsed = ba->getData().mLastInputTime; // the last time we sent money (not received because anyone can send us money).
				if ( ba->getData().mLastInputTime == 0 ) // if it has never had a spend.. then we use the time of first receive..
				{
					lastUsed = ba->getData().mFirstOutputTime;
				}
				double seconds = difftime(currentTime,time_t(lastUsed));
				double minutes = seconds/60;
				double hours = minutes/60;
				uint32_t days = (uint32_t) (hours/24);
				if ( days >= daysMin && days < daysMax )
				{
					btcValue+=balance;
					ret++;
				}
			}
		}

		btcTotal = (uint32_t)(btcValue / ONE_BTC);

		return ret;
	}

	uint32_t getBTC(uint64_t btc)
	{
		uint64_t oneBtc = ONE_BTC;
		uint64_t result = btc / oneBtc;
		return (uint32_t)result;
	}


	void zombieReport(uint32_t referenceTime,uint32_t zdays,float minBalance,BlockChain::ZombieReport &report)
	{
		uint64_t mbtc = (uint64_t)(minBalance*ONE_BTC);
		time_t currentTime(referenceTime);

		logMessage("Scanning %s bitcoin addresses and looking for zombies, relative to this date: %s\r\n", formatNumber(mAddresses.size()), getDateString(currentTime) );

		for (uint32_t i=0; i<mAddresses.size(); i++) // print one in every 10,000 addresses (just for testing right now)
		{
			BitcoinAddress *ba = mAddresses.getKey(i);
			uint64_t balance = ba->getData().mTotalReceived-ba->getData().mTotalSent;

			uint32_t type = ba->getData().mBitcoinAddressFlags;

			uint32_t lastUsed = ba->getData().mLastInputTime; // the last time we sent money (not received because anyone can send us money).
			if ( ba->getData().mLastInputTime == 0 ) // if it has never had a spend.. then we use the time of first receive..
			{
				lastUsed = ba->getData().mFirstOutputTime;
			}
			double seconds = difftime(currentTime,time_t(lastUsed));
			double minutes = seconds/60;
			double hours = minutes/60;

			uint32_t days = (uint32_t) (hours/24);

			if ( days > zdays )
			{
				if ( balance > mbtc )
				{
					report.mOverall.mAddressCount++;
					report.mOverall.mValue+=balance;

					if ( type & BitcoinAddress::BAT_COINBASE_50 )
					{
						report.mCoinBase50.mAddressCount++;
						report.mCoinBase50.mValue+=balance;
					}
					else if ( type & BitcoinAddress::BAT_COINBASE_25 )
					{
						report.mCoinBase25.mAddressCount++;
						report.mCoinBase25.mValue+=balance;
					}
					else if ( type & BitcoinAddress::BAT_HAS_SENDS )
					{
						report.mNormal.mAddressCount++;
						report.mNormal.mValue+=balance;
					}
					else
					{
						report.mNeverSpent.mAddressCount++;
						report.mNeverSpent.mValue+=balance;
					}
				}
				else
				{
					report.mDust.mAddressCount++;
					report.mDust.mValue+=balance;
				}
			}
			else
			{
				if ( balance > mbtc )
				{
					report.mAlive.mAddressCount++;
					report.mAlive.mValue+=balance;
				}
			}
		}

		logMessage("Zombie Report:\r\n");
		logMessage("Found %s zombie addresses older than %s days with a total balance of %s, excluding balances less than %0.4f\r\n",formatNumber(report.mOverall.mAddressCount),formatNumber(zdays),formatNumber(getBTC(report.mOverall.mValue)), minBalance );
		logMessage("Found %s living addresses newer than %s days with a total balance of %s, excluding balances less than %0.4f\r\n",formatNumber(report.mAlive.mAddressCount),formatNumber(zdays),formatNumber(getBTC(report.mAlive.mValue)), minBalance );
	}

	void printOldest(uint32_t tcount,float minBalance)
	{
		uint32_t plotCount = 0;
		uint64_t mbtc = (uint64_t)(minBalance*ONE_BTC);
		for (uint32_t i=0; i<mAddresses.size(); i++) // print one in every 10,000 addresses (just for testing right now)
		{
			BitcoinAddress *ba = mAddresses.getKey(i);
			uint64_t balance = ba->getData().mTotalReceived-ba->getData().mTotalSent;
			if ( balance >= mbtc )
			{
				plotCount++;
			}
		}

		if ( !plotCount )
		{
			logMessage("No addresses found with a balance more than %d bitcoins\r\n", minBalance );
			return;
		}

		BitcoinAddress **sortPointers = new BitcoinAddress*[plotCount];
		plotCount = 0;
		for (uint32_t i=0; i<mAddresses.size(); i++) // print one in every 10,000 addresses (just for testing right now)
		{
			BitcoinAddress *ba = mAddresses.getKey(i);
			uint64_t balance = ba->getData().mTotalReceived-ba->getData().mTotalSent;
			if ( balance >= mbtc )
			{
				sortPointers[plotCount] = ba;
				plotCount++;
			}
		}
		SortByAge sb(sortPointers,plotCount);
		time_t currentTime;
		time(&currentTime); // get the current time.

		if ( plotCount < tcount )
		{
			tcount = plotCount;
		}
		logMessage("Displaying the top %d addresses by age.\r\n", tcount );
		logMessage("==============================================\r\n");
		logMessage(" Address           : Balance  : Days Since Last Use\r\n");
		logMessage("==============================================\r\n");
		for (uint32_t i=0; i<tcount; i++)
		{
			BitcoinAddress *ba = sortPointers[i];
			uint64_t balance = ba->getData().mTotalReceived-ba->getData().mTotalSent;
			uint32_t lastUsed = ba->getData().mLastInputTime; // the last time we sent money (not received because anyone can send us money).
			if ( ba->getData().mLastInputTime == 0 ) // if it has never had a spend.. then we use the time of first receive..
			{
				lastUsed = ba->getData().mFirstOutputTime;
			}
			double seconds = difftime(currentTime,time_t(lastUsed));
			double minutes = seconds/60;
			double hours = minutes/60;
			uint32_t days = (uint32_t) (hours/24);
			uint32_t adr = mAddresses.getIndex(ba)+1;
			logMessage("%40s,  %0.4f,  %4d\r\n", getKey(adr), (float) balance / ONE_BTC, days );
		}
		delete []sortPointers;
	}

	void printAddress(const char *adr)
	{
		BitcoinAddress ba;
		uint8_t output[25];
		if ( bitcoinAsciiToAddress(adr,output) )
		{
			memcpy(&ba.mWord0,&output[1],20);
			BitcoinAddress *found = mAddresses.find(ba);
			if ( found )
			{
				printAddress(found);
			}
			else
			{
				logMessage("Failed to locate address: %s\r\n", adr );
			}
		}
		else
		{
			logMessage("Failed to decode address: %s\r\n", adr );
		}
	}

	void printAddresses(void)
	{
		for (uint32_t i=0; i<mAddresses.size(); i++) // print one in every 10,000 addresses (just for testing right now)
		{
			BitcoinAddress *ba = mAddresses.getKey(i);
			printAddress(ba);
		}
	}


	const char *getAddressString(BitcoinAddress *ba)
	{
		const char *ret = NULL;

		uint32_t i = mAddresses.getIndex(ba);
		ret = getKey(i+1);

		return ret;
	}


	void printAddress(BitcoinAddress *ba)
	{
		uint32_t i = mAddresses.getIndex(ba);
		logMessage("========================================\r\n");
		logMessage("PublicKey: %s[%d] has %s transactions associated with it.\r\n", getKey(i+1),i+1, formatNumber(ba->getData().mTransactionCount) );
		logMessage("Balance: %0.4f : TotalReceived: %0.4f TotalSpent: %0.4f\r\n", (float) (ba->getData().mTotalReceived-ba->getData().mTotalSent)/ONE_BTC, (float)ba->getData().mTotalReceived / ONE_BTC, (float) ba->getData().mTotalSent / ONE_BTC );
		if ( ba->getData().mLastInputTime )
		{
			logMessage("Last Input Time: %s\r\n", getTimeString(ba->getData().mLastInputTime) );
		}
		if ( ba->getData().mLastOutputTime )
		{
			logMessage("Last Output Time: %s\r\n", getTimeString(ba->getData().mLastOutputTime) );
		}
		for (uint32_t j=0; j<ba->getData().mTransactionCount; j++)
		{
			printTransaction(j,ba->getData().mTransactions[j],i+1);
		}
		logMessage("========================================\r\n");
		logMessage("\r\n");
	}

	inline StatSize getStatSize(uint64_t v)
	{
		if ( v == 0 ) return SS_ZERO;
		for (uint32_t i=1; i<(SS_COUNT-1); i++)
		{
			if ( v < mStatLimits[i] )
			{
				return (StatSize)i;
			}
		}
		return SS_MAX_BTC;
	}

	void gatherStatistics(uint32_t stime,uint32_t zombieDate,bool recordAddresses)
	{
		gatherAddresses(stime);

		assert( mStatCount < MAX_STAT_COUNT );
		if ( mStatCount >= MAX_STAT_COUNT )
		{
			printf("Overflowed stats table.\r\n");
			exit(1);
		}
		StatRow &row = mStatistics[mStatCount];
		row.mTime = stime;

		time_t currentTime;
		time(&currentTime); // get the current time.

		for (uint32_t i=0; i<mAddresses.size(); i++)
		{
			BitcoinAddress *ba = mAddresses.getKey(i);
			uint64_t balance = ba->getData().mTotalReceived-ba->getData().mTotalSent;
			StatSize s = getStatSize(balance);
			row.mCount++;
			row.mValue+=balance;

			row.mStats[s].mCount++;
			row.mStats[s].mValue+=balance;

			uint32_t lastUsed = ba->getData().mLastInputTime; // the last time we sent money (not received because anyone can send us money).

			if ( ba->getData().mLastInputTime == 0 ) // if it has never had a spend.. then we use the time of first receive..
			{
				lastUsed = ba->getData().mFirstOutputTime;
			}

			if ( lastUsed < zombieDate )
			{
				row.mZombieTotal+=balance;
				row.mZombieCount++;
			}

			if ( balance > 0 )
			{
				uint32_t days = ba->getDaysSinceLastUsed(stime);
				StatSize s = SS_FIVE_YEARS;
				if ( days <= 1 )
				{
					s = SS_ONE_DAY;
				}
				else if ( days <= 7 )
				{
					s = SS_ONE_WEEK;
				}
				else if ( days <= 31 )
				{
					s = SS_ONE_MONTH;
				}
				else if ( days <= (30*3) )
				{
					s = SS_THREE_MONTHS;
				}
				else if ( days <= (31*6) )
				{
					s = SS_SIX_MONTHS;
				}
				else if ( days <= 365 )
				{
					s = SS_ONE_YEAR;
				}
				else if ( days <= 365*2 )
				{
					s = SS_TWO_YEARS;
				}
				else if ( days <= 365*3 )
				{
					s = SS_THREE_YEARS;
				}
				else if ( days <= 365*4 )
				{
					s = SS_FOUR_YEARS;
				}
				row.mStats[s].mCount++;
				row.mStats[s].mValue+=balance;
			}
		}

		if ( recordAddresses )
		{
			// First compute how many bitcoin addresses have a balance over a minimum bitcoin size (we will start with just one)
			uint32_t plotCount = 0;

			for (uint32_t i=0; i<mAddresses.size(); i++)
			{
				BitcoinAddress *ba = mAddresses.getKey(i);
				uint64_t balance = ba->getData().mTotalReceived-ba->getData().mTotalSent;
				if ( balance >= ONE_BTC )
				{
					plotCount++;
				}
			}

			logMessage("Gathering Address Delta's for %s addresses containing more than one bitcoin\r\n", formatNumber(plotCount) );

			if ( plotCount )
			{
				BitcoinAddress **sortPointers = new BitcoinAddress*[plotCount];
				uint32_t plotCount = 0;
				for (uint32_t i=0; i<mAddresses.size(); i++) // print one in every 10,000 addresses (just for testing right now)
				{
					BitcoinAddress *ba = mAddresses.getKey(i);
					uint64_t balance = ba->getData().mTotalReceived-ba->getData().mTotalSent;
					if ( balance >= ONE_BTC )
					{
						sortPointers[plotCount] = ba;
						plotCount++;
					}
				}

				uint32_t reportCount = plotCount;

				row.mAddresses = new StatAddress[reportCount];
				row.mAddressCount = reportCount;

				SortByBalance sb(sortPointers,plotCount);

				for (uint32_t i=0; i<reportCount; i++)
				{
					BitcoinAddress *ba = sortPointers[i];
					StatAddress &sa = row.mAddresses[i];
					sa.mAddress = mAddresses.getIndex(ba)+1;
					sa.mLastTime = ba->getLastUsedTime();
					sa.mFirstTime = ba->getData().mFirstOutputTime;
					sa.mTotalReceived = (uint32_t)(ba->getData().mTotalReceived/ONE_MBTC);
					sa.mTotalSent = (uint32_t)(ba->getData().mTotalSent/ONE_MBTC);
					sa.mTransactionCount = (uint8_t) (ba->getData().mTransactionCount > 255 ? 255 : ba->getData().mTransactionCount);
					uint32_t inputCount = ba->getInputCount();
					uint32_t outputCount = ba->getOutputCount();
					sa.mInputCount = (uint8_t) (inputCount > 255 ? 255 : inputCount);
					sa.mOutputCount = (uint8_t) (outputCount > 255 ? 255 : outputCount);
				}

				if ( mStatCount >= 1 )
				{
					// build the delta!
					StatRow &previousRow = mStatistics[mStatCount-1];
					//
					uint32_t *addressIndex = new uint32_t[mAddresses.size()];	// convert from master address list to used by statistics address list table

					memset(addressIndex,0,sizeof(uint32_t)*mAddresses.size());

					for (uint32_t i=0; i<previousRow.mAddressCount; i++)
					{
						StatAddress &sa = previousRow.mAddresses[i];
						addressIndex[sa.mAddress-1] = i+1; // make this address as being used by the previous row
					}

					uint32_t changeCount=0;
					uint32_t newCount=0;
					uint32_t deleteCount=0;
					uint32_t sameCount=0;
					uint32_t riseFromTheDeadCount=0;
					uint32_t riseFromTheDeadAmount=0;

					for (uint32_t i=0; i<row.mAddressCount; i++)
					{
						StatAddress &na = row.mAddresses[i];	// get the current row address
						uint32_t aindex = na.mAddress-1; // get the array index for this address
						if ( addressIndex[aindex] ) // did the previous row use this address?
						{
							uint32_t pindex = addressIndex[aindex]-1; // get the array index in the previous row so we can do a compare.
							addressIndex[aindex] = 0xFFFFFFFF; // make it as processed.
							StatAddress &oa = previousRow.mAddresses[pindex];
							if ( na == oa )
							{
								sameCount++; // no changes...
							}
							else
							{
								// ok.. if it previously existed but there has been a change, was it a zombie change?
								if ( oa.mLastTime < zombieDate && na.mLastTime >= zombieDate )
								{
									riseFromTheDeadCount++;
									riseFromTheDeadAmount+=oa.getBalance(); // how much bitcoin rose from the dead.
								}
								changeCount++;
							}
						}
						else
						{
							newCount++;
						}
					}

					for (uint32_t i=0; i<mAddresses.size(); i++)
					{
						if ( addressIndex[i] && addressIndex[i] != 0xFFFFFFFF )
						{
							deleteCount++;
						}
					}

					row.mNewAddressCount = newCount;
					row.mDeleteAddressCount = deleteCount;
					row.mChangeAddressCount = changeCount;
					row.mSameAddressCount = sameCount;
					row.mRiseFromDeadAmount = riseFromTheDeadAmount;
					row.mRiseFromDeadCount = riseFromTheDeadCount;


					if ( newCount )
					{
						row.mNewAddresses = new StatAddress[newCount];
					}

					if ( changeCount )
					{
						row.mChangedAddresses = new StatAddress[changeCount];
					}
					// Assign an array index to each address used by the previous row
					memset(addressIndex,0,sizeof(uint32_t)*mAddresses.size());
					for (uint32_t i=0; i<previousRow.mAddressCount; i++)
					{
						StatAddress &sa = previousRow.mAddresses[i];
						addressIndex[sa.mAddress-1] = i+1;
					}

					newCount = 0;
					changeCount = 0;
					sameCount = 0;

					for (uint32_t i=0; i<row.mAddressCount; i++)
					{
						StatAddress &na = row.mAddresses[i];
						uint32_t aindex = na.mAddress-1;

						if ( addressIndex[aindex] ) // did the previous row have this address.
						{
							uint32_t pindex = addressIndex[aindex]-1;
							addressIndex[aindex] = 0xFFFFFFFF; // make it as processed.
							StatAddress &oa = previousRow.mAddresses[pindex];
							if ( na == oa )
							{
								sameCount++;
							}
							else
							{
								row.mChangedAddresses[changeCount] = na;
								changeCount++;
							}
						}
						else
						{
							row.mNewAddresses[newCount] = na;
							newCount++;
						}
					}

					if ( deleteCount )
					{
						row.mDeletedAddresses = new uint32_t[deleteCount];
						deleteCount = 0;
						for (uint32_t i=0; i<mAddresses.size(); i++)
						{
							if ( addressIndex[i] && addressIndex[i] != 0xFFFFFFFF )
							{
								row.mDeletedAddresses[deleteCount] = i+1;
								deleteCount++;
							}
						}
					}

					delete []addressIndex;

					logMessage("Found %s new addresses, %s changed addresses, and %s deleted addresses\r\n",
						formatNumber(newCount),
						formatNumber(changeCount),
						formatNumber(deleteCount));

					if ( mStatCount >= 2 )
					{
						StatRow &oldRow = mStatistics[mStatCount-2];
						delete []oldRow.mAddresses;
						oldRow.mAddresses = NULL;
						oldRow.mAddressCount = 0;
					}
				}
				delete []sortPointers;
			}
		}
		mStatCount++;
	}

	void saveAddressesOverTime(void)
	{
		FILE *fph = fopen("BlockChainAddresses.bin", "wb");
		if ( fph )
		{
			const char *header = "BLOCK_CHAIN_ADDRESSES";
			fwrite(header,strlen(header)+1,1,fph);
			uint32_t version = 1;
			fwrite(&version, sizeof(version), 1, fph );

			// first..we need to count how many addresses are being used for this report.
			uint32_t *addressIndex = new uint32_t[mAddresses.size()];	// convert from master address list to used by statistics address list table
			uint32_t *inverseAddress = new uint32_t[mAddresses.size()]; // convert from remapped list back to master address.
			memset(addressIndex,0xFF,sizeof(uint32_t)*mAddresses.size());
			memset(inverseAddress,0xFF,sizeof(uint32_t)*mAddresses.size());
			uint32_t fcount = 0; // number of unique addresses found

			for (uint32_t i=0; i<mStatCount; i++)
			{
				StatRow &row = mStatistics[i];

				for (uint32_t i=0; i<row.mAddressCount; i++)
				{
					StatAddress &sa = row.mAddresses[i];
					assert( sa.mAddress	 );
					uint32_t a = sa.mAddress-1;
					assert( a < mAddresses.size() );
					if ( addressIndex[a] == 0xFFFFFFFF ) // if this is the first time we have encountered this address, then we add it to the forward and inverse lookup tables.
					{
						addressIndex[a] = fcount+1;
						inverseAddress[fcount] = a;
						fcount++;
					}
				}
				for (uint32_t i=0; i<row.mNewAddressCount; i++)
				{
					StatAddress &sa = row.mNewAddresses[i];
					assert( sa.mAddress	 );
					uint32_t a = sa.mAddress-1;
					assert( a < mAddresses.size() );
					if ( addressIndex[a] == 0xFFFFFFFF ) // if this is the first time we have encountered this address, then we add it to the forward and inverse lookup tables.
					{
						addressIndex[a] = fcount+1;
						inverseAddress[fcount] = a;
						fcount++;
					}
				}
			}
			// ok..now ready to write out the address headers.
			fwrite(&fcount,sizeof(fcount),1,fph);	// save how many unique addresses were found.
			// now write out the 20 byte public key address for each.
			for (uint32_t i=0; i<fcount; i++)
			{
				uint32_t a = inverseAddress[i]; // get the original address.
				BitcoinAddress *ba = mAddresses.getKey(a);
				fwrite(ba,20,1,fph);// write out the bitcoin address 160 bit public key (20 bytes long)
			}

			fwrite(&mStatCount, sizeof(mStatCount), 1, fph );

			for (uint32_t i=0; i<mStatCount; i++)
			{
				StatRow &row = mStatistics[i];
				fwrite(&row.mTime,sizeof(row.mTime),1, fph); // write out the time that this row was recorded...
				if ( i == 0 )
				{
					fwrite(&row.mAddressCount,sizeof(row.mAddressCount),1,fph);
				}
				else
				{
					fwrite(&row.mNewAddressCount,sizeof(row.mNewAddressCount),1,fph);
				}
				fwrite(&row.mChangeAddressCount,sizeof(row.mChangeAddressCount),1,fph);
				fwrite(&row.mDeleteAddressCount,sizeof(row.mDeleteAddressCount),1,fph);
			}

			for (uint32_t i=0; i<mStatCount; i++)
			{
				StatRow &row = mStatistics[i];
				if ( i == 0 )
				{
					for (uint32_t i=0; i<row.mAddressCount; i++)
					{
						StatAddress sa = row.mAddresses[i];
						sa.mAddress = addressIndex[sa.mAddress-1]; // convert to the new sequentially ordered hash
						assert( sa.mAddress != 0 && sa.mAddress <= fcount );
						fwrite(&sa,sizeof(sa),1,fph); // write it out...
					}
				}
				else
				{
					for (uint32_t i=0; i<row.mNewAddressCount; i++)
					{
						StatAddress sa = row.mNewAddresses[i];
						sa.mAddress = addressIndex[sa.mAddress-1]; // convert to the new sequentially ordered hash
						assert( sa.mAddress != 0 && sa.mAddress <= fcount );
						fwrite(&sa,sizeof(sa),1,fph); // write it out...
					}

					for (uint32_t i=0; i<row.mChangeAddressCount; i++)
					{
						StatAddress sa = row.mChangedAddresses[i];
						sa.mAddress = addressIndex[sa.mAddress-1]; // convert to the new sequentially ordered hash
						assert( sa.mAddress != 0 && sa.mAddress <= fcount );
						fwrite(&sa,sizeof(sa),1,fph); // write it out...
					}

					for (uint32_t i=0; i<row.mDeleteAddressCount; i++)
					{
						uint32_t da = row.mDeletedAddresses[i];
						uint32_t a = addressIndex[da-1];
						assert ( a != 0 && a <= fcount );
						fwrite(&a,sizeof(uint32_t),1,fph);
					}
				}
			}

			delete []addressIndex;
			delete []inverseAddress;
			fclose(fph);
		}
	}

	void tipJar(FILE *fph)
	{
		fprintf(fph,"\r\n");
		fprintf(fph,"\"BlockChain Statistics Report generated by: https://code.google.com/p/blockchain/ \"\r\n" );
		fprintf(fph,"\r\n");
		fprintf(fph,"\"Written by John W. Ratcliff mailto:jratcliffscarab@gmail.com\"\r\n" );
		fprintf(fph,"\"Website: http://codesuppository.blogspot.com/\"\r\n" );
		fprintf(fph,"\"TipJar Address: 1NY8SuaXfh8h5WHd4QnYwpgL1mNu9hHVBT\"\r\n" );
		fprintf(fph,"\r\n");
	}

	void saveStatistics(bool record_addresses,float minBalance)
	{
		if ( record_addresses )
		{
			saveAddressesOverTime();
		}
		FILE *fph = fopen("stats.csv", "wb");
		if ( !fph )
		{
			logMessage("Failed to open statistics output file 'stats.csv' for write access.\r\n");
			return;
		}


		logMessage("Saving TopKeys.csv report\r\n");

		FILE *topKeys = fopen("topkeys.csv", "wb");

		// BitcoinAddress Summary Results first
		uint64_t mbtc = (uint64_t)(minBalance*ONE_BTC);

		AgeStat ageStats[AM_LAST];

		// First compute how many bitcoin addresses have a balance over a minimum bitcoin size (we will start with just one)
		uint32_t plotCount = 0;

		for (uint32_t i=0; i<mAddresses.size(); i++)
		{
			BitcoinAddress *ba = mAddresses.getKey(i);

			uint64_t balance = ba->getData().mTotalReceived-ba->getData().mTotalSent;

			uint32_t days = ba->getDaysSinceLastUsed(0);
			if ( days <= 1 )
			{
				ageStats[AM_ONE_DAY].addValue(balance);
			}
			else if ( days <= 7 )
			{
				ageStats[AM_ONE_WEEK].addValue(balance);
			}
			else if ( days <= 30 )
			{
				ageStats[AM_ONE_MONTH].addValue(balance);
			}
			else if ( days <= (30*3) )
			{
				ageStats[AM_THREE_MONTHS].addValue(balance);
			}
			else if ( days <= (30*6) )
			{
				ageStats[AM_SIX_MONTHS].addValue(balance);
			}
			else if ( days <= 365 )
			{
				ageStats[AM_ONE_YEAR].addValue(balance);
			}
			else if ( days <= 365*2 )
			{
				ageStats[AM_TWO_YEARS].addValue(balance);
			}
			else if ( days <= 365*3 )
			{
				ageStats[AM_THREE_YEARS].addValue(balance);
			}
			else if ( days <= 365*4 )
			{
				ageStats[AM_FOUR_YEARS].addValue(balance);
			}
			else
			{
				ageStats[AM_FIVE_YEARS].addValue(balance);
			}

			if ( balance >= mbtc )
			{
				plotCount++;
			}
		}

		if ( plotCount )
		{
			BitcoinAddress **sortPointers = new BitcoinAddress*[plotCount];
			uint32_t plotCount = 0;
			for (uint32_t i=0; i<mAddresses.size(); i++) // print one in every 10,000 addresses (just for testing right now)
			{
				BitcoinAddress *ba = mAddresses.getKey(i);
				uint64_t balance = ba->getData().mTotalReceived-ba->getData().mTotalSent;
				if ( balance >= mbtc )
				{
					sortPointers[plotCount] = ba;
					plotCount++;
				}
			}
			uint32_t reportCount = plotCount;
			tipJar(fph);

			fprintf(fph,"\r\n");
			fprintf(fph,"Bitcoin value distribution based on age.\r\n");
			fprintf(fph,"Age,Value,Count\r\n");
			for (uint32_t i=0; i<AM_LAST; i++)
			{
				AgeStat &as = ageStats[i];
				fprintf(fph,"%s,%d,%d\r\n", getAgeString((AgeMarker)i), (uint32_t)(as.mTotalValue/ONE_BTC), as.mCount );
			}
			fprintf(fph,"\r\n");

			if ( topKeys )
			{
				tipJar(topKeys);

				fprintf(topKeys,"\"Found %s addreses with a bitcoin balance of %0.4f btc or more.\"\r\n", formatNumber(plotCount), minBalance);
				if ( plotCount > MAX_PLOT_COUNT )
				{
					reportCount = MAX_PLOT_COUNT;
					fprintf(topKeys,"\"Exceeded maximum plot count, so only reporting the first %s addresses.\"\r\n", formatNumber(reportCount));
				}


				fprintf(topKeys,"\"Scatter Plot Data values of %s bitcoin address balances with over %0.4f btc and number of days since last transaction. Sorted by Balance\"\r\n", formatNumber(plotCount), minBalance);
				fprintf(topKeys,"Days,Value,FirstUsed,LastReceived,LastSpent,TotalSent,TotalReceived,TransactionCount,PublicKeyAddress\r\n");
				SortByBalance sb(sortPointers,plotCount);
				time_t currentTime;
				time(&currentTime); // get the current time.

				for (uint32_t i=0; i<reportCount; i++)
				{
					BitcoinAddress *ba = sortPointers[i];
					uint64_t balance = ba->getData().mTotalReceived-ba->getData().mTotalSent;
					uint32_t lastUsed = ba->getData().mLastInputTime; // the last time we sent money (not received because anyone can send us money).
					if ( ba->getData().mLastInputTime == 0 ) // if it has never had a spend.. then we use the time of first receive..
					{
						lastUsed = ba->getData().mFirstOutputTime;
					}
					double seconds = difftime(currentTime,time_t(lastUsed));
					double minutes = seconds/60;
					double hours = minutes/60;
					uint32_t days = (uint32_t) (hours/24);
					uint32_t adr = mAddresses.getIndex(ba)+1;

					fprintf(topKeys,"%d,", days );
					fprintf(topKeys,"%0.9f,", (float) balance / ONE_BTC );
					fprintf(topKeys,"\"%s\",", getTimeString(ba->getData().mFirstOutputTime));
					fprintf(topKeys,"\"%s\",", getTimeString(ba->getData().mLastOutputTime));
					fprintf(topKeys,"\"%s\",", getTimeString(ba->getData().mLastInputTime));
					fprintf(topKeys,"%0.9f,", (float)ba->getData().mTotalSent / ONE_BTC );
					fprintf(topKeys,"%0.9f,", (float) ba->getData().mTotalReceived / ONE_BTC );
					fprintf(topKeys,"%d,", ba->getData().mTransactionCount );
					fprintf(topKeys,"%s\r\n", getKey(adr) );
				}
				fprintf(topKeys,"\r\n");
			}

			delete []sortPointers;
		}
//


		const char *months[12] = { "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December" };
		{
			fprintf(fph,"\r\n");
			fprintf(fph,"Bitcoin Public Key Address Distribution Count by balance.\r\n");
			fprintf(fph,"\r\n");
			fprintf(fph,",");
			for (uint32_t i=0; i<SS_COUNT; i++)
			{
				fprintf(fph,"\"%s\",", mStatLabel[i]);
			}
			fprintf(fph,"\r\n");
			for (uint32_t i=0; i<mStatCount; i++)
			{
				StatRow &row = mStatistics[i];
				time_t tnow(row.mTime);
				struct tm beg;
				beg = *localtime(&tnow);
				fprintf(fph,"\"%s %d %d\",", months[beg.tm_mon], beg.tm_mday, beg.tm_year+1900);
				for (uint32_t j=0; j<SS_COUNT; j++)
				{
					StatValue &v = row.mStats[j];
					fprintf(fph,"%d,",v.mCount);
				}
				fprintf(fph,"\r\n");
			}
			fprintf(fph,"\r\n");
		}

		{
			fprintf(fph,"\r\n");
			fprintf(fph,"Bitcoin Public Key Address Distribution Total Value by balance.\r\n");
			fprintf(fph,"\r\n");
			fprintf(fph,",");
			for (uint32_t i=0; i<SS_COUNT; i++)
			{
				fprintf(fph,"\"%s\",", mStatLabel[i]);
			}
			fprintf(fph,"\r\n");
			for (uint32_t i=0; i<mStatCount; i++)
			{
				StatRow &row = mStatistics[i];
				time_t tnow(row.mTime);
				struct tm beg;
				beg = *localtime(&tnow);
				fprintf(fph,"\"%s %d %d\",", months[beg.tm_mon], beg.tm_mday, beg.tm_year+1900);
				for (uint32_t j=0; j<SS_COUNT; j++)
				{
					StatValue &v = row.mStats[j];
					fprintf(fph,"%0.4f,",(float)v.mValue/ONE_BTC);
				}
				fprintf(fph,"\r\n");
			}
			fprintf(fph,"\r\n");
		}



		fclose(fph);
	}

protected:
	uint64_t					mLastBitcoinTotal;
	FILE						*mKeyReport;
	FILE						*mZombieOutput;
	ZombieFinder				*mZombieFinder;
	BitcoinAddressHashMap		mAddresses;				// A hash map of every single bitcoin address ever referenced to a much shorter integer to save memory
	uint32_t					mTransactionCount;
	uint32_t					mTotalInputCount;
	uint32_t					mTotalOutputCount;
	Transaction					*mTransactions;
	TransactionInput			*mInputs;
	TransactionOutput			*mOutputs;
	uint32_t					mBlockCount;
	Transaction					**mBlocks;
	Transaction					**mTransactionReferences;
	uint32_t					mStatCount;
	StatRow						mStatistics[MAX_STAT_COUNT];
	const char					*mStatLabel[SS_COUNT];
	uint64_t					mStatLimits[SS_COUNT];
};

#ifdef _MSC_VER
#pragma warning(pop)
#endif

// This is the implementation of the BlockChain parser interface
class BlockChainImpl : public BlockChain
{
public:
	BlockChainImpl(const char *rootPath)
	{
		uint8_t key[20] = { 0x19, 0xa7, 0xd8, 0x69, 0x03, 0x23, 0x68, 0xfd, 0x1f, 0x1e, 0x26, 0xe5, 0xe7, 0x3a, 0x4a, 0xd0, 0xe4, 0x74, 0x96, 0x0e };
		uint8_t temp[25];
		char scratch[256];
		bitcoinRIPEMD160ToScriptAddress(key,temp);
		bitcoinAddressToAscii(temp,scratch,256);



//		uint8_t ckey[33] = { 0x03, 0x2b, 0x0d, 0x81, 0xe6, 0xef, 0xe5, 0x4f, 0x10, 0x89, 0x08, 0xe7, 0xf7, 0x05, 0x1c, 0x54, 0x75, 0x46, 0x81, 0xe3, 0x85, 0x0d, 0xf0, 0x5d, 0xba, 0x4b, 0xb5, 0xec, 0x82, 0xd0, 0x5b, 0x63, 0xe5 };
//		uint8_t temp[25];
//		bitcoinCompressedPublicKeyToAddress(ckey,temp);
//		char output[256];
//		bitcoinAddressToAscii(temp,output,256);

//		uint8_t temp[25] = { 0x00, 0x8b, 0x1d, 0x6a, 0x31, 0xb0, 0x19, 0xe2, 0xda, 0x16, 0xde, 0x77, 0xf6, 0x0c, 0x62, 0x3b, 0x14, 0x42, 0xd5, 0xec, 0x2e, 0x24, 0x3a, 0x00, 0x61 };
//		char output[256];
//		bitcoinAddressToAscii(temp,output,256);
//		bitcoinAsciiToAddress("1DgaASdtGgUavpNUE8ESBq3gmPbHh2ALnC",gDummyKey);

		bitcoinAsciiToAddress(gDummyKeyAscii,gDummyKey);
		bitcoinAsciiToAddress(gZeroByteAscii,gZeroByte);

		mTextReport = NULL;
		mBitcoinAddressDataFactory = new BitcoinAddressDataFactory;
		gBitcoinAddressDataFactory = mBitcoinAddressDataFactory;
		mSearchForText = 0;
		mTransactionFactory = new BitcoinTransactionFactory;
		mTransactionSizeReport = NULL;
		mExportFile = NULL;
		mLastExportIndex = 0;
		mLastExportDay = 0xFFFFFFFF;
		mLastExportTime = 0xFFFFFFFF;
		mAnalyzeInputSignatures = false;
		mExportTransactions = false;
		sprintf(mRootDir,"%s",rootPath);
		mCurrentBlockData = mBlockDataBuffer;	// scratch buffers to read in up to 3 block.
		mTransactionCount = 0;
		mBlockIndex = 0;
		mBlockBase = 0;
		mReadCount = 0;
		for (uint32_t i=0; i<MAX_BLOCK_FILES; i++)
		{
			mBlockChain[i] = NULL;
		}
		mBlockCount = 0;
		mScanCount = 0;
		mBlockHeaders = NULL;
		mLastBlockHeaderCount = 0;
		mLastBlockHeader = NULL;
		mTotalInputCount = 0;
		mTotalOutputCount = 0;
		mTotalTransactionCount = 0;
		mBlockHeaderMap.setMemoryMapFileName("@BlockHeaderMap.mmap");
		mTransactionMap.setMemoryMapFileName("@TransactionMap.mmap");
		openBlock();	// open the input file
	}

	// Close all blockchain files which have been opended so far
	virtual ~BlockChainImpl(void)
	{
		for (uint32_t i=0; i<mBlockIndex; i++)
		{
			if ( mBlockChain[i] )
			{
				fclose(mBlockChain[i]);	// close the block-chain file pointer
			}
		}
		delete []mBlockHeaders;
		if ( mExportFile )
		{
			fclose(mExportFile);
		}
		if ( mTransactionSizeReport )
		{
			fclose(mTransactionSizeReport);
		}
		delete mTransactionFactory;
		delete	mBitcoinAddressDataFactory;
		gBitcoinAddressDataFactory = NULL;
		if ( mTextReport )
		{
			fclose(mTextReport);
		}
	}

	// Open the next data file in the block-chain sequence
	bool openBlock(void)
	{
		bool ret = false;

		char scratch[512];
#ifdef _MSC_VER
		sprintf(scratch,"%s\\blk%05d.dat", mRootDir, mBlockIndex );	// get the filename
#else
		sprintf(scratch,"%s/blk%05d.dat", mRootDir, mBlockIndex );	// get the filename
#endif
		FILE *fph = fopen(scratch,"rb");
		if ( fph )
		{
			fseek(fph,0L,SEEK_END);
			mFileLength = ftell(fph);
			fseek(fph,0L,SEEK_SET);
			mBlockChain[mBlockIndex] = fph;
			ret = true;
			logMessage("Successfully opened block-chain input file '%s'\r\n", scratch );
		}
		else
		{
			logMessage("Failed to open block-chain input file '%s'\r\n", scratch );
		}
		if ( mBlockHeaderMap.size() )
		{
			logMessage("Scanned %s block headers so far, %s since last time.\r\n", formatNumber(mBlockHeaderMap.size()), formatNumber(mBlockHeaderMap.size()-mLastBlockHeaderCount));
		}

		mLastBlockHeaderCount = mBlockHeaderMap.size();

		return ret;
	}

	virtual void release(void)
	{
		delete this;
	}

	// Returns true if we successfully opened the block-chain input file
	bool isValid(void)
	{
		return mBlockChain[0] ? true : false;
	}

	void processTransactions(Block &block)
	{
		mTotalTransactionCount+=block.transactionCount;

		for (uint32_t i=0; i<block.transactionCount; i++)
		{
			BlockTransaction &t = block.transactions[i];
			Hash256 hash(t.transactionHash);
			FileLocation f(hash,t.fileIndex,t.fileOffset,t.transactionLength,t.transactionIndex);
			mTransactionMap.insert(f);
		}

		// ok.. now make sure we can locate every input transaction!
		for (uint32_t i=0; i<block.transactionCount; i++)
		{
			BlockTransaction &t = block.transactions[i];
			mTotalInputCount+=t.inputCount;
			mTotalOutputCount+=t.outputCount;
			for (uint32_t j=0; j<t.inputCount; j++)
			{
				BlockInput &input = t.inputs[j];

				if ( input.transactionIndex != 0xFFFFFFFF )
				{
					Hash256 thash(input.transactionHash);
					FileLocation key(thash,0,0,0,0);
					FileLocation *found = mTransactionMap.find(key);
					if ( found == NULL )
					{
						block.warning = true;
						printf("Failed to find transaction!\r\n");
						exit(1);
					}
				}
			}
		}
	}


	virtual const Block *readBlock(uint32_t blockIndex)
	{
		Block *ret = NULL;

		if ( readBlock(mSingleReadBlock,blockIndex) )
		{
			ret = &mSingleReadBlock;
			if ( gDumpBlock )
			{
				gDumpBlock = false;
				logMessage("\r\n");
				logMessage("\r\n");
				printBlock(ret);
				logMessage("\r\n");
				logMessage("\r\n");
			}
		}

		return ret;
	}

	virtual bool readBlock(BlockImpl &block,uint32_t blockIndex)
	{
		bool ret = false;

		if ( blockIndex >= mBlockCount ) return false;
		BlockHeader &header = *mBlockHeaders[blockIndex];
		FILE *fph = mBlockChain[header.mFileIndex];
		if ( fph )
		{
			block.blockIndex = blockIndex;
			block.warning = false;
			fseek(fph,header.mFileOffset,SEEK_SET);
			gBlockIndex = blockIndex;
			block.blockLength = header.mBlockLength;
			block.blockReward = 0;
			block.totalInputCount = 0;
			block.totalOutputCount = 0;
			block.fileIndex = header.mFileIndex;
			block.fileOffset = header.mFileOffset;
			block.blockLength = header.mBlockLength;

			if ( blockIndex < (mBlockCount-2) )
			{
				BlockHeader *nextNext = mBlockHeaders[blockIndex+2];
				block.nextBlockHash =  nextNext->mPreviousBlockHash;
			}

			uint8_t *blockData = mBlockDataBuffer;
			size_t r = fread(blockData,block.blockLength,1,fph); // read the rest of the block (less the 8 byte header we have already consumed)

			if ( r == 1 )
			{
				computeSHA256(blockData,4+32+32+4+4+4,block.computedBlockHash);
				computeSHA256(block.computedBlockHash,32,block.computedBlockHash);
				ret = block.processBlockData(blockData,block.blockLength,mTransactionCount);


				if ( mSearchForText ) // if we are searching for ASCII text in the input stream...
				{
					uint32_t textCount = 0;
					const char *scan = (const char *)blockData;
					const char *end_scan = scan+(block.blockLength-mSearchForText);
					char *scratch =  new char[MAX_BLOCK_SIZE];
					uint32_t lineCount = 0;
					uint32_t totalCount = 0;
					while ( scan < end_scan )
					{
						uint32_t count = 0;
//						const char *begin = scan;
						char *dest = scratch;
						while ( isASCII(*scan) && scan < end_scan )
						{
							*dest++ = *scan++;
							count++;
						}
						if ( count >= mSearchForText )
						{
							*dest = 0;
							if ( textCount == 0 )
							{
								if ( mTextReport == 0 )
								{
									mTextReport = fopen("AsciiTextReport.txt", "wb");
								}
								if ( mTextReport )
								{
									fprintf(mTextReport,"==========================================\r\n");
									fprintf(mTextReport,"= ASCII TEXT REPORT for Block #%s on %s\r\n", formatNumber(blockIndex), getDateString(block.timeStamp) );
									fprintf(mTextReport,"==========================================\r\n");
								}
							}
							textCount++;
							if ( mTextReport )
							{
								fprintf(mTextReport,"%s", scratch );
								lineCount+=count;
								totalCount+=count;
								if ( lineCount > 80 )
								{
									fprintf(mTextReport,"\r\n");
									lineCount = 0;
								}
							}
						}
						scan++;
					}
					if ( textCount && mTextReport )
					{
						fprintf(mTextReport,"\r\n");
						fprintf(mTextReport,"==========================================\r\n");
						if ( totalCount >= 128 )
						{
							fprintf(mTextReport,"Very Long Text: %d bytes\r\n", totalCount);
						}
						else if ( totalCount >= 64 )
						{
							fprintf(mTextReport,"Long Text: %d bytes\r\n", totalCount);
						}
						else
						{
							fprintf(mTextReport,"Short Text: %d bytes\r\n", totalCount );
						}
						fprintf(mTextReport,"\r\n");
						fflush(mTextReport);
					}
					delete []scratch;
				}

				if ( ret )
				{

					processTransactions(block);

					if ( mAnalyzeInputSignatures )
					{
						for (uint32_t j=0; j<block.transactionCount; j++)
						{
							BlockChain::BlockTransaction &transaction = block.transactions[j];
							for (uint32_t i=0; i<transaction.inputCount; i++)
							{
								BlockChain::BlockInput &input = transaction.inputs[i];
								input.signatureFormat = analyzeSignature(input.responseScript,input.responseScriptLength,j,i,input.transactionHash,transaction.transactionHash,input.inputValue);
								bool found = false;
								for (uint32_t i=0; i<gSignatureStatCount; i++)
								{
									if ( gSignatureStats[i].mFlags == input.signatureFormat )
									{
										gSignatureStats[i].mCount++;
										gSignatureStats[i].mValue+=input.inputValue;
										found = true;
										break;
									}
								}
								if ( !found )
								{
									if ( gSignatureStatCount < MAX_SIGNATURE_STAT )
									{
										gSignatureStats[gSignatureStatCount].mFlags = input.signatureFormat;
										gSignatureStats[gSignatureStatCount].mCount = 1;
										gSignatureStats[gSignatureStatCount].mValue = input.inputValue;
										gSignatureStatCount++;
									}
								}
							}
						}
					}


				}
			}
			else
			{
				logMessage("Failed to read input block.  BlockChain corrupted.\r\n");
				exit(1);
			}
		}
		block.warning = gIsWarning;
		gIsWarning = false;
		return ret;
	}


	virtual void printBlock(const Block *block) // prints the contents of the block to the console for debugging purposes
	{
		logMessage("==========================================================================================\r\n");
		logMessage("Block #%s\r\n", formatNumber(block->blockIndex) );

		logMessage("ComputedBlockHash: ");
		printReverseHash(block->computedBlockHash);
		logMessage("\r\n");

		if ( block->previousBlockHash )
		{
			logMessage("PreviousBlockHash:");
			printReverseHash(block->previousBlockHash);
			logMessage("\r\n");
		}
		if ( block->nextBlockHash )
		{
			logMessage("NextBlockHash:");
			printReverseHash(block->nextBlockHash);
			logMessage("\r\n");
		}


		logMessage("Merkle root: ");
		printReverseHash(block->merkleRoot);
		logMessage("\r\n");

		logMessage("Number of Transactions: %s\r\n", formatNumber(block->transactionCount) );
		logMessage("Timestamp : %s\r\n", getTimeString(block->timeStamp ) );
		logMessage("Bits: %d Hex: %08X\r\n", block->bits, block->bits );
		logMessage("Size: %0.10f KB or %s bytes.\r\n", (float)block->blockLength / 1024.0f, formatNumber(block->blockLength) );
		logMessage("Version: %d\r\n", block->blockFormatVersion );
		logMessage("Nonce: %u\r\n", block->nonce );
		logMessage("BlockReward: %f\r\n", (float)block->blockReward / ONE_BTC );

		logMessage("%s transactions\r\n", formatNumber(block->transactionCount) );
		for (uint32_t i=0; i<block->transactionCount; i++)
		{
			const BlockTransaction &t = block->transactions[i];
			logMessage("Transaction %s : %s inputs %s outputs. VersionNumber: %d\r\n", formatNumber(i), formatNumber(t.inputCount), formatNumber(t.outputCount), t.transactionVersionNumber );
			logMessage("TransactionHash: ");
			printReverseHash(t.transactionHash);
			logMessage("\r\n");
			for (uint32_t i=0; i<t.inputCount; i++)
			{
				const BlockInput &input = t.inputs[i];
				logMessage("    Input %s : ResponsScriptLength: %s TransactionIndex: %s : TransactionHash: ", formatNumber(i), formatNumber(input.responseScriptLength), formatNumber(input.transactionIndex) );

				printReverseHash(input.transactionHash);

				logMessage("\r\n");

				if ( input.transactionIndex != 0xFFFFFFFF )
				{
					const BlockTransaction *t = readSingleTransaction(input.transactionHash);
					if ( t == NULL )
					{
						logMessage("ERROR: TransactionIndex[%d] FAILED TO LOCATE TRANSACTION FOR HASH: ", input.transactionIndex );
						printReverseHash(input.transactionHash);
						logMessage("\r\n");
					}
					else
					{
						if ( input.transactionIndex < t->outputCount )
						{
							const BlockOutput &o = t->outputs[input.transactionIndex];
							if ( o.publicKey[0] )
							{
								logMessage("     Spending From Public Key: %s in the amount of: %0.4f\r\n", o.asciiAddress, (float)o.value / ONE_BTC );
							}
							else
							{
								logMessage("ERROR: No public key found for this previous output.\r\n");
							}
						}
						else
						{
							logMessage("ERROR: Invalid transaction index!\r\n");
						}
					}
				}
			}
			for (uint32_t i=0; i<t.outputCount; i++)
			{
				const BlockOutput &output = t.outputs[i];
				logMessage("    Output: %s : %f BTC : ChallengeScriptLength: %s\r\n", formatNumber(i), (float)output.value / ONE_BTC, formatNumber(output.challengeScriptLength) );
				if ( output.publicKey[0] )
				{
					logMessage("PublicKey: %s : %s\r\n", output.asciiAddress, output.keyTypeName );
				}
				else
				{
					logMessage("ERROR: Unable to derive a public key for this output!\r\n");
				}
			}
		}

		logMessage("==========================================================================================\r\n");
	}

	virtual const Block * processSingleBlock(const void *blockData,uint32_t blockLength)
	{
		const Block *ret = NULL;
		if ( blockLength < MAX_BLOCK_SIZE )
		{
			mSingleReadBlock.blockIndex = 0;
			mSingleReadBlock.blockReward = 0;
			mSingleReadBlock.totalInputCount = 0;
			mSingleReadBlock.totalOutputCount = 0;
			mSingleReadBlock.fileIndex = 0;
			mSingleReadBlock.fileOffset =  0;
			uint32_t transactionIndex=0;
			mSingleReadBlock.processBlockData(blockData,blockLength,transactionIndex);
			ret = static_cast< Block *>(&mSingleReadBlock);
		}
		return ret;
	}

	virtual const BlockTransaction *processSingleTransaction(const void *transactionData,uint32_t transactionLength)
	{
		const BlockTransaction *ret = NULL;
		if ( transactionLength < MAX_BLOCK_SIZE )
		{
			mSingleTransactionBlock.blockIndex = 0;
			mSingleTransactionBlock.blockReward = 0;
			mSingleTransactionBlock.totalInputCount = 0;
			mSingleTransactionBlock.totalOutputCount = 0;
			mSingleTransactionBlock.fileIndex = 0;
			mSingleTransactionBlock.fileOffset =  0;
			ret = mSingleTransactionBlock.processTransactionData(transactionData,transactionLength);
		}
		return ret;

	}

	virtual const BlockTransaction *readSingleTransaction(const uint8_t *transactionHash)
	{
		const BlockTransaction *ret = NULL;

		Hash256 h(transactionHash);
		FileLocation key(h,0,0,0,0);
		FileLocation *found = mTransactionMap.find(key);
		if ( found == NULL )
		{
			logMessage("ERROR: Unable to locate this transaction hash:");
			printReverseHash(transactionHash);
			logMessage("\r\n");
			return NULL;
		}
		const FileLocation &f = *found;
		uint32_t fileIndex = f.mFileIndex;
		uint32_t fileOffset = f.mFileOffset;
		uint32_t transactionLength = f.mFileLength;

		if ( fileIndex < MAX_BLOCK_FILES && mBlockChain[fileIndex] && transactionLength < MAX_BLOCK_SIZE )
		{
			FILE *fph = mBlockChain[fileIndex];
			uint32_t saveLocation = (uint32_t)ftell(fph);
			fseek(fph,fileOffset,SEEK_SET);
			uint32_t s = (uint32_t)ftell(fph);
			if ( s == fileOffset )
			{
				uint8_t *blockData = mTransactionBlockBuffer;
				size_t r = fread(blockData,transactionLength,1,fph);
				if ( r == 1 ) // if we successfully read in the entire transaction
				{
					ret = processSingleTransaction(blockData,transactionLength);
					if ( ret )
					{
						BlockTransaction *t = (BlockTransaction *)ret;
						t->transactionIndex = f.mTransactionIndex;
						t->fileIndex = fileIndex;
						t->fileOffset = fileOffset;
					}
				}
				else
				{
					assert(0);
				}
			}
			else
			{
				assert(0);
			}
			fseek(fph,saveLocation,SEEK_SET); // restore the file position back to it's previous location.
		}
		else
		{
			assert(0);
		}
		return ret;
	}

	virtual void processTransactions(const Block *block) // process the transactions in this block and assign them to individual wallets
	{
		if ( !block ) return;

		Transaction *transactions = mTransactionFactory->getTransactions(block->transactionCount);
		if ( !transactions ) return;

		mTransactionFactory->markBlock(transactions);

		for (uint32_t i=0; i<block->transactionCount; i++)
		{

			const BlockTransaction &t = block->transactions[i];
			Transaction &trans = transactions[i];
			trans.mBlock = block->blockIndex;
			trans.mTime = block->timeStamp;
			trans.mInputCount = t.inputCount;
			trans.mOutputCount = t.outputCount;

			trans.mInputs   = mTransactionFactory->getInputs(trans.mInputCount);
			trans.mOutputs  = mTransactionFactory->getOutputs(trans.mOutputCount);

			if ( trans.mInputs == NULL || trans.mOutputs == NULL )
			{
				break;
			}

			for (uint32_t i=0; i<t.outputCount; i++)
			{
				const BlockOutput &output = t.outputs[i];
				TransactionOutput &to = trans.mOutputs[i];

				uint32_t adr = 0;

				if ( output.publicKey[0] )
				{
					if ( output.keyType == BlockChain::KT_MULTISIG )
					{
						const uint8_t *adr1 = output.publicKey[0] ? &output.addresses[0].address[1] : NULL;
						const uint8_t *adr2 = output.publicKey[1] ? &output.addresses[1].address[1] : NULL;
						const uint8_t *adr3 = output.publicKey[2] ? &output.addresses[2].address[1] : NULL;
						const uint8_t *adr4 = output.publicKey[3] ? &output.addresses[3].address[1] : NULL;
						const uint8_t *adr5 = output.publicKey[4] ? &output.addresses[4].address[1] : NULL;

						uint32_t a1=0;
						uint32_t a2=0;
						uint32_t a3=0;
						uint32_t a4=0;
						uint32_t a5=0;

						if ( adr1 )
						{
							mTransactionFactory->getAddress(adr1,a1);
						}
						if ( adr2 )
						{
							mTransactionFactory->getAddress(adr2,a2);
						}
						if ( adr3 )
						{
							mTransactionFactory->getAddress(adr3,a3);
						}
						if ( adr4 )
						{
							mTransactionFactory->getAddress(adr4,a4);
						}
						if ( adr5 )
						{
							mTransactionFactory->getAddress(adr5,a5);
						}
						mTransactionFactory->getMultiSigAddress(&output.multisig.address[1],adr,a1,a2,a3,a4,a5);
					}
					else
					{
						BitcoinAddress *ba = mTransactionFactory->getAddress(&output.addresses[0].address[1],adr);
						if ( ba && output.keyType == BlockChain::KT_STEALTH )
						{
							ba->getData().mBitcoinAddressFlags|=BitcoinAddress::BAT_STEALTH; // flag it as being a stealth address
						}
						if ( ba && output.keyType == BlockChain::KT_SCRIPT_HASH )
						{
							ba->getData().mBitcoinAddressFlags|=BitcoinAddress::BAT_SCRIPT_HASH; // flag it as being a stealth address
						}

					}
				}
				to.mAddress = adr;
				to.mValue = output.value;
			}

			for (uint32_t i=0; i<t.inputCount; i++)
			{
				BlockInput &input = t.inputs[i];
				TransactionInput &tin = trans.mInputs[i];
				tin.mOutput = NULL;
				tin.mSignatureFormat = input.signatureFormat;

				if ( input.transactionIndex != 0xFFFFFFFF )
				{
					Hash256 h(input.transactionHash);
					FileLocation key(h,0,0,0,0);
					FileLocation *found = mTransactionMap.find(key);
					//assert(found);
					if ( found )
					{
						Transaction *previousTransaction = mTransactionFactory->getSingleTransaction(found->mTransactionIndex);
						if ( previousTransaction == NULL )
						{
							logMessage("ERROR: FAILED TO LOCATE TRANSACTION!\r\n");
						}
						else
						{
							assert( input.transactionIndex < previousTransaction->mOutputCount );
							if ( input.transactionIndex < previousTransaction->mOutputCount )
							{
								tin.mOutput = &previousTransaction->mOutputs[input.transactionIndex];
								input.inputValue = tin.mOutput->mValue;
								mTransactionFactory->getAddress(tin.mOutput->mAddress);
							}
						}
					}
					else
					{
						logMessage("ERROR: FAILED TO LOOKUP RESULTS FOR TRANSACTION HASH : ");
						printReverseHash(input.transactionHash);
						logMessage("\r\n");
					}
				}
			}
		}

		if ( mExportTransactions )
		{
			exportTransactions(block);
		}

	}

	virtual uint32_t gatherAddresses(uint32_t refTime)
	{
		mTransactionFactory->gatherAddresses(refTime);
		return mTransactionFactory->getAddressCount();
	}

	virtual void reportCounts(void)
	{
		logMessage("Total Blocks: %s\r\n", formatNumber(mBlockCount) );
		logMessage("Total Transactions: %s\r\n", formatNumber(mTotalTransactionCount));
		logMessage("Total Inputs: %s\r\n", formatNumber(mTotalInputCount));
		logMessage("Total Outputs: %s\r\n", formatNumber(mTotalOutputCount));
		mTransactionFactory->reportCounts();
	}

	virtual void printTransactions(uint32_t blockIndex)
	{
		mTransactionFactory->printTransactions(blockIndex);
	}

	virtual void gatherStatistics(uint32_t stime,uint32_t zombieDate,bool record_addresses)
	{
		mTransactionFactory->gatherStatistics(stime,zombieDate,record_addresses);
	}

	virtual void saveStatistics(bool record_addresses,float minBalance)
	{
		mTransactionFactory->saveStatistics(record_addresses,minBalance);
	}

	virtual void printAddresses(void)
	{
		mTransactionFactory->printAddresses();
	}

	virtual void printBlocks(void)
	{
		for (uint32_t i=0; i<mBlockCount; i++)
		{
			mTransactionFactory->printTransactions(i);
		}
	}

	bool readBlockHeader(void)
	{
		bool ok = false;
		FILE *fph = mBlockChain[mBlockIndex];
		if ( fph )
		{
			uint32_t magicID = 0;
			uint32_t lastBlockRead = (uint32_t)ftell(fph);
			size_t r = fread(&magicID,sizeof(magicID),1,fph);	// Attempt to read the magic id for the next block
			if ( r == 0 )
			{
				mBlockIndex++;	// advance to the next data file if we couldn't read any further in the current data file
				if ( openBlock() )
				{
					fph = mBlockChain[mBlockIndex];
					r = fread(&magicID,sizeof(magicID),1,fph); // if we opened up a new file; read the magic id from it's first block.
					lastBlockRead = ftell(fph);
				}
			}
			// If after reading the previous block, we did not encounter a block header, we need to scan for the next block header..
			if ( r == 1 && magicID != MAGIC_ID )
			{
				fseek(fph,lastBlockRead,SEEK_SET);
				logMessage("Warning: Missing block-header; scanning for next one.\r\n");
				uint8_t *temp = (uint8_t *)::malloc(MAX_BLOCK_SIZE);
				memset(temp,0,MAX_BLOCK_SIZE);
				uint32_t c = (uint32_t)fread(temp,1,MAX_BLOCK_SIZE,fph);
				bool found = false;
				if ( c > 0 )
				{
					for (uint32_t i=0; i<c; i++)
					{
						const uint32_t *check = (const uint32_t *)&temp[i];
						if ( *check == MAGIC_ID )
						{
							logMessage("Found the next block header after skipping: %s bytes forward in the file.\r\n", formatNumber(i) );
							lastBlockRead+=i; // advance to this location.
							found = true;
							break;
						}
					}
				}
				::free(temp);
				if ( found )
				{
					fseek(fph,lastBlockRead,SEEK_SET);
					r = fread(&magicID,sizeof(magicID),1,fph); // if we opened up a new file; read the magic id from it's first block.
					assert( magicID == MAGIC_ID );
				}

				if ( found ) // if we found it before the EOF, we are cool, otherwise, we need to advance to the next file.
				{
				}
				else
				{
					mBlockIndex++;	// advance to the next data file if we couldn't read any further in the current data file
					if ( openBlock() )
					{
						fph = mBlockChain[mBlockIndex];
						r = fread(&magicID,sizeof(magicID),1,fph); // if we opened up a new file; read the magic id from it's first block.
						if ( r == 1 )
						{
							if ( magicID != MAGIC_ID )
							{
								logMessage("Advanced to the next data file; but it does not start with a valid block.  Aborting reading the block-chain.\r\n");
								r = 0;
							}
						}
					}
					else
					{
						r = 0; // done
					}
				}
			}
			if ( r == 1 )	// Ok, this is a valid block, let's continue
			{
				BlockHeader header;
				BlockPrefix prefix;
				header.mFileIndex = mBlockIndex;
				r = fread(&header.mBlockLength,sizeof(header.mBlockLength),1,fph); // read the length of the block
				header.mFileOffset = (uint32_t)ftell(fph);
				if ( r == 1 )
				{
					assert( header.mBlockLength < MAX_BLOCK_SIZE ); // make sure the block length does not exceed our maximum expected ever possible block size
					if ( header.mBlockLength < MAX_BLOCK_SIZE )
					{
						r = fread(&prefix,sizeof(prefix),1,fph); // read the rest of the block (less the 8 byte header we have already consumed)
						if ( r == 1 )
						{
							Hash256 *blockHash = static_cast< Hash256 *>(&header);
							memcpy(header.mPreviousBlockHash,prefix.mPreviousBlock,32);
							computeSHA256((uint8_t *)&prefix,sizeof(prefix),(uint8_t *)blockHash);
							computeSHA256((uint8_t *)blockHash,32,(uint8_t *)blockHash);
							uint32_t currentFileOffset = ftell(fph); // get the current file offset.
							uint32_t advance = header.mBlockLength - sizeof(BlockPrefix);
							currentFileOffset+=advance;
							fseek(fph,currentFileOffset,SEEK_SET); // skip past the block to get to the next header.
							mLastBlockHeader = mBlockHeaderMap.insert(header);
							ok = true;
						}
					}
				}
			}
		}
		return ok;
	}

	virtual uint32_t getBlockCount(void) const
	{
		return mBlockCount;
	}

	virtual void printBlockHeaders(void)
	{
		for (uint32_t i=0; i<mBlockCount; i++)
		{
			BlockHeader &h = *mBlockHeaders[i];
			logMessage("Block #%d : prevBlockHash:", i );
			printReverseHash(h.mPreviousBlockHash);
			logMessage("\r\n");
		}
	}

	virtual uint32_t buildBlockChain(void)
	{
		if ( mScanCount )
		{

			logMessage("Found %s block headers total. %s in the last block.\r\n",
				formatNumber(mBlockHeaderMap.size()),
				formatNumber( mBlockHeaderMap.size()-mLastBlockHeaderCount) );

			logMessage("Building complete block-chain.\r\n");
			// need to count the total number of blocks...

			if ( mLastBlockHeader )
			{
				mBlockCount = 0;
				const BlockHeader *scan = mLastBlockHeader;
				while ( scan )
				{
					Hash256 prevBlock(scan->mPreviousBlockHash);
					scan = mBlockHeaderMap.find(prevBlock);
					mBlockCount++;
				}
				logMessage("Found %s blocks and skipped %s orphan blocks.\r\n", formatNumber(mBlockCount), formatNumber(mBlockHeaderMap.size()-mBlockCount));
				mBlockHeaders = new BlockHeader *[mBlockCount];
				uint32_t index = mBlockCount-1;
				scan = mLastBlockHeader;
				while ( scan )
				{
					mBlockHeaders[index] = (BlockHeader *)scan;
					Hash256 prevBlock(scan->mPreviousBlockHash);
					scan = mBlockHeaderMap.find(prevBlock);
					index--;
				}
			}
			mScanCount = 0;
		}

		return mBlockCount;
	}

	virtual bool readBlockHeaders(uint32_t maxBlock,uint32_t &blockCount)
	{
		if ( readBlockHeader() && mScanCount < maxBlock )
		{
			mScanCount++;
			blockCount = mScanCount;
			return true;	// true means there are more blocks to read..
		}

		return false;
	}

	virtual void printAddress(const char *address)
	{
		mTransactionFactory->printAddress(address);
	}

	virtual void printTopBalances(uint32_t tcount,float minBalance)
	{
		mTransactionFactory->printTopBalances(tcount,minBalance);
	}

	virtual void printOldest(uint32_t tcount,float minBalance)
	{
		mTransactionFactory->printOldest(tcount,minBalance);
	}

	virtual void zombieReport(uint32_t referenceTime,uint32_t zdays,float minBalance,BlockChain::ZombieReport &report)
	{
		mTransactionFactory->zombieReport(referenceTime,zdays,minBalance,report);
	}

	inline bool isSigHash(uint8_t c,uint32_t &flags) const
	{
		if ( c == 0x01 ) flags|=BlockChain::SF_SIGHASH_ALL;
		if ( c == 0x02 ) flags|=BlockChain::SF_SIGHASH_NONE;
		if ( c == 0x03 ) flags|=BlockChain::SF_SIGHASH_SINGLE;

		if ( c == 0x81 ) flags|=BlockChain::SF_SIGHASH_PAY_ANY_ALL;
		if ( c == 0x82 ) flags|=BlockChain::SF_SIGHASH_PAY_ANY_NONE;
		if ( c == 0x83 ) flags|=BlockChain::SF_SIGHASH_PAY_ANY_SINGLE;

		return c == 0x01 || c == 0x02 || c == 0x03 || c == 0x81 || c == 0x82 || c == 0x83;
	}

	uint32_t analyzeSignature(const uint8_t *_inputScript,uint32_t _inputLength,uint32_t transactionIndex,uint32_t inputNumber,const uint8_t *inputHash,const uint8_t *transactionHash,uint64_t value)
	{
		uint32_t ret = BlockChain::SF_ABNORMAL;


		const uint8_t *sigHash = NULL;

		bool report = false;

		if ( gBlockIndex == 278309 || gBlockIndex == 278306 )
		{
			report = true;
		}

		// Search for more than 16 characters of ASCII text in a row
		uint32_t acount = 0;
		for (uint32_t i=0; i<_inputLength; i++)
		{
			uint8_t c = _inputScript[i];
			if ( c >= 32 && c < 126 )
			{
				acount++;
				if ( acount >= 16 )
				{
					ret|=BlockChain::SF_ASCII;
					break;
				}
			}
			else
			{
				acount = 0;
			}
		}

		if ( gBlockIndex == 260788 && transactionIndex == 24 && inputNumber == 139 )
		{
			//			logMessage("debug me");
		}

		// If it's the coinbase transaction, and we accept pretty much any input as valid
		if ( transactionIndex == 0 && inputNumber == 0 )
		{
			// normal expected coinbase input...
			ret&=~BlockChain::SF_ABNORMAL; // remove the abnormal bit
			ret|= BlockChain::SF_COINBASE; // mark it as coinbase
		}
		else if ( _inputScript )
		{
			const uint8_t *inputScript = _inputScript;
			uint32_t inputLength = _inputLength;

			uint32_t keyLength = 0;

			if ( inputScript[0] == 0 ) // if it has a push-data length of zero... (essentially a no-op)
			{
				ret|=BlockChain::SF_PUSHDATA0;
				keyLength = inputScript[1];
				inputScript++;
				inputLength--;
			}

			if ( inputScript[0] < OP_PUSHDATA1 )
			{
				keyLength = inputScript[0];
			}
			else if ( inputScript[0] == OP_PUSHDATA1 )
			{
				ret|=BlockChain::SF_PUSHDATA1;
				keyLength = inputScript[1];
				inputScript++;
				inputLength--;
			}
			else if ( inputScript[0] == OP_PUSHDATA2 )
			{
				ret|=BlockChain::SF_PUSHDATA2;
				keyLength = inputScript[1];
				inputScript+=2;
				inputLength-=2;
			}

			if ( keyLength > 0 )
			{
				if ( keyLength < inputLength ) // the length of the key must be less than the length of the inputscript!
				{
					const uint8_t *scan = inputScript;
					if ( scan[1] == 0x30 ) // then it is the sequence number as we normally expect!
					{
						uint32_t sequenceLength = scan[2]; // get the sequence length.
						if ( scan[3] == 0x02 ) // it's an integer type, as expected.
						{

							uint32_t length1 = scan[4]; // get the length of the first part....

							if ( length1 == 0x1E )
							{
								ret|=BlockChain::SF_DER_X_1E;
							}
							else if ( length1 == 0x1F )
							{
								ret|=BlockChain::SF_DER_X_1F;
							}
							else if ( length1 == 0x20 )
							{
								ret|=BlockChain::SF_DER_X_20;
							}
							else if ( length1 == 0x21 )
							{
								ret|=BlockChain::SF_DER_X_21;
							}
							else
							{
								ret|=BlockChain::SF_UNUSUAL_SIGNATURE_LENGTH;
							}

							if ( length1 < sequenceLength )
							{
								scan+=5; // ok, now pointing at the first integer...
								scan+=length1;
								if ( scan[0] == 0x02 )
								{
									uint32_t length2 = scan[1]; // next integer...

									if ( length2 == 0x1E )
									{
										ret|=BlockChain::SF_DER_Y_1E;
									}
									else if ( length2 == 0x1F )
									{
										ret|=BlockChain::SF_DER_Y_1F;
									}
									else if ( length2 == 0x20 )
									{
										ret|=BlockChain::SF_DER_Y_20;
									}
									else if ( length2 == 0x21 )
									{
										ret|=BlockChain::SF_DER_Y_21;
									}
									else
									{
										ret|=BlockChain::SF_UNUSUAL_SIGNATURE_LENGTH;
									}
									scan+=2;
									scan+=length2;
									if ( (length1 + length2 + 4) == sequenceLength )
									{
										sigHash = scan;
										uint32_t scanLength = (uint32_t)(scan-inputScript);
										const uint8_t *eos = inputScript+inputLength;
										if ( scan[0] == 0x2a ) // pretty damned unsual situation!
										{
											ret|=BlockChain::SF_SIGNATURE_LEADING_STRANGE;
											while ( scan < eos && !isSigHash(scan[0],ret) )
											{
												scanLength++;
												scan++;
											}
										}
										if ( scan[0] == 0x90 && scan[1] == 00 )
										{
											ret|=BlockChain::SF_WEIRD_90_00;
											scanLength+=2;
											scan+=2;
										}
										if ( isSigHash(scan[0],ret) || scan[0] == 0x00 ) // If should end with a sequence number of 01 or 00
										{
											if ( scan[0] == 0x00 )
											{
												ret|=BlockChain::SF_SIGHASH_ZERO;
											}
											scan++;
											scanLength++;
											if ( scanLength == inputLength )
											{
												ret&=~BlockChain::SF_ABNORMAL; // accepted as a valid signature.
												ret|=BlockChain::SF_DER_ONLY;
											}
											else
											{
												while ( (scan+1) < eos && scan[0] == 0x00 && scan[1] == 0x00 )
												{
													ret|=BlockChain::SF_SIGNATURE_LEADING_ZERO;
													scan++;
													scanLength++;
												}
												if ( scan[0] == 0 && isSigHash(scan[1],ret) )
												{
													ret|=BlockChain::SF_SIGNATURE_LEADING_ZERO;
													scan++;
													scanLength++;
												}

												if ( isSigHash(scan[0],ret) )
												{
													scan++;
													scanLength++;
												}

												if ( scan[0] == 0x41 ) /// PUSHDATA41
												{
													ret|=BlockChain::SF_SIGNATURE_41;
													if ( scan[1] == 0x04 )
													{
														scanLength+=0x42;
														if ( scanLength == inputLength )
														{
															ret&=~BlockChain::SF_ABNORMAL; // accepted as a valid signature
														}
													}
												}
												else if ( scan[0] == 0x4D )
												{
													ret|=BlockChain::SF_TRANSACTION_MALLEABILITY;
													if ( scan[1] == 0x41 && scan[2] == 0x00 && scan[3] == 0x04 )
													{
														scanLength+=0x44;
														if ( scanLength == inputLength )
														{
															ret&=~BlockChain::SF_ABNORMAL; // mark it as a valid signature.
														}
													}
												}
												else if ( scan[0] == 0x21 )
												{
													ret|=BlockChain::SF_SIGNATURE_21;
													if ( scan[1] == 0x02 || scan[1] == 0x03 )
													{
														scanLength+=0x22;
														if ( scanLength == inputLength )
														{
															ret&=~BlockChain::SF_ABNORMAL; // mark it as a valid signature.
														}
													}
												}
												else
												{
													ret|=BlockChain::SF_UNUSUAL_SIGNATURE_LENGTH;
													uint32_t sigLen = scan[0]+1;
													scanLength+=sigLen;
													if ( scanLength == inputLength )
													{
														ret&=~BlockChain::SF_ABNORMAL; // mark it as a valid signature.
													}
													else if ( scanLength < inputLength )
													{
														ret|=BlockChain::SF_EXTRA_STUFF;
														ret&=~BlockChain::SF_ABNORMAL; // mark it that we 'understand' it (don't report it as unable to decode, but it's not valid either.
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}


		if ( (ret & (BlockChain::SF_ABNORMAL | BlockChain::SF_ASCII | BlockChain::SF_TRANSACTION_MALLEABILITY)) || report )
		{

			if ( gWeirdSignatureFile == NULL )
			{
				gWeirdSignatureFile = fopen ( "WeirdSignature.csv", "wb" );
				fprintf(gWeirdSignatureFile,"BlockNumber,BlockTime,TransactionHash,TransactionIndex,InputHash,InputIndex,InputLength,Value,HeaderBytes,SigBytes,SigFlags,ASCII,Hex\r\n");
			}
			if ( gAsciiSignatureFile == NULL )
			{
				gAsciiSignatureFile = fopen ( "AsciiSignature.csv", "wb" );
				fprintf(gAsciiSignatureFile,"BlockNumber,BlockTime,TransactionHash,TransactionIndex,InputHash,InputIndex,InputLength,Value,HeaderBytes,SigBytes,SigFlags,ASCII,Hex\r\n");
			}
			FILE *fph = NULL;
			if ( (ret & (BlockChain::SF_ABNORMAL | BlockChain::SF_TRANSACTION_MALLEABILITY)) || report  )
			{
				logMessage("Unusual input script: Block #%d : Transaction #%d : Input #%d : Input Length: %d\r\n", gBlockIndex, transactionIndex, inputNumber, _inputLength );
				fph = gWeirdSignatureFile;
			}
			else
			{
				fph = gAsciiSignatureFile;
			}
			if ( fph )
			{
				// Print the block #
				fprintf(fph,"%d,", gBlockIndex );
				// Print the block time
				const char *ts = getTimeString(gBlockTime);
				fprintf(fph,"\"%s\",", ts );
				// Print the transaction hash
				fprintReverseHash (fph , transactionHash);
				fprintf(fph,",");
				// Print the transaction index
				fprintf(fph,"%d,", transactionIndex ); // print the transaction index.

				// Print the input hash.
				fprintReverseHash (fph, inputHash );
				fprintf(fph,",");

				// Print the input number
				fprintf(fph,"%d,", inputNumber ); // p

				// Print the input length
				fprintf(fph,"%d,", _inputLength );

				// Print the input value (TBD)
				fprintf(fph,"%0.9f,", (float)value/ONE_BTC );

				// Print the header bytes (up to 8 of them)
				fprintf(fph,"0x");
				for (uint32_t i=0; i<_inputLength; i++)
				{
					fprintf(fph,"%02x",_inputScript[i] );
					if ( i >= 8 )
						break;
				}
				fprintf(fph,",");

				// Print the sigHash bytes, up to 8 of them.
				if ( sigHash )
				{
					fprintf(fph,"0x");
					uint32_t sigIndex = (uint32_t) (sigHash-_inputScript);
					uint32_t count = 0;
					for (uint32_t i=sigIndex; i<_inputLength; i++)
					{
						fprintf(fph,"%02x",_inputScript[i] );
						count++;
						if ( count == 8 )
						{
							break;
						}
					}
				}
				fprintf(fph,",");

				// now we print the signature flags!
				fprintf(fph,"\"");

				logSignatureFormat(ret,fph);

				fprintf(fph,"\"");
				fprintf(fph,",");

				// ok, now print ASCII text found in the signature if there is any ...
				fprintf(fph,"\"");
				if ( ret & BlockChain::SF_ASCII )
				{
					// Search for more than 16 characters of ASCII text in a row
					uint32_t acount = 0;
					for (uint32_t i=0; i<_inputLength; i++)
					{
						uint8_t c = _inputScript[i];
						if ( c >= 32 && c < 126 )
						{
							acount++;
							fprintf(fph,"%c", c );
						}
						else
						{
							if ( acount )
							{
								fprintf(fph,"~");
							}
							acount = 0;
						}
					}

				}
				fprintf(fph,"\"");
				fprintf(fph,",");

				// Finally, print out the complete hex dump of the signature!
				uint32_t count = 0;
				for (uint32_t i=0; i<_inputLength; i++)
				{
					fprintf(fph,"%02x",_inputScript[i] );
					count++;
					if ( count == 8 )
					{
						fprintf(fph," ");
						count = 0;
					}

				}

				fprintf(fph,"\r\n");
			}
		}
		return ret;
	}

	virtual void setAnalyzeInputSignatures(bool state)
	{
		mAnalyzeInputSignatures = state;
	}

	virtual void setExportTransactions(bool state)
	{
		mExportTransactions = state;
	}

	void printExportHeader(void)
	{
		if ( !mExportFile ) return;

		fprintf(mExportFile,"\r\n");
		fprintf(mExportFile,"### ");
		fprintf(mExportFile,"BlockNumber,");
		fprintf(mExportFile,"BlockTime,");
		fprintf(mExportFile,"TransactionHash,");
		fprintf(mExportFile,"TransactionSize,");
		fprintf(mExportFile,"TransactionVersionNumber,");
		fprintf(mExportFile,"InputCount,");
		fprintf(mExportFile,"OutputCount,");

		for (uint32_t i=0; i<32; i++)
		{
			fprintf(mExportFile,"Input%dKey,", i+1);
			fprintf(mExportFile,"Input%dHash,", i+1);
			fprintf(mExportFile,"Input%dAmount,", i+1);
			fprintf(mExportFile,"Input%dTransactionIndex,", i+1);
			fprintf(mExportFile,"Input%dSequenceNumber,", i+1);
			fprintf(mExportFile,"Input%dSigLength,", i+1);
			fprintf(mExportFile,"Input%dSigFormat,", i+1);

			fprintf(mExportFile,"Output%dKey,", i+1);
			fprintf(mExportFile,"Output%dValue,", i+1);
			fprintf(mExportFile,"Output%dScriptLength,", i+1);
			fprintf(mExportFile,"Output%dKeyFormat,", i+1);
		}

		fprintf(mExportFile,"\r\n");


	}

	void exportTransactions(const BlockChain::Block *block)
	{
		bool nextFile = false;

		time_t t(block->timeStamp);
		struct tm *gtm = gmtime(&t);

		if ( gtm->tm_yday != (int)mLastExportDay )
		{
			nextFile = true;
		}

		if ( nextFile )
		{
			if ( mExportFile )
			{
				fclose(mExportFile);
				mExportFile = NULL;
			}
			char scratch[512];

			if ( mLastExportTime != 0xFFFFFFFF )
			{
				time_t t(mLastExportTime);
				gtm = gmtime(&t);
			}
			sprintf(scratch,"EXPORT_%04d_%02d_%02d.csv", 1900+gtm->tm_year, gtm->tm_mon+1, gtm->tm_mday );
			mExportFile = fopen(scratch,"wb");
			if ( mExportFile )
			{
				printf("Opened transaction export file: %s\r\n", scratch );
				mLastExportTime = block->timeStamp;
				fprintf(mExportFile,"\r\n");
				fprintf(mExportFile,"\"#### BlockChain Transaction Report generated by: https://code.google.com/p/blockchain/ \"\r\n" );
				fprintf(mExportFile,"\r\n");
				fprintf(mExportFile,"\"#### Written by John W. Ratcliff mailto:jratcliffscarab@gmail.com\"\r\n" );
				fprintf(mExportFile,"\"#### Website: http://codesuppository.blogspot.com/\"\r\n" );
				fprintf(mExportFile,"\"#### TipJar Address: 1NY8SuaXfh8h5WHd4QnYwpgL1mNu9hHVBT\"\r\n" );
				fprintf(mExportFile,"\r\n");

				printExportHeader();
				mExportTransactionCount = 0;
			}
			else
			{
				printf("Failed to open transaction export file '%s'. Disk full!?\r\n", scratch );
			}
			{
				time_t t(block->timeStamp);
				struct tm *gtm = gmtime(&t);
				mLastExportDay = gtm->tm_yday;
				mLastExportTime = block->timeStamp;
			}
		}

		if ( mExportFile )
		{

			mExportTransactionCount++;

			if ( mExportTransactionCount == 40 )
			{
				mExportTransactionCount = 0;
				printExportHeader();
			}

			for (uint32_t i=0; i<block->transactionCount; i++)
			{
				BlockChain::BlockTransaction &t = block->transactions[i];

				// Print the block index
				fprintf(mExportFile,"\"%d\",", block->blockIndex );

				// Print the block time stamp
				fprintf(mExportFile,"\"%s\",", getTimeString(block->timeStamp) );

				// Print the transaction hash
				fprintf(mExportFile,"\"");
				fprintReverseHash(mExportFile,t.transactionHash);
				fprintf(mExportFile,"\",");

				// Print the transaction length
				fprintf(mExportFile,"\"%d\",", t.transactionLength );

				// Print the transaction version number.
				fprintf(mExportFile,"\"%d\",", t.transactionVersionNumber );

				// Print the input count
				fprintf(mExportFile,"\"%d\",", t.inputCount );

				// Print the output count
				fprintf(mExportFile,"\"%d\",", t.outputCount );

				uint32_t count = t.inputCount > t.outputCount ? t.inputCount : t.outputCount;

				for (uint32_t i=0; i<count; i++)
				{
					if ( i < t.inputCount )
					{
						const BlockChain::BlockInput &input = t.inputs[i];
						char scratch[256];
						scratch[0] = 0;
						uint64_t inputValue=0;
						if ( input.transactionIndex != 0xFFFFFFFF )
						{
							const BlockTransaction *t = readSingleTransaction(input.transactionHash);
							if ( t == NULL )
							{
							}
							else
							{
								if ( input.transactionIndex < t->outputCount )
								{
									const BlockOutput &o = t->outputs[input.transactionIndex];
									if ( o.publicKey[0] )
									{
										inputValue = o.value;
										strcpy(scratch,o.asciiAddress);
									}
								}
							}
						}
						// Print the public key of the input
						fprintf(mExportFile,"\"%s\",", scratch );

						// print the transaction hash of the input
						fprintf(mExportFile,"\"");
						fprintReverseHash(mExportFile,input.transactionHash);
						fprintf(mExportFile,"\",");

						// the input value
						fprintf(mExportFile,"\"%0.9f\",", (float)inputValue / ONE_BTC );

						// transaction index
						fprintf(mExportFile,"\"%d\",", input.transactionIndex );

						// sequence number
						fprintf(mExportFile,"\"%d\",", input.sequenceNumber );

						// input length
						fprintf(mExportFile,"\"%d\",", input.responseScriptLength );

						// write out the signature format
						fprintf(mExportFile,"\"");
						logSignatureFormat(input.signatureFormat,mExportFile);
						fprintf(mExportFile,"\",");

					}
					else
					{
						fprintf(mExportFile,",");
						fprintf(mExportFile,",");
						fprintf(mExportFile,",");
						fprintf(mExportFile,",");
						fprintf(mExportFile,",");
						fprintf(mExportFile,",");
						fprintf(mExportFile,",");
					}

					if ( i < t.outputCount )
					{
						const BlockChain::BlockOutput &output = t.outputs[i];

						fprintf(mExportFile,"\"%s\",", output.asciiAddress );
						fprintf(mExportFile,"\"%0.9f\",", (float)output.value / ONE_BTC );
						fprintf(mExportFile,"\"%d\",", output.challengeScriptLength );
						fprintf(mExportFile,"\"%s\",", output.keyTypeName );
					}
					else
					{
						fprintf(mExportFile,",");
						fprintf(mExportFile,",");
						fprintf(mExportFile,",");
						fprintf(mExportFile,",");
					}
				}

				fprintf(mExportFile,"\r\n");

				fflush(mExportFile);
			}
		}
	}

	void dump(float minBalance)
	{
		mTransactionFactory->dumpByBalance(minBalance);
		mTransactionFactory->dumpByAge(minBalance);
	}

	virtual uint32_t getUsage(uint32_t baseTime,uint32_t daysMin,uint32_t daysMax,uint32_t &btcTotal)
	{
		uint32_t ret = 0;

		ret = mTransactionFactory->getUsage(baseTime,daysMin,daysMax,btcTotal,0.000001f);

		return ret;
	}

	virtual void accumulateTransactionValues(const Block *b)
	{
		if ( mTransactionBlockStat.mValues == NULL )
		{
			mTransactionBlockStat.mValues = new uint64_t[MAX_TRANSACTION_STAT];
		}

		mTransactionBlockStat.mBlockCount++;
		mTransactionBlockStat.mBlockSize+=b->blockLength;


		for (uint32_t j=0; j<b->transactionCount; j++)
		{
			const BlockTransaction &t = b->transactions[j];
			mTransactionBlockStat.mInputCount+=t.inputCount;
			mTransactionBlockStat.mOutputCount+=t.outputCount;

			uint64_t inputValue=0;
			uint64_t outputValue=0;
			uint64_t coinbaseValue=0;

			for (uint32_t i=0; i<t.inputCount; i++)
			{
				BlockInput &input = t.inputs[i];
				inputValue+=input.inputValue;
			}

			for (uint32_t i=0; i<t.outputCount; i++)
			{
				BlockOutput &output = t.outputs[i];
				if ( i == 0 && j == 0 )
				{
					coinbaseValue = output.value;
				}
				outputValue+=output.value;
				if ( output.value < ONE_MBTC )
				{
					mTransactionBlockStat.mDustCount++;
				}
			}

			uint64_t ot = inputValue+coinbaseValue;
			uint64_t fees = 0;
			if ( ot > outputValue )
			{
				fees = (inputValue+coinbaseValue) - outputValue;
			}

			mTransactionBlockStat.mInputValue+=inputValue;
			mTransactionBlockStat.mOutputValue+=outputValue;
			mTransactionBlockStat.mFeeValue+=fees;
			mTransactionBlockStat.mCoinBaseValue+=coinbaseValue;

			if ( mTransactionBlockStat.mTransactionCount < MAX_TRANSACTION_STAT )
			{
				mTransactionBlockStat.mValues[mTransactionBlockStat.mTransactionCount] = outputValue+fees;
				mTransactionBlockStat.mTransactionSize+=t.transactionLength;
				mTransactionBlockStat.mTransactionCount++;
				if ( t.transactionLength > 100000 )
				{
					logMessage("TransactionHash: ");
					printReverseHash(t.transactionHash);
					logMessage(" is huge! %s bytes long.\r\n",formatNumber(t.transactionLength));
				}
			}
		}
	}

	virtual void reportTransactionValues(uint32_t date)
	{
		if ( mTransactionSizeReport == NULL )
		{
			mTransactionSizeReport = fopen("TransactionValues.csv", "wb");
			if ( mTransactionSizeReport )
			{
				fprintf(mTransactionSizeReport,"Date,InputValue,OutputValue,CoinBase,Fees,InputCount,OutputCount,BlockCount,TotalBlockSize,AverageBlockSize,TransactionCount,AverageTransactionsPerBlock,AverageTransactionSize,AverageTransactionInputCount,AverageTransactionOutputCount,DustOutputCount\r\n" );
			}
		}
		if ( mTransactionSizeReport )
		{
			fprintf(mTransactionSizeReport,"%s,", getDateString(date));
			fprintf(mTransactionSizeReport,"%0.4f,", (float)mTransactionBlockStat.mInputValue / ONE_BTC );
			fprintf(mTransactionSizeReport,"%0.4f,", (float)mTransactionBlockStat.mOutputValue / ONE_BTC );
			fprintf(mTransactionSizeReport,"%0.4f,", (float)mTransactionBlockStat.mCoinBaseValue / ONE_BTC );
			fprintf(mTransactionSizeReport,"%0.4f,", (float)mTransactionBlockStat.mFeeValue / ONE_BTC );
			fprintf(mTransactionSizeReport,"%d,", mTransactionBlockStat.mInputCount );
			fprintf(mTransactionSizeReport,"%d,", mTransactionBlockStat.mOutputCount );
			fprintf(mTransactionSizeReport,"%d,", mTransactionBlockStat.mBlockCount );
			fprintf(mTransactionSizeReport,"%d,", mTransactionBlockStat.mBlockSize );
			fprintf(mTransactionSizeReport,"%0.2f,", (float)mTransactionBlockStat.mBlockSize / (float)mTransactionBlockStat.mBlockCount );
			fprintf(mTransactionSizeReport,"%d,", mTransactionBlockStat.mTransactionCount );
			fprintf(mTransactionSizeReport,"%0.2f,", (float)mTransactionBlockStat.mTransactionCount / (float)mTransactionBlockStat.mBlockCount );
			fprintf(mTransactionSizeReport,"%0.2f,", (float)mTransactionBlockStat.mTransactionSize / (float)mTransactionBlockStat.mTransactionCount );
			fprintf(mTransactionSizeReport,"%0.2f,", (float)mTransactionBlockStat.mInputCount / (float)mTransactionBlockStat.mTransactionCount );
			fprintf(mTransactionSizeReport,"%0.2f,", (float)mTransactionBlockStat.mOutputCount / (float)mTransactionBlockStat.mTransactionCount );
			fprintf(mTransactionSizeReport,"%d,", mTransactionBlockStat.mDustCount );
			fprintf(mTransactionSizeReport,"\r\n");

			fflush(mTransactionSizeReport);
		}
		mTransactionBlockStat.init();
	}

	virtual void setZombieDays(uint32_t zombieDays)
	{
		ZOMBIE_DAYS = zombieDays;
	}

	virtual void searchForText(uint32_t textCount)
	{
		mSearchForText = textCount;
	}

	FILE						*mTransactionSizeReport;
	FILE						*mExportFile;
	uint32_t					mLastExportTime;
	uint32_t					mLastExportDay;
	uint32_t					mLastExportIndex;
	uint32_t					mExportTransactionCount;

	uint32_t					mSearchForText;
	bool						mAnalyzeInputSignatures;
	bool						mExportTransactions;

	char						mRootDir[512];					// The root directory name where the block chain is stored
	FILE						*mBlockChain[MAX_BLOCK_FILES];	// The FILE pointer reading from the current file in the blockchain
	uint32_t					mBlockIndex;					// Which index number of the block-chain file sequence we are currently reading.


	size_t						mFileLength;
	uint8_t						mBlockHash[32];	// The current blocks hash


	uint32_t					mBlockBase;	// which index we are pulling working blocks from next
	BlockImpl					mSingleReadBlock;
	BlockImpl					mSingleTransactionBlock;

	uint32_t					mReadCount;
	uint8_t						*mCurrentBlockData;
	uint8_t						mBlockDataBuffer[MAX_BLOCK_SIZE];	// Holds one block of data
	uint8_t						mTransactionBlockBuffer[MAX_BLOCK_SIZE];
	uint32_t					mTransactionCount;
	TransactionHashMap			mTransactionMap;	// A hash map to the seek file location of all transactions (by hash)
	uint32_t					mLastBlockHeaderCount;

	uint32_t					mTotalTransactionCount;
	uint32_t					mTotalInputCount;
	uint32_t					mTotalOutputCount;
	uint32_t					mScanCount;
	uint32_t					mBlockCount;
	BlockHeader					*mLastBlockHeader;
	BlockHeader					**mBlockHeaders;
	BlockHeaderMap				mBlockHeaderMap;		// A hash-map of all of the block headers
	BitcoinTransactionFactory	*mTransactionFactory;	// the factory that accumulates all transactions on a per-address basis
	TransactionBlockStat		mTransactionBlockStat;
	BitcoinAddressDataFactory	*mBitcoinAddressDataFactory;
	FILE						*mTextReport;
};


BlockChain *createBlockChain(const char *rootPath)
{
	BlockChainImpl *b = new BlockChainImpl(rootPath);
	if ( !b->isValid() )
	{
		delete b;
		b = NULL;
	}
	return static_cast<BlockChain *>(b);
}
