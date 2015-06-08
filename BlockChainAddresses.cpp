#include "BlockChainAddresses.h"
#include "BitcoinAddress.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <vector>

#ifdef _MSC_VER
#pragma warning(disable:4100 4505 4996)
#endif

#define CURRENT_VERSION 1

#if 0 // Not currently being used

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



static const char *getTimeString(uint32_t timeStamp)
{
	static char scratch[1024];
	time_t t(timeStamp);
	struct tm *gtm = gmtime(&t);
	strftime(scratch, 1024, "%m/%d/%Y %H:%M:%S", gtm);
	return scratch;
}
#endif

class BlockChainAddressesImpl : public BlockChainAddresses
{
public:
	class Address
	{
	public:
		uint8_t	mAddress[20];
	};

	class Row
	{
	public:
		Row(void)
		{
			mStartTime = 0;
			mAddressCount = 0;
			mChangeAddressCount = 0;
			mDeleteAddressCount = 0;
			mNewAddresses = NULL;
			mChangedAddresses = NULL;
			mDeletedAddresses = NULL;
		}

		~Row(void)
		{
			delete []mNewAddresses;
			delete []mChangedAddresses;
			delete []mDeletedAddresses;
		}

		uint32_t							mStartTime;
		uint32_t							mAddressCount;
		uint32_t							mChangeAddressCount;
		uint32_t							mDeleteAddressCount;
		BlockChainAddresses::StatAddress	*mNewAddresses;
		BlockChainAddresses::StatAddress	*mChangedAddresses;
		uint32_t							*mDeletedAddresses;
	};

	BlockChainAddressesImpl(const char *fname)
	{
		mRowCount = 0;
		mAddressCount = 0;
		mAddresses = 0;
		mRows = 0;
		mCurrentRow = NULL;
		mCurrentRowIndex = 0;
		mCurrentRowCount = 0;
		mCurrentAddressLocation = NULL;

		FILE *fph = fopen(fname,"rb");
		if ( fph )
		{
			char headerBlock[22];
			size_t r = fread(headerBlock,sizeof(headerBlock),1,fph);	// read the block header
			if ( r == 1 )
			{
				const char *headerString = "BLOCK_CHAIN_ADDRESSES";
				if ( headerBlock[21] == 0 && strcmp(headerBlock,headerString) == 0 ) // confirm this is a valid block-header for the data file we are expecting
				{
					uint32_t version=0;
					fread(&version,sizeof(version),1,fph);
					if ( version == CURRENT_VERSION )	// Confirm this is for the same version number of this file we are one.
					{
						r = fread(&mAddressCount,sizeof(mAddressCount),1,fph);	// Read the number of unique public key addresses recorded
						if ( r == 1 )
						{
							mCurrentAddressLocation = new uint32_t[mAddressCount];
							memset(mCurrentAddressLocation,0xFF,sizeof(uint32_t)*mAddressCount);
							mAddresses = new Address[mAddressCount];
							r  = fread(mAddresses,sizeof(Address)*mAddressCount,1,fph);	// Read all of the addresses into memory.
							if ( r == 1 )
							{
								fread(&mRowCount,sizeof(mRowCount),1,fph);		// Read the number of rows (days)
								if ( mRowCount )
								{
									mRows = new Row[mRowCount];
									// For each row read the start time, the number of new addresses, the number of changed addresses, and the number of removed addresses
									// Also allocate memory to hold the change data
									for (uint32_t i=0; i<mRowCount; i++)
									{
										Row &row = mRows[i];
										fread(&row.mStartTime,sizeof(row.mStartTime),1,fph);
										fread(&row.mAddressCount,sizeof(row.mAddressCount),1,fph);
										fread(&row.mChangeAddressCount,sizeof(row.mChangeAddressCount),1,fph);
										fread(&row.mDeleteAddressCount,sizeof(row.mDeleteAddressCount),1,fph);
										if ( row.mAddressCount )
										{
											row.mNewAddresses = new BlockChainAddresses::StatAddress[row.mAddressCount];
										}
										if ( row.mChangeAddressCount )
										{
											row.mChangedAddresses = new BlockChainAddresses::StatAddress[row.mChangeAddressCount];
										}
										if ( row.mDeleteAddressCount )
										{
											row.mDeletedAddresses = new uint32_t[row.mDeleteAddressCount];
										}
									}
									// Now for each row, read the new address data, the change address data, and the deleted address data
									for (uint32_t i=0; i<mRowCount; i++)
									{
										Row &row = mRows[i];
										if ( row.mNewAddresses )
										{
											fread(row.mNewAddresses,sizeof(BlockChainAddresses::StatAddress)*row.mAddressCount,1,fph);
#ifdef _DEBUG
											for (uint32_t i=0; i<row.mAddressCount; i++)
											{
												StatAddress &a = row.mNewAddresses[i];
												assert( a.mAddress != 0 && a.mAddress <= mAddressCount );
											}
#endif
										}
										if ( row.mChangedAddresses )
										{
											fread(row.mChangedAddresses,sizeof(BlockChainAddresses::StatAddress)*row.mChangeAddressCount,1,fph);
#ifdef _DEBUG
											for (uint32_t i=0; i<row.mChangeAddressCount; i++)
											{
												StatAddress &a = row.mChangedAddresses[i];
												assert( a.mAddress != 0 && a.mAddress <= mAddressCount );
											}
#endif
										}
										if ( row.mDeletedAddresses )
										{
											fread(row.mDeletedAddresses,sizeof(uint32_t)*row.mDeleteAddressCount,1,fph);
#ifdef _DEBUG
											for (uint32_t i=0; i<row.mDeleteAddressCount; i++)
											{
												assert( row.mDeletedAddresses[i] != 0 && row.mDeletedAddresses[i] <= mAddressCount );
											}
#endif
										}
									}
									printf("Loaded %d rows from the recording file.\r\n", mRowCount );
								}
								else
								{
									printf("Failed to read the row counter.\r\n");
								}
							}
							else
							{
								printf("Failed to read public-key addresses.\r\n");
							}
						}
						else
						{
							printf("Failed to read address count.\r\n");
						}
					}
				}
				else
				{
					printf("Invalid header block.\r\n");
				}
			}
			else
			{
				printf("Failed to read header block!\r\n");
			}
			fclose(fph);
		}
		else
		{
			printf("Failed to open BitcoinAddress file: %s\r\n", fname );
		}
#if 0
		for (uint32_t i=0; i<mRowCount; i++)
		{
			seekNextRow();
		}
#endif
	}

	virtual ~BlockChainAddressesImpl(void)
	{
		delete []mCurrentAddressLocation;
		delete []mAddresses;
		delete []mRows;
		delete []mCurrentRow;
	}

	const char *getKey(uint32_t a) const
	{
		static char scratch[256];
		const char *ret = "UNKNOWN ADDRESS";
		assert(a);
		assert( (a-1) < mAddressCount );
		if ( a && (a-1) < mAddressCount )
		{
			Address *ba = &mAddresses[a-1];
			uint8_t address1[25];
			bitcoinRIPEMD160ToAddress((const uint8_t *)ba,address1);
			bitcoinAddressToAscii(address1,scratch,256);
			ret = scratch;
		}
		return ret;
	}


	virtual void		printRow(void) 				// Print out for debugging purposes the data in this current row
	{
		if ( !mCurrentRow ) return;
		if ( mCurrentRowIndex > 0 && mCurrentRowIndex < mRowCount )
		{
			Row &row = mRows[mCurrentRowIndex-1];
			printf("Row: %d\r\n", mCurrentRowIndex );
			printf("%d new addresses.\r\n", row.mAddressCount );
			printf("%d changed addresses.\r\n", row.mChangeAddressCount );
			printf("%d deleted addresses.\r\n", row.mDeleteAddressCount );
			printf("Row has %d addresses with a balance of one bitcoin or more.\r\n", mCurrentRowCount );
			for (uint32_t i=0; i<mCurrentRowCount; i++)
			{
				StatAddress &sa = mCurrentRow[i];
				printf("%s : %d\r\n", getKey(sa.mAddress), sa.getBalance() );
			}
		}
	}

	virtual uint32_t seekNextRow(void)
	{
		if ( mCurrentRowIndex >= mRowCount ) return mCurrentRowIndex;
		Row &row = mRows[mCurrentRowIndex];
		if ( mCurrentRow == NULL )
		{
			if ( row.mAddressCount )
			{
				mCurrentRow = new StatAddress[row.mAddressCount];
				for (uint32_t i=0; i<row.mAddressCount; i++)
				{
					StatAddress &dest = mCurrentRow[i];
					StatAddress &from = row.mNewAddresses[i];
					dest = from;
					assert( dest.mAddress != 0 && dest.mAddress <= mAddressCount );
					mCurrentAddressLocation[dest.mAddress-1] = i;
				}
				mCurrentRowCount = row.mAddressCount;
			}
		}
		else
		{
			typedef std::vector< StatAddress > StatAddressVector;
			StatAddressVector changeNew;
			if ( row.mChangeAddressCount )
			{
				for (uint32_t i=0; i<row.mChangeAddressCount; i++)
				{
					StatAddress &source = row.mChangedAddresses[i];
					assert( source.mAddress != 0 && source.mAddress <= mAddressCount );
					uint32_t index = mCurrentAddressLocation[source.mAddress-1];
					if ( index < mCurrentRowCount )
					{
						mCurrentRow[index] = source; // update the address
					}
					else
					{
						printf("Warning: %s\r\n", getKey(source.mAddress));
						changeNew.push_back(source);
					}
				}
			}
			// For each deleted address
			if ( row.mDeleteAddressCount )
			{
				for (uint32_t i=0; i<row.mDeleteAddressCount; i++)
				{
					uint32_t adr = row.mDeletedAddresses[i];			// Get the address which was deleted.
					assert( adr != 0 && adr <= mAddressCount );
					uint32_t index = mCurrentAddressLocation[adr-1];	// Look up the current location for this address.
					assert( index < mCurrentRowCount );
					mCurrentRow[index].mAddress = 0xFFFFFFFF; // make it as a deleted item
					mCurrentAddressLocation[adr-1] = 0xFFFFFFFF; // mark it as deleted!
				}
			}
			uint32_t newRowCount = mCurrentRowCount + row.mAddressCount - row.mDeleteAddressCount + (uint32_t)changeNew.size();
			StatAddress *newRows = new StatAddress[newRowCount];
			uint32_t destIndex = 0;
			for (uint32_t i=0; i<mCurrentRowCount; i++)
			{
				StatAddress &source = mCurrentRow[i];
				if ( source.mAddress != 0xFFFFFFFF ) // if not deleted..
				{
					newRows[destIndex] = source;
					assert( source.mAddress != 0 && source.mAddress <= mAddressCount );
					mCurrentAddressLocation[source.mAddress-1] = destIndex;
					destIndex++;
				}
			}
			for (uint32_t i=0; i<row.mAddressCount; i++)
			{
				StatAddress &source = row.mNewAddresses[i];
				newRows[destIndex] = source;
				assert( source.mAddress != 0 && source.mAddress <= mAddressCount );
				mCurrentAddressLocation[source.mAddress-1] = destIndex;
				destIndex++;
			}
			for (uint32_t i=0; i<changeNew.size(); i++)
			{
				StatAddress &source = changeNew[i];
				newRows[destIndex] = source;
				assert( source.mAddress != 0 && source.mAddress <= mAddressCount );
				mCurrentAddressLocation[source.mAddress-1] = destIndex;
				destIndex++;
			}
			assert( destIndex == newRowCount );
			delete []mCurrentRow;
			mCurrentRow = newRows;
			mCurrentRowCount = destIndex;
		}
		mCurrentRowIndex++;
		return mCurrentRowIndex;
	}

	virtual bool		seekRow(uint32_t index)	// Seek the file to this row location.
	{
		bool ret = false;

		if ( index >= mRowCount ) return false;

		if ( index == (mCurrentRowIndex+1) )
		{
			seekNextRow();
		}
		else
		{
			if ( index < mCurrentRowIndex )
			{
				mCurrentRowIndex = 0;
				delete []mCurrentRow;
				mCurrentRow = NULL;
				seekNextRow();
				for (uint32_t i=1; i<=index; i++)
				{
					seekNextRow();
				}
			}
			else
			{
				if ( index > mRowCount )
				{
					index = mRowCount;
				}
				while ( index != mCurrentRowIndex )
				{
					uint32_t before = mCurrentRowIndex;
					seekNextRow();
					if ( mCurrentRowIndex == before )
					{
						break;
					}
				}
			}
		}
		return ret;
	}

	virtual uint32_t	getRowCount(void) const	// return the number of rows found in the file.
	{
		return mRowCount;
	}

	virtual void		release(void)				// release the interface
	{
		delete this;
	};

	virtual const StatAddress *getRow(uint32_t &scount)
	{
		scount = mCurrentRowCount;
		return mCurrentRow;
	}

	uint32_t	mAddressCount;
	Address		*mAddresses;
	uint32_t	mRowCount;
	Row			*mRows;
	uint32_t	 mCurrentRowIndex;
	uint32_t	 mCurrentRowCount;
	StatAddress	*mCurrentRow;
	uint32_t	*mCurrentAddressLocation;
};


BlockChainAddresses *createBlockChainAddresses(const char *fname)
{
	BlockChainAddressesImpl *b = new BlockChainAddressesImpl(fname);
	return static_cast< BlockChainAddresses *>(b);
}
