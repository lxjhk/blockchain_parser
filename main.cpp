#include "BlockChain.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <float.h>
#include <math.h>
#include <time.h>

#ifdef WIN32
#include <conio.h>
#endif

#include "HeapSort.h"

#ifdef _MSC_VER
#pragma warning(disable:4996 4702 4505)
#endif

time_t zombieDate(0x510B56CB); // right around January 1, 2013

static bool isESC(void)
{
	bool ret = false;

#ifdef _MSC_VER
	if ( kbhit() )
	{
		int c = getch();
		if ( c == 27 )
		{
			return true;
		}
	}
#endif

	return ret;
}

enum StatResolution
{
	SR_DAY,
	SR_MONTH,
	SR_YEAR,
	SR_LAST
};

enum CommandMode
{
	CM_NONE,	//
	CM_SCAN,	// scanning.
	CM_PROCESS,
	CM_EXIT
};

class BlockChainCommand
{
public:
	BlockChainCommand(const char *dataPath,
						uint32_t maxBlock,
						bool processTransactions,
						StatResolution resolution,
						uint32_t searchText,
						uint32_t zombieDays)
	{
		mTransactionValue = true;
		mAnalyze = false;
		mExportTransactions = false;
		mBlockChain = createBlockChain(dataPath);	// Create the block-chain parser using this root path
		mZombieDays = zombieDays;
		mSearchText = searchText;
		if ( mBlockChain )
		{
			mBlockChain->searchForText(mSearchText);
			mBlockChain->setZombieDays(mZombieDays);
		}
		mStatResolution = resolution;
		mMaxBlock = maxBlock;

		printf("Running the BlockChain parser.  Written by John W. Ratcliff on January 4, 2014 : TipJar: 1NY8SuaXfh8h5WHd4QnYwpgL1mNu9hHVBT\r\n");
		printf("Registered DataDirectory: %s to scan for the blockchain.\r\n", dataPath );
		printf("\r\n");
		printf("You may press the ESC key to cleanly exit the processing wherever it is at currently.\r\n");
		printf("\r\n");
		mProcessTransactions = processTransactions;
		mProcessBlock = 0;
		mLastBlockScan = 0;
		mLastBlockPrint = 0;
		mFinishedScanning = false;
		mCurrentBlock = NULL;
		mLastTime = 0;
		mSatoshiTime = 0;
		mMinBalance = 1;
		mRecordAddresses = false;
		mMode = CM_SCAN;

		if ( mBlockChain == NULL )
		{
			printf("Failed to open file: blk00000.dat in directory: %s\r\n", dataPath );
			mMode = CM_EXIT;
		}
	}

	~BlockChainCommand(void)
	{
		if ( mBlockChain )
		{
			mBlockChain->release();
		}
	}

	bool process(void)
	{
		switch ( mMode )
		{
			case CM_PROCESS:
				if ( mProcessBlock < mBlockChain->getBlockCount() && !isESC() )
				{
					mCurrentBlock = mBlockChain->readBlock(mProcessBlock);
					if ( mCurrentBlock )
					{
						if ( mLastTime == 0 )
						{
							mLastTime = mCurrentBlock->timeStamp;
							mSatoshiTime = mCurrentBlock->timeStamp;
						}
						else
						{
							uint32_t currentTime = mCurrentBlock->timeStamp;

							time_t tnow(currentTime);
							struct tm beg;
							beg = *localtime(&tnow);

							time_t tbefore(mLastTime);
							struct tm before;
							before = *localtime(&tbefore);

							bool getStats = false;

							switch ( mStatResolution )
							{
								case SR_DAY:
									if ( beg.tm_yday != before.tm_yday && currentTime > mLastTime )
									{
										getStats = true;
									}
									break;
								case SR_MONTH:
									if ( beg.tm_mon != before.tm_mon  && currentTime > mLastTime )
									{
										getStats = true;
									}
									break;
								case SR_YEAR:
									if ( beg.tm_year != before.tm_year  && currentTime > mLastTime )
									{
										getStats = true;
									}
									break;
                                default:
                                    break;
							}
							if ( getStats )
							{
								if ( mProcessTransactions )
								{
									const char *months[12] = { "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December" };
									printf("Gathering statistics for %s %d, %d to %s %d, %d\r\n",
										months[before.tm_mon], before.tm_mday, before.tm_year+1900,
										months[beg.tm_mon], beg.tm_mday, beg.tm_year+1900);
									mBlockChain->gatherStatistics(mLastTime,(uint32_t)zombieDate,mRecordAddresses);
								}

								if ( mTransactionValue )
								{
									mBlockChain->reportTransactionValues(mLastTime);
								}

								mLastTime = currentTime;

							}
						}

						if ( mProcessTransactions )
						{
							mBlockChain->processTransactions(mCurrentBlock);  // process transactions into individual addresses
						}

						if ( mTransactionValue )
						{
							mBlockChain->accumulateTransactionValues(mCurrentBlock);
						}

					}
					mProcessBlock++;
					if ( (mProcessBlock%1000) == 0 )
					{
						printf("Processed block #%d of %d total.\r\n", mProcessBlock, mBlockChain->getBlockCount() );
					}
				}
				else
				{
					printf("Finished processing all blocks in the blockchain.\r\n");
					mBlockChain->reportCounts();
					if ( mProcessTransactions )
					{
						printf("Gathering final statistics.\r\n");
						mBlockChain->gatherStatistics(mLastTime,(uint32_t)zombieDate,mRecordAddresses);
						printf("Saving statistics to file 'stats.csv\r\n");
						mBlockChain->saveStatistics(mRecordAddresses,mMinBalance);
					}
					mMode = CM_EXIT;
					mProcessBlock = 0;
				}
				break;
			case CM_SCAN:
				if ( isESC() )
				{
					mMode = CM_EXIT;
					printf("ESC hit, exiting before processing any blocks.\r\n");
				}
				else
				{
					bool ok = mBlockChain->readBlockHeaders(mMaxBlock,mLastBlockScan);
					if ( !ok )
					{
						mFinishedScanning = true;
						mMode = CM_PROCESS; // done scanning.
						mLastBlockScan = mBlockChain->buildBlockChain();
						printf("Finished scanning block headers. Built block-chain with %d blocks found..\r\n", mLastBlockScan);
					}
				}
				break;
            default:
                break;
		}
		return mMode != CM_EXIT;
	}

	const BlockChain::Block *getBlock(uint32_t index)
	{
		mCurrentBlock = mBlockChain->readBlock(index);
		return mCurrentBlock;
	}

	void setMaxBlocks(uint32_t maxBlocks)
	{
		mMaxBlock = maxBlocks;
	}

	CommandMode				mMode;
	bool					mExportTransactions;
	bool					mAnalyze;
	bool					mRecordAddresses;
	bool					mFinishedScanning;
	bool					mProcessTransactions;
	StatResolution			mStatResolution;
	uint32_t				mProcessBlock;
	uint32_t				mMaxBlock;
	uint32_t				mLastBlockScan;
	uint32_t				mLastBlockPrint;
	const BlockChain::Block	*mCurrentBlock;
	BlockChain				*mBlockChain;
	uint32_t				mLastTime;
	uint32_t				mSatoshiTime;
	float					mMinBalance;
	bool					mTransactionValue;
	uint32_t				mZombieDays;
	uint32_t				mSearchText;
};


int main(int argc,const char **argv)
{
	if ( argc < 2 )
	{
		printf("Usage: blockchain (options) <dataDir>\n");
		printf("\n");
		printf("Options:\n");
		printf("\n");
		printf("-max_blocks <n> : Maximum number of blocks in the blockchain to analyze\n");
		printf("-statistics : Whether or not to perform full statistics processing of every single address\n");
		printf("-by_day : Accumulate breakdown of all bitcoin addresses by day\n");
		printf("-by_month : Accumulate breakdown of all bitcoin addresses by month\n");
		printf("-by_year : Accumulate breakdown of all bitcoin addresses by year\n");
		printf("-zombie_days <n> : Number of days to consider a bitcoin address as a zombie, default value is 3 years.\n");
		printf("-transactions_only : Don't accumulate full statistics, just report transaction data.\n");
		printf("-find_text <n> : Search for occurrences of ASCII text in the blockchain and output it to the log file. <n> is how many ASCII characters in a row to report text.\n");
	}
	else
	{
		uint32_t zombieDays = 365*3;
		uint32_t maxBlocks = 10000000;
		const char *dataPath = ".";
		int i = 1;
		StatResolution resolution = SR_YEAR;
		bool processTransactions = false;
		bool transactionsOnly = false;
		uint32_t searchText = 0;

		while ( i < argc )
		{
			const char *option = argv[i];
			if ( *option == '-' )
			{
				if ( strcmp(option,"-max_blocks") == 0 )
				{
					i++;
					if ( i < argc )
					{
						maxBlocks = atoi(argv[i]);
						if ( maxBlocks < 1 )
						{
							printf("Invalid max_blocks value '%s'\n", argv[i] );
							maxBlocks = 1000000;
						}
						else
						{
							printf("Maximum blocks set to %d\r\n", maxBlocks);
						}
					}
					else
					{
						printf("Error parsing option '-max_blocks', missing block number.\n");
					}
				}
				else if ( strcmp(option,"-transactions_only") == 0 )
				{
					transactionsOnly = true;
					printf("Will only process transactions but not full statistics.\r\n");
				}
				else if ( strcmp(option,"-statistics") == 0 )
				{
					processTransactions = true;
					printf("Enabling statistics processing\r\n");
				}
				else if ( strcmp(option,"-by_day") == 0 )
				{
					resolution = SR_DAY;
					processTransactions = true;
					printf("Gathering statistics by day\n");
				}
				else if ( strcmp(option,"-by_month") == 0 )
				{
					resolution = SR_MONTH;
					processTransactions = true;
					printf("Gathering statistics by month\n");
				}
				else if ( strcmp(option,"-by_year") == 0 )
				{
					resolution = SR_YEAR;
					processTransactions = true;
					printf("Gathering statistics by year\n");
				}
				else if ( strcmp(option,"-find_text") == 0 )
				{
					i++;
					if ( i < argc )
					{
						searchText = atoi(argv[i]);
						printf("Searching for ASCII text in the blockchain using a character limit of %d\n", searchText );
					}
					else
					{
						printf("Error parsing option '-find_text', missing character length.\n");
					}
				}
				else if ( strcmp(option,"-zombie_days") == 0 )
				{
					i++;
					if ( i < argc )
					{
						zombieDays = atoi(argv[i]);
						printf("Zombie Days set to %d\n", zombieDays );
					}
					else
					{
						printf("Error parsing option '-zombie_days', missing day count.\n");
					}
				}
				else
				{
					printf("Unknown option '%s'\n", option );
				}
			}
			else
			{
				if ( (i+1) == argc )
				{
					printf("Using directory: %s to locate bitcoin data blocks.\n", option );
					dataPath = option;
				}
				else
				{
					printf("%s not a valid option.\n", option );
				}
			}
			i++;
		}
		if ( transactionsOnly )
		{
			processTransactions = false;
		}
		BlockChainCommand bc(dataPath,maxBlocks,processTransactions,resolution,searchText,zombieDays);
		bc.setMaxBlocks(maxBlocks);
		while ( bc.process() );
	}


	return 0;
}
