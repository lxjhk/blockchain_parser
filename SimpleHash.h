#ifndef SIMPLE_HASH_H
#define SIMPLE_HASH_H

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <new>

#define USE_MEMORY_MAP 0

#if USE_MEMORY_MAP
#include "MemoryMap.h"
#endif

template < class Key,
	uint32_t hashTableSize = 8192,		// *MUST* be a power of 2!
	uint32_t hashTableEntries = 2048 >

class SimpleHash
{
public:
	class HashEntry
	{
	public:
		HashEntry(void)
		{
			mNext = NULL;
		}
		Key			mKey;
		HashEntry*	mNext;
	};

	inline bool empty(void) const
	{
		return mHashTableCount ? true : false;
	}

	SimpleHash(void)
	{
		mMemoryMapFileName = NULL;
#if USE_MEMORY_MAP
		mMemoryMap = NULL;
#endif
		mEntries = NULL;
		mHashTableCount = 0;
		for (uint32_t i = 0; i < hashTableSize; i++)
		{
			mHashTable[i] = NULL;
		}
	}

	inline void init(void)
	{
		assert( mMemoryMapFileName );
		if ( mEntries == NULL )
		{
#if USE_MEMORY_MAP
			uint64_t size = sizeof(HashEntry)*hashTableEntries;
			mMemoryMap = createMemoryMap(mMemoryMapFileName,size,true);
			assert( mMemoryMap );
			if ( mMemoryMap )
			{
				mEntries = (HashEntry *)mMemoryMap->getBaseAddress();
			}
			else
			{
				printf("Failed to allocate memory for hashmap %s. Exiting\r\n", mMemoryMapFileName);
				exit(1);
			}
#else
			uint64_t size = sizeof(HashEntry)*hashTableEntries;
			uint64_t mb = size / (1024*1024);
			printf("Allocating %d MB of memory for %s\r\n", (uint32_t)mb, mMemoryMapFileName );
			mEntries = (HashEntry *)malloc(size);
			if ( mEntries == NULL )
			{
				printf("Failed to allocate memory for hashmap %s. Exiting\r\n", mMemoryMapFileName);
				exit(1);
			}
#endif
		}
	}

	~SimpleHash(void)
	{
#if USE_MEMORY_MAP
		if ( mMemoryMap )
		{
			mMemoryMap->release();
		}
#else
		free(mEntries);
#endif
	}

	inline uint32_t getIndex(const Key *k) const
	{
		assert(k);
		HashEntry *h = (HashEntry *)k;
		return (uint32_t)(h-mEntries);
	}

	inline Key * getKey(uint32_t i) const
	{
		Key *ret = NULL;
		assert( i < mHashTableCount );
		if ( i < mHashTableCount )
		{
			ret = &mEntries[i].mKey;
		}
		return ret;
	}

	inline Key* find(const Key& key)  const
	{
		Key* ret = NULL;
		uint32_t hash = getHash(key);
		HashEntry* h = mHashTable[hash];
		while (h)
		{
			if (h->mKey == key)
			{
				ret = &h->mKey;
				break;
			}
			h = h->mNext;
		}
		return ret;
	}

	// Inserts are not thread safe; use a mutex
	inline Key * insert(const Key& key)
	{
		Key *ret = NULL;
		init(); // allocate the entries table
		if (mHashTableCount < hashTableEntries)
		{
			HashEntry* h = &mEntries[mHashTableCount];
			new ( h ) HashEntry;
			h->mKey = key;
			ret = &h->mKey;
			mHashTableCount++;
			uint32_t hash = getHash(key);
			if (mHashTable[hash])
			{
				HashEntry* next = mHashTable[hash];
				mHashTable[hash] = h;
				h->mNext = next;
			}
			else
			{
				mHashTable[hash] = h;
			}
		}
		else
		{
			assert(0); // we should never run out of hash entries
			printf("Overflowed hash table for hashmap %s.\n", mMemoryMapFileName);
			exit(1);
		}
		return ret;
	}

	inline uint32_t size(void) const
	{
		return mHashTableCount;
	}

	void setMemoryMapFileName(const char *f)
	{
		mMemoryMapFileName = f;
	}
private:

	inline uint32_t getHash(const Key& key) const
	{
		return key.getHash() & (hashTableSize - 1);
	}


	HashEntry		*mHashTable[hashTableSize];
	unsigned int	mHashTableCount;
	HashEntry		*mEntries;
	const char		*mMemoryMapFileName;
#if USE_MEMORY_MAP
	MemoryMap		*mMemoryMap;
#endif
};


#endif
