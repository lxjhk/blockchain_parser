#ifndef MEMORY_MAP_H

#define MEMORY_MAP_H

#include <stdint.h>

class MemoryMap
{
public:

	virtual void *getBaseAddress(void) = 0;
	virtual void release(void) = 0;

protected:
	virtual ~MemoryMap(void)
	{
	}
};


MemoryMap * createMemoryMap(const char *fileName,uint64_t size,bool createOk);


#endif
