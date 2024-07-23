#include "polyhook2/FBAllocator.hpp"
#include "polyhook2/PolyHookOsIncludes.hpp"

void* ALLOC_NewBlock(ALLOC_Allocator* alloc);
void ALLOC_Push(ALLOC_Allocator* alloc, void* pBlock);
void* ALLOC_Pop(ALLOC_Allocator* alloc);

//----------------------------------------------------------------------------
// ALLOC_NewBlock
//----------------------------------------------------------------------------
void* ALLOC_NewBlock(ALLOC_Allocator* self)
{
    ALLOC_Block* pBlock = nullptr;

    // If we have not exceeded the pool maximum
    if (self->poolIndex < self->maxBlocks)
    {
        // Get pointer to a new fixed memory block within the pool
        pBlock = (ALLOC_Block*)(self->pPool + (self->poolIndex++ * self->blockSize));
    }

    return pBlock;
}

//----------------------------------------------------------------------------
// ALLOC_Push
//----------------------------------------------------------------------------
void ALLOC_Push(ALLOC_Allocator* self, void* pBlock)
{
    if (!pBlock)
        return;

    // Get a pointer to the client's location within the block
    auto pClient = static_cast<ALLOC_Block*>(pBlock);

    // Point client block's next pointer to head
    pClient->pNext = self->pHead;

    // The client block is now the new head
    self->pHead = pClient;
}

//----------------------------------------------------------------------------
// ALLOC_Pop
//----------------------------------------------------------------------------
void* ALLOC_Pop(ALLOC_Allocator* self)
{
    ALLOC_Block* pBlock = nullptr;

    // Is the free-list empty?
    if (self->pHead)
    {
        // Remove the head block
        pBlock = self->pHead;

        // Set the head to the next block
        self->pHead = static_cast<ALLOC_Block*>(self->pHead->pNext);
    }

    return pBlock;
}

//----------------------------------------------------------------------------
// ALLOC_Alloc
//----------------------------------------------------------------------------
void* ALLOC_Alloc(ALLOC_HANDLE hAlloc, size_t size)
{
    ALLOC_Allocator* self = nullptr;
    void* pBlock = nullptr;

    assert(hAlloc);

    // Convert handle to an ALLOC_Allocator instance
    self = static_cast<ALLOC_Allocator*>(hAlloc);

    // Ensure requested size fits within memory block
    assert(size <= self->blockSize);

    // Get a block from the free-list
    pBlock = ALLOC_Pop(self);

    // If the free-list empty?
    if (!pBlock)
    {
        // Get a new block from the pool
        pBlock = ALLOC_NewBlock(self);
    }

    if (pBlock)
    {
        // Keep track of usage statistics
        self->allocations++;
        self->blocksInUse++;
        if (self->blocksInUse > self->maxBlocksInUse)
        {
            self->maxBlocksInUse = self->blocksInUse;
        }
    }
    return pBlock;
}

//----------------------------------------------------------------------------
// ALLOC_Calloc
//----------------------------------------------------------------------------
void* ALLOC_Calloc(ALLOC_HANDLE hAlloc, size_t num, size_t size)
{
    void* pMem = nullptr;
    size_t n = 0;

    assert(hAlloc);

    // Compute the total size of the block
    n = num * size;

    // Allocate the memory
    pMem = ALLOC_Alloc(hAlloc, n);

    if (pMem)
    {
        memset(pMem, 0, n);
    }
    return pMem;
}

//----------------------------------------------------------------------------
// ALLOC_Free
//----------------------------------------------------------------------------
void ALLOC_Free(ALLOC_HANDLE hAlloc, void* pBlock)
{
    ALLOC_Allocator* self = nullptr;

    if (!pBlock)
        return;

    assert(hAlloc);

    // Cast handle to an allocator instance
    self = static_cast<ALLOC_Allocator*>(hAlloc);

    // Push the block onto a stack (i.e. the free-list)
    ALLOC_Push(self, pBlock);

    // Keep track of usage statistics
    self->deallocations++;
    self->blocksInUse--;
}
