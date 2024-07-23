#include "polyhook2/RangeAllocator.hpp"
#include "polyhook2/PolyHookOsIncludes.hpp"

PLH::FBAllocator::FBAllocator(uint64_t min, uint64_t max, uint8_t blockSize, uint8_t blockCount) : m_allocator(nullptr),
    m_hAllocator(nullptr)
{
    m_min = min;
    m_max = max;
    m_dataPool = 0;
    m_maxBlocks = blockCount;
    m_usedBlocks = 0;
    m_blockSize = blockSize;
    m_alloc2Supported = boundedAllocSupported();
}

PLH::FBAllocator::~FBAllocator()
{
    uint64_t freeSize = 0;

    if (m_allocator)
    {
        freeSize = m_allocator->blockSize * m_allocator->maxBlocks;
        delete m_allocator;
        m_allocator = nullptr;
        m_hAllocator = nullptr;
    }

    if (m_dataPool)
    {
        boundAllocFree(m_dataPool, freeSize);
        m_dataPool = 0;
    }
}

bool PLH::FBAllocator::initialize()
{
    const uint64_t alignment = getAllocationAlignment();
    const uint64_t start = AlignUpwards(m_min, static_cast<size_t>(alignment));
    const uint64_t end = AlignDownwards(m_max, static_cast<size_t>(alignment));

    if (m_alloc2Supported)
    {
        // alignment shrinks area by aligning both towards middle so we don't allocate beyond the given bounds
        m_dataPool = boundAlloc(start, end, ALLOC_BLOCK_SIZE(m_blockSize) * static_cast<uint64_t>(m_maxBlocks));
        if (!m_dataPool)
        {
            return false;
        }
    }
    else
    {
        m_dataPool = boundAllocLegacy(start, end, ALLOC_BLOCK_SIZE(m_blockSize) * static_cast<uint64_t>(m_maxBlocks));
        if (!m_dataPool)
        {
            return false;
        }
    }

    m_allocator = new ALLOC_Allocator{
        "PLH", (char*)m_dataPool,
        m_blockSize, ALLOC_BLOCK_SIZE(m_blockSize), m_maxBlocks, nullptr, 0, 0, 0, 0, 0
    };
    if (!m_allocator)
    {
        return false;
    }

    m_hAllocator = m_allocator;
    return true;
}

char* PLH::FBAllocator::allocate()
{
    if (m_usedBlocks + 1 == m_maxBlocks)
    {
        return nullptr;
    }
    m_usedBlocks++;
    return static_cast<char*>(ALLOC_Alloc(m_hAllocator, m_blockSize));
}

char* PLH::FBAllocator::callocate(uint8_t num)
{
    m_usedBlocks += num;
    return static_cast<char*>(ALLOC_Calloc(m_hAllocator, num, m_blockSize));
}

void PLH::FBAllocator::deallocate(char* mem)
{
    m_usedBlocks--;
    ALLOC_Free(m_hAllocator, mem);
}

bool PLH::FBAllocator::inRange(uint64_t addr)
{
    if (addr >= m_min && addr < m_max)
    {
        return true;
    }
    return false;
}

bool PLH::FBAllocator::intersectsRange(uint64_t min, uint64_t max)
{
    const uint64_t _min = std::max(m_min, min);
    const uint64_t _max = std::min(m_max, max);
    if (_min <= _max)
        return true;
    return false;
}

uint8_t PLH::FBAllocator::intersectionLoadFactor(uint64_t min, uint64_t max)
{
    assert(intersectsRange(min, max));
    const uint64_t _min = std::max(m_min, min);
    const uint64_t _max = std::min(m_max, max);
    const double intersectLength = static_cast<double>(_max - _min);
    return static_cast<uint8_t>((intersectLength / (max - min)) * 100.0);
}

PLH::RangeAllocator::RangeAllocator(uint8_t blockSize, uint8_t blockCount)
{
    m_maxBlocks = blockCount;
    m_blockSize = blockSize;
}

std::shared_ptr<PLH::FBAllocator> PLH::RangeAllocator::findOrInsertAllocator(uint64_t min, uint64_t max)
{
    for (auto& allocator : m_allocators)
    {
        if (allocator->inRange(min) && allocator->inRange(max - 1))
        {
            return allocator;
        }
    }

    auto allocator = std::make_shared<FBAllocator>(min, max, m_blockSize, m_maxBlocks);
    if (!allocator->initialize())
        return nullptr;

    m_allocators.push_back(allocator);
    return allocator;
}

char* PLH::RangeAllocator::allocate(uint64_t min, uint64_t max)
{
    static bool is32 = sizeof(void*) == 4;
    if (is32 && max > 0x7FFFFFFF)
    {
        max = 0x7FFFFFFF; // allocator apis fail in 32bit above this range
    }

    std::lock_guard<std::mutex> m_lock(m_mutex);
    const auto allocator = findOrInsertAllocator(min, max);
    if (!allocator)
    {
        return nullptr;
    }

    char* addr = allocator->allocate();
    m_allocMap[(uint64_t)addr] = allocator;
    return addr;
}

void PLH::RangeAllocator::deallocate(uint64_t addr)
{
    std::lock_guard<std::mutex> m_lock(m_mutex);
    if (const auto it{m_allocMap.find(addr)}; it != std::end(m_allocMap))
    {
        const auto allocator = it->second;
        allocator->deallocate((char*)addr);
        m_allocMap.erase(addr);

        // this instance + instance in m_allocators array
        if (allocator.use_count() == 2)
        {
            std::erase(m_allocators, allocator);
        }
    }
    else
    {
        assert(false);
    }
}
