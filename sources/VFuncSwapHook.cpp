#include "polyhook2/Virtuals/VFuncSwapHook.hpp"
#include "polyhook2/ErrorLog.hpp"

PLH::VFuncSwapHook::VFuncSwapHook(const char* Class, const VFuncMap& redirectMap, VFuncMap* userOrigMap)
    : VFuncSwapHook((uint64_t)Class, redirectMap, userOrigMap)
{
}

PLH::VFuncSwapHook::VFuncSwapHook(const uint64_t Class, const VFuncMap& redirectMap, VFuncMap* userOrigMap)
    : m_class(Class)
      , m_vtable(nullptr)
      , m_vFuncCount(0)
      , m_redirectMap(redirectMap)
      , m_userOrigMap(userOrigMap)
{
}

bool PLH::VFuncSwapHook::hook()
{
    assert(m_userOrigMap != nullptr);
    MemoryProtector prot(m_class, sizeof(void*), R | W, *this);
    m_vtable = *(uintptr_t**)m_class;
    m_vFuncCount = countVFuncs();
    if (m_vFuncCount <= 0)
        return false;

    MemoryProtector prot2((uint64_t)&m_vtable[0], sizeof(uintptr_t) * static_cast<uint64_t>(m_vFuncCount), R | W,
                          *this);
    for (const auto& p : m_redirectMap)
    {
        assert(p.first < m_vFuncCount);
        if (p.first >= m_vFuncCount)
            return false;

        // redirect ptr at VTable[i]
        (*m_userOrigMap)[p.first] = static_cast<uint64_t>(m_vtable[p.first]);
        m_vtable[p.first] = static_cast<uintptr_t>(p.second);
    }

    m_hooked = true;
    return true;
}

bool PLH::VFuncSwapHook::unHook()
{
    assert(m_userOrigMap != nullptr);
    assert(m_hooked);
    if (!m_hooked)
    {
        PLH_LOG("vfuncswap unhook failed: no hook present", ErrorLevel::SEV);
        return false;
    }

    MemoryProtector prot2((uint64_t)&m_vtable[0], sizeof(uintptr_t) * static_cast<uint64_t>(m_vFuncCount), R | W,
                          *this);
    for (const auto& p : (*m_userOrigMap))
    {
        assert(p.first < m_vFuncCount);
        if (p.first >= m_vFuncCount)
            return false;

        m_vtable[p.first] = static_cast<uintptr_t>(p.second);
    }

    m_userOrigMap->clear();

    m_hooked = false;
    return true;
}

uint16_t PLH::VFuncSwapHook::countVFuncs()
{
    uint16_t count = 0;
    for (;; count++)
    {
        // if you have more than 500 vfuncs you have a problem and i don't support you :)
        if (!IsValidPtr((void*)m_vtable[count]) || count > 500)
            break;
    }
    return count;
}
