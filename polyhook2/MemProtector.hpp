//
// Created by steve on 7/10/17.
//

#ifndef POLYHOOK_2_MEMORYPROTECTOR_HPP
#define POLYHOOK_2_MEMORYPROTECTOR_HPP

#include "polyhook2/PolyHookOs.hpp"
#include "polyhook2/MemAccessor.hpp"
#include "polyhook2/Enums.hpp"

PLH::ProtFlag operator|(PLH::ProtFlag lhs, PLH::ProtFlag rhs);
bool operator&(PLH::ProtFlag lhs, PLH::ProtFlag rhs);
std::ostream& operator<<(std::ostream& os, PLH::ProtFlag v);

// prefer enum class over enum
#pragma warning( disable : 26812)

namespace PLH
{
    int TranslateProtection(ProtFlag flags);
    ProtFlag TranslateProtection(int prot);

    class MemoryProtector
    {
    public:
        MemoryProtector(const uint64_t address, const uint64_t length, const ProtFlag prot, MemAccessor& accessor,
                        bool unsetOnDestroy = true) : m_accessor(accessor)
        {
            m_address = address;
            m_length = length;
            unsetLater = unsetOnDestroy;

            m_origProtection = UNSET;
            m_origProtection = m_accessor.mem_protect(address, length, prot, status);
        }

        ProtFlag originalProt()
        {
            return m_origProtection;
        }

        bool isGood()
        {
            return status;
        }

        ~MemoryProtector()
        {
            if (m_origProtection == UNSET || !unsetLater)
                return;

            m_accessor.mem_protect(m_address, m_length, m_origProtection, status);
        }

    private:
        ProtFlag m_origProtection;
        MemAccessor& m_accessor;

        uint64_t m_address;
        uint64_t m_length;
        bool status;
        bool unsetLater;
    };
}
#endif //POLYHOOK_2_MEMORYPROTECTOR_HPP
