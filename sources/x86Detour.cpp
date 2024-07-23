//
// Created by steve on 7/5/17.
//
#include "polyhook2/Detour/x86Detour.hpp"

#define PAGE_SIZE 4096

namespace PLH
{
    x86Detour::x86Detour(const uint64_t fnAddress, const uint64_t fnCallback, uint64_t* userTrampVar)
        : Detour(fnAddress, fnCallback, userTrampVar, getArchType())
    {
    }

    Mode x86Detour::getArchType() const
    {
        return Mode::x86;
    }

    uint8_t getJmpSize()
    {
        return 5;
    }

    bool x86Detour::hook()
    {
        PLH_LOG("m_fnAddress: " + int_to_hex(m_fnAddress) + "\n", ErrorLevel::INFO);

        insts_t insts = m_disasm.disassemble(m_fnAddress, m_fnAddress, m_fnAddress + 100, *this);
        PLH_LOG("Original function:\n" + instsToStr(insts) + "\n", ErrorLevel::INFO);

        if (insts.empty())
        {
            PLH_LOG("Disassembler unable to decode any valid instructions", ErrorLevel::SEV);
            return false;
        }

        if (!followJmp(insts))
        {
            PLH_LOG("Prologue jmp resolution failed", ErrorLevel::SEV);
            return false;
        }

        // update given fn address to resolved one
        m_fnAddress = insts.front().getAddress();

        // --------------- END RECURSIVE JMP RESOLUTION ---------------------

        uint64_t minProlSz = getJmpSize(); // min size of patches that may split instructions
        uint64_t roundProlSz = minProlSz; // nearest size to min that doesn't split any instructions

        // find the prologue section we will overwrite with jmp + zero or more nops
        const auto prologueOpt = calcNearestSz(insts, minProlSz, roundProlSz);
        if (!prologueOpt)
        {
            PLH_LOG("Function too small to hook safely!", ErrorLevel::SEV);
            return false;
        }

        assert(roundProlSz >= minProlSz);
        auto prologue = *prologueOpt;

        if (!expandProlSelfJmps(prologue, insts, minProlSz, roundProlSz))
        {
            PLH_LOG("Function needs a prologue jmp table but it's too small to insert one", ErrorLevel::SEV);
            return false;
        }

        m_originalInsts = prologue;
        PLH_LOG("Prologue to overwrite:\n" + instsToStr(prologue) + "\n", ErrorLevel::INFO);

        // copy all the prologue stuff to trampoline
        insts_t jmpTblOpt;
        if (!makeTrampoline(prologue, jmpTblOpt))
        {
            return false;
        }

        auto tramp_instructions = m_disasm.
            disassemble(m_trampoline, m_trampoline, m_trampoline + m_trampolineSz, *this);
        PLH_LOG("Trampoline:\n" + instsToStr(tramp_instructions) + "\n\n", ErrorLevel::INFO);
        if (!jmpTblOpt.empty())
        {
            PLH_LOG("Trampoline Jmp Tbl:\n" + instsToStr(jmpTblOpt) + "\n\n", ErrorLevel::INFO);
        }

        *m_userTrampVar = m_trampoline;
        m_hookSize = static_cast<uint32_t>(roundProlSz);
        m_nopProlOffset = static_cast<uint16_t>(minProlSz);

        MemoryProtector prot(m_fnAddress, m_hookSize, RWX, *this);

        m_hookInsts = makex86Jmp(m_fnAddress, m_fnCallback);
        PLH_LOG("Hook instructions:\n" + instsToStr(m_hookInsts) + "\n", ErrorLevel::INFO);
        ZydisDisassembler::writeEncoding(m_hookInsts, *this);

        // Nop the space between jmp and end of prologue
        assert(m_hookSize >= m_nopProlOffset);
        m_nopSize = static_cast<uint16_t>(m_hookSize - m_nopProlOffset);
        const auto nops = make_nops(m_fnAddress + m_nopProlOffset, m_nopSize);
        ZydisDisassembler::writeEncoding(nops, *this);

        m_hooked = true;
        return true;
    }

    bool x86Detour::makeTrampoline(insts_t& prologue, insts_t& trampolineOut)
    {
        assert(!prologue.empty());
        const uint64_t prolStart = prologue.front().getAddress();
        const uint16_t prolSz = calcInstsSz(prologue);

        /** Make a guess for the number entries we need so we can try to allocate a trampoline. The allocation
        address will change each attempt, which changes delta, which changes the number of needed entries. So
        we just try until we hit that lucky number that works.
    
        The relocation could also because of data operations too. But that's specific to the function and can't
        work again on a retry (same function, duh). Return immediately in that case.
        **/
        uint8_t neededEntryCount = 5;
        insts_t instsNeedingEntry;
        insts_t instsNeedingReloc;
        insts_t instsNeedingTranslation;

        uint8_t retries = 0;
        do
        {
            if (retries++ > 4)
            {
                PLH_LOG("Failed to calculate trampoline information", ErrorLevel::SEV);
                return false;
            }

            if (m_trampoline != NULL)
            {
                g_asmjit_rt.allocator()->release((void*)m_trampoline);
                neededEntryCount = static_cast<uint8_t>(instsNeedingEntry.size());
            }

            // prol + jmp back to prol + N * jmpEntries
            m_trampolineSz = static_cast<uint16_t>(prolSz + getJmpSize() + getJmpSize() * neededEntryCount);

            void* rwPtr{};
            g_asmjit_rt.allocator()->alloc((void**)&m_trampoline, &rwPtr, m_trampolineSz);

            const int64_t delta = m_trampoline - prolStart;

            buildRelocationList(prologue, prolSz, delta, instsNeedingEntry, instsNeedingReloc, instsNeedingTranslation);
        }
        while (instsNeedingEntry.size() > neededEntryCount);

        const int64_t delta = m_trampoline - prolStart;

        // Insert jmp from trampoline -> prologue after overwritten section
        const uint64_t jmpToProlAddr = m_trampoline + prolSz;
        const auto jmpToProl = makex86Jmp(jmpToProlAddr, prologue.front().getAddress() + prolSz);
        ZydisDisassembler::writeEncoding(jmpToProl, *this);

        const auto makeJmpFn = [=](uint64_t a, Instruction& inst) mutable
        {
            // move inst to trampoline and point instruction to entry
            const auto oldDest = inst.getDestination();
            inst.setAddress(inst.getAddress() + delta);
            inst.setDestination(a);

            return makex86Jmp(a, oldDest);
        };

        const uint64_t jmpTblStart = jmpToProlAddr + getJmpSize();
        trampolineOut = relocateTrampoline(prologue, jmpTblStart, delta, makeJmpFn, instsNeedingReloc,
                                           instsNeedingEntry);
        return true;
    }
}
