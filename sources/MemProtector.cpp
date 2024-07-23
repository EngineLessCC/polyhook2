#include "polyhook2/MemProtector.hpp"
#include "polyhook2/Enums.hpp"
#include "polyhook2/PolyHookOsIncludes.hpp"

std::ostream& operator<<(std::ostream& os, const PLH::ProtFlag flags)
{
    if (flags == PLH::ProtFlag::UNSET)
    {
        os << "UNSET";
        return os;
    }

    if (flags & PLH::ProtFlag::X)
        os << "x";
    else
        os << "-";

    if (flags & PLH::ProtFlag::R)
        os << "r";
    else
        os << "-";

    if (flags & PLH::ProtFlag::W)
        os << "w";
    else
        os << "-";

    if (flags & PLH::ProtFlag::NONE)
        os << "n";
    else
        os << "-";

    if (flags & PLH::ProtFlag::P)
        os << " private";
    else if (flags & PLH::ProtFlag::S)
        os << " shared";
    return os;
}

#if defined(POLYHOOK2_OS_WINDOWS)

int PLH::TranslateProtection(const ProtFlag flags)
{
    int NativeFlag = 0;
    if (flags == X)
        NativeFlag = PAGE_EXECUTE;

    if (flags == R)
        NativeFlag = PAGE_READONLY;

    if (flags == W || (flags == (R | W)))
        NativeFlag = PAGE_READWRITE;

    if ((flags & X) && (flags & R))
        NativeFlag = PAGE_EXECUTE_READ;

    if ((flags & X) && (flags & W))
        NativeFlag = PAGE_EXECUTE_READWRITE;

    if (flags & NONE)
        NativeFlag = PAGE_NOACCESS;
    return NativeFlag;
}

PLH::ProtFlag PLH::TranslateProtection(const int prot)
{
    ProtFlag flags = UNSET;
    switch (prot)
    {
    case PAGE_EXECUTE:
        flags = flags | X;
        break;
    case PAGE_READONLY:
        flags = flags | R;
        break;
    case PAGE_READWRITE:
        flags = flags | W;
        flags = flags | R;
        break;
    case PAGE_EXECUTE_READWRITE:
        flags = flags | X;
        flags = flags | R;
        flags = flags | W;
        break;
    case PAGE_EXECUTE_READ:
        flags = flags | X;
        flags = flags | R;
        break;
    case PAGE_NOACCESS:
        flags = flags | NONE;
        break;
    }
    return flags;
}

#elif defined(POLYHOOK2_OS_LINUX)

int PLH::TranslateProtection(const PLH::ProtFlag flags) {
	int NativeFlag = PROT_NONE;
	if (flags & PLH::ProtFlag::X)
		NativeFlag |= PROT_EXEC;

	if (flags & PLH::ProtFlag::R)
		NativeFlag |= PROT_READ;

	if (flags & PLH::ProtFlag::W)
		NativeFlag |= PROT_WRITE;

	if (flags & PLH::ProtFlag::NONE)
		NativeFlag = PROT_NONE;

	return NativeFlag;
}

PLH::ProtFlag PLH::TranslateProtection(const int prot) {
	PLH::ProtFlag flags = PLH::ProtFlag::UNSET;

	if(prot & PROT_EXEC)
		flags = flags | PLH::ProtFlag::X;

	if (prot & PROT_READ)
		flags = flags | PLH::ProtFlag::R;

	if (prot & PROT_WRITE)
		flags = flags | PLH::ProtFlag::W;

	if (prot == PROT_NONE)
		flags = flags | PLH::ProtFlag::NONE;

	return flags;
}

#elif defined(POLYHOOK2_OS_APPLE)

int PLH::TranslateProtection(const PLH::ProtFlag flags) {
	int NativeFlag = VM_PROT_NONE;
	if (flags & PLH::ProtFlag::X)
		NativeFlag |= PROT_EXEC;

	if (flags & PLH::ProtFlag::R)
		NativeFlag |= PROT_READ;

	if (flags & PLH::ProtFlag::W)
		NativeFlag |= PROT_WRITE;

	if (flags & PLH::ProtFlag::NONE)
		NativeFlag = PROT_NONE;

	return NativeFlag;
}

PLH::ProtFlag PLH::TranslateProtection(const int prot) {
	PLH::ProtFlag flags = PLH::ProtFlag::UNSET;

	if (prot & VM_PROT_EXECUTE)
		flags = flags | PLH::ProtFlag::X;

	if (prot & VM_PROT_READ)
		flags = flags | PLH::ProtFlag::R;

	if (prot & VM_PROT_WRITE)
		flags = flags | PLH::ProtFlag::W;

	if (prot == VM_PROT_NONE)
		flags = flags | PLH::ProtFlag::NONE;

	return flags;
}

#endif
