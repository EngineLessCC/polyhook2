#include "polyhook2/PE/IatHook.hpp"

PLH::IatHook::IatHook(const std::string& dllName, const std::string& apiName, const char* fnCallback,
                      uint64_t* userOrigVar, const std::wstring& moduleName)
    : IatHook(dllName, apiName, (uint64_t)fnCallback, userOrigVar, moduleName)
{
}

PLH::IatHook::IatHook(const std::string& dllName, const std::string& apiName, const uint64_t fnCallback,
                      uint64_t* userOrigVar, const std::wstring& moduleName)
    : m_dllName(dllName)
      , m_apiName(apiName)
      , m_moduleName(moduleName)
      , m_fnCallback(fnCallback)
      , m_origFunc(0)
      , m_userOrigVar(userOrigVar)
{
}

bool PLH::IatHook::hook()
{
    assert(m_userOrigVar != nullptr);
    IMAGE_THUNK_DATA* pThunk = FindIatThunk(m_dllName, m_apiName);
    if (pThunk == nullptr)
        return false;

    // IAT is by default a writeable section
    MemoryProtector prot((uint64_t)&pThunk->u1.Function, sizeof(uintptr_t), R | W, *this);
    m_origFunc = static_cast<uint64_t>(pThunk->u1.Function);
    pThunk->u1.Function = static_cast<uintptr_t>(m_fnCallback);
    m_hooked = true;
    *m_userOrigVar = m_origFunc;
    return true;
}

bool PLH::IatHook::unHook()
{
    assert(m_userOrigVar != nullptr);
    assert(m_hooked);
    if (!m_hooked)
        return false;

    IMAGE_THUNK_DATA* pThunk = FindIatThunk(m_dllName, m_apiName);
    if (pThunk == nullptr)
        return false;

    MemoryProtector prot((uint64_t)&pThunk->u1.Function, sizeof(uintptr_t), R | W, *this);
    pThunk->u1.Function = static_cast<uintptr_t>(m_origFunc);
    m_hooked = false;
    *m_userOrigVar = NULL;
    return true;
}

IMAGE_THUNK_DATA* PLH::IatHook::FindIatThunk(const std::string& dllName, const std::string& apiName,
                                             const std::wstring moduleName /* = L"" */)
{
#if defined(_WIN64)
	PEB* peb = (PPEB)__readgsqword(0x60);
#else
    auto peb = (PPEB)__readfsdword(0x30);
#endif

    IMAGE_THUNK_DATA* pThunk = nullptr;
    const auto* ldr = peb->Ldr;

    // find loaded module from peb
    for (const auto* dte = (LDR_DATA_TABLE_ENTRY*)ldr->InLoadOrderModuleList.Flink;
         dte->DllBase != nullptr;
         dte = (LDR_DATA_TABLE_ENTRY*)dte->InLoadOrderLinks.Flink)
    {
        // TODO: create stricmp for UNICODE_STRING because this is really bad for performance
        std::wstring baseModuleName(dte->BaseDllName.Buffer, dte->BaseDllName.Length / sizeof(wchar_t));

        // try all modules if none given, otherwise only try specified
        if (!moduleName.empty() && (my_wide_stricmp(baseModuleName.c_str(), moduleName.c_str()) != 0))
            continue;

        pThunk = FindIatThunkInModule(dte->DllBase, dllName, apiName);
        if (pThunk != nullptr)
            return pThunk;
    }

    PLH_LOG("Failed to find thunk for api from requested dll", ErrorLevel::SEV);

    return nullptr;
}

IMAGE_THUNK_DATA* PLH::IatHook::FindIatThunkInModule(void* moduleBase, const std::string& dllName,
                                                     const std::string& apiName)
{
    assert(moduleBase != nullptr);
    if (moduleBase == nullptr)
        return nullptr;

    const auto* pDos = static_cast<IMAGE_DOS_HEADER*>(moduleBase);
    const auto* pNT = RVA2VA(IMAGE_NT_HEADERS*, moduleBase, pDos->e_lfanew);
    const auto* pDataDir = (IMAGE_DATA_DIRECTORY*)pNT->OptionalHeader.DataDirectory;

    if (pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == NULL)
    {
        PLH_LOG("PEs without import tables are unsupported", ErrorLevel::SEV);
        return nullptr;
    }

    const auto* pImports = (IMAGE_IMPORT_DESCRIPTOR*)RVA2VA(uintptr_t, moduleBase,
                                                            pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // import entry with null fields marks end
    for (uint_fast16_t i = 0; pImports[i].Name != NULL; i++)
    {
        if (my_narrow_stricmp(RVA2VA(PCHAR, moduleBase, pImports[i].Name),
                              dllName.c_str()) != 0)
            continue;

        // Original holds the API Names
        auto pOriginalThunk = (PIMAGE_THUNK_DATA)
            RVA2VA(uintptr_t, moduleBase, pImports[i].OriginalFirstThunk);

        // FirstThunk is overwritten by loader with API addresses, we change this
        auto pThunk = (PIMAGE_THUNK_DATA)
            RVA2VA(uintptr_t, moduleBase, pImports[i].FirstThunk);

        if (!pOriginalThunk)
        {
            PLH_LOG("IAT's without valid original thunk are un-supported", ErrorLevel::SEV);
            return nullptr;
        }

        // Table is null terminated, increment both tables
        for (; pOriginalThunk->u1.Ordinal != NULL; pOriginalThunk++, pThunk++)
        {
            if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal))
            {
                //printf("Import By Ordinal:[Ordinal:%d]\n", IMAGE_ORDINAL(pOriginalThunk->u1.Ordinal));
                continue;
            }

            const auto pImport = (PIMAGE_IMPORT_BY_NAME)
                RVA2VA(uintptr_t, moduleBase, pOriginalThunk->u1.AddressOfData);

            if (my_narrow_stricmp(pImport->Name, apiName.c_str()) != 0)
                continue;

            return pThunk;
        }
    }

    PLH_LOG("Thunk not found before end of IAT", ErrorLevel::SEV);
    return nullptr;
}
