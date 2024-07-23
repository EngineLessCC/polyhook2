cmake_minimum_required(VERSION 3.15)

project(polyhook2)
string(TOLOWER ${PROJECT_NAME} LOWERCASE_PROJECT_NAME)
include(CMakePackageConfigHelpers)

if(WIN32)
	set(POLYHOOK_OS "windows")
elseif(APPLE)
	set(POLYHOOK_OS "macos")
elseif(UNIX)
	set(POLYHOOK_OS "linux")
endif()

#
# Polyhook
#

# Core
set(POLYHOOK_CORE_HEADERS
	${PROJECT_SOURCE_DIR}/polyhook2/Enums.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/IHook.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/Instruction.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/Misc.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/UID.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/ErrorLog.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/MemProtector.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/MemAccessor.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/FBAllocator.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/RangeAllocator.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/Tests/TestEffectTracker.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/Tests/StackCanary.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/EventDispatcher.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/PolyHookOs.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/PolyHookOsIncludes.hpp
)

add_library(${PROJECT_NAME} STATIC ${POLYHOOK_CORE_HEADERS})
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD 20)
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD_REQUIRED ON)

target_include_directories(${PROJECT_NAME}
    PUBLIC
		$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
    INTERFACE
		$<INSTALL_INTERFACE:include>
)


install(FILES ${POLYHOOK_CORE_HEADERS} DESTINATION include/polyhook2)


target_sources(${PROJECT_NAME} PRIVATE
	${PROJECT_SOURCE_DIR}/sources/MemProtector.cpp
	${PROJECT_SOURCE_DIR}/sources/MemAccessor.cpp
	${PROJECT_SOURCE_DIR}/sources/TestEffectTracker.cpp
	${PROJECT_SOURCE_DIR}/sources/StackCanary.cpp
	${PROJECT_SOURCE_DIR}/sources/FBAllocator.cpp
	${PROJECT_SOURCE_DIR}/sources/RangeAllocator.cpp
	${PROJECT_SOURCE_DIR}/sources/ErrorLog.cpp
	${PROJECT_SOURCE_DIR}/sources/UID.cpp
	${PROJECT_SOURCE_DIR}/sources/Misc.cpp
	${PROJECT_SOURCE_DIR}/sources/PolyHookOs.cpp
)

find_package(asmjit CONFIG REQUIRED)
find_package(asmtk CONFIG REQUIRED)

target_link_libraries(${PROJECT_NAME} PUBLIC
	asmjit::asmjit
	asmjit::asmtk
	zydis zycore
)

set(POLYHOOK_DETOUR_HEADERS
	${PROJECT_SOURCE_DIR}/polyhook2/Detour/ADetour.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/Detour/NatDetour.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/Detour/x64Detour.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/Detour/x86Detour.hpp)

install(FILES ${POLYHOOK_DETOUR_HEADERS} DESTINATION include/polyhook2/Detour)

target_sources(${PROJECT_NAME} PRIVATE
	${PROJECT_SOURCE_DIR}/sources/ADetour.cpp
	${PROJECT_SOURCE_DIR}/sources/x64Detour.cpp
	${PROJECT_SOURCE_DIR}/sources/x86Detour.cpp
	${PROJECT_SOURCE_DIR}/sources/ZydisDisassembler.cpp
	)

#Feature/Inlinentd
install(FILES ${PROJECT_SOURCE_DIR}/polyhook2/Detour/ILCallback.hpp DESTINATION include/polyhook2/Detour)
target_sources(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/sources/ILCallback.cpp)

#Feature/Exception
set(POLYHOOK_EXCEPTION_HEADERS
	${PROJECT_SOURCE_DIR}/polyhook2/Exceptions/AVehHook.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/Exceptions/BreakPointHook.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/Exceptions/HWBreakPointHook.hpp)
install(FILES ${POLYHOOK_EXCEPTION_HEADERS} DESTINATION include/polyhook2/Exceptions)

target_sources(${PROJECT_NAME} PRIVATE
	${PROJECT_SOURCE_DIR}/sources/AVehHook.cpp
	${PROJECT_SOURCE_DIR}/sources/BreakPointHook.cpp
	${PROJECT_SOURCE_DIR}/sources/HWBreakPointHook.cpp)

#Feature/PE
set(POLYHOOK_PE_HEADERS
	${PROJECT_SOURCE_DIR}/polyhook2/PE/EatHook.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/PE/IatHook.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/PE/PEB.hpp)
install(FILES ${POLYHOOK_PE_HEADERS} DESTINATION include/polyhook2/PE)

target_sources(${PROJECT_NAME} PRIVATE
	${PROJECT_SOURCE_DIR}/sources/EatHook.cpp
	${PROJECT_SOURCE_DIR}/sources/IatHook.cpp)

#Feature/Virtuals
set(POLYHOOK_VIRTUAL_HEADERS
	${PROJECT_SOURCE_DIR}/polyhook2/Virtuals/VTableSwapHook.hpp
	${PROJECT_SOURCE_DIR}/polyhook2/Virtuals/VFuncSwapHook.hpp)
install(FILES ${POLYHOOK_VIRTUAL_HEADERS} DESTINATION include/polyhook2/Virtuals)

target_sources(${PROJECT_NAME} PRIVATE
	${PROJECT_SOURCE_DIR}/sources/VTableSwapHook.cpp
	${PROJECT_SOURCE_DIR}/sources/VFuncSwapHook.cpp)