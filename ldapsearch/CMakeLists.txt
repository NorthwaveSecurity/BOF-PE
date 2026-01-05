set(EXE_NAME "ldapsearch")
add_executable(${EXE_NAME} main.cpp)

if (NOT DEBUG)
    install(PROGRAMS ${EXE_NAME}_async_bof.s1.py TYPE BIN)
    set_target_properties(${EXE_NAME} PROPERTIES OUTPUT_NAME ${EXE_NAME}.${ARCH} SUFFIX .o)
endif()

target_include_directories(${EXE_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/beacon)
target_link_libraries(${EXE_NAME} beacon rpcrt4 wldap32 SECUR32 NETAPI32)

if (CMAKE_C_COMPILER_ID MATCHES "MSVC|Clang")
    target_compile_options(${EXE_NAME} PRIVATE /GS- /MT -Wno-microsoft-goto)
    target_link_options(${EXE_NAME} PRIVATE /MERGE:.gfids=. /MERGE:_RDATA=. /MERGE:.data=. /MERGE:.rdata=. /MERGE:.pdata=. /SECTION:.,RW /MERGE:.discard_data=.discard)

    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        target_link_options(${EXE_NAME} PRIVATE /SAFESEH)
    endif()

else()
    target_link_options(${EXE_NAME} PRIVATE -static)
    target_link_options(${EXE_NAME} PRIVATE -fno-unwind-tables -fno-asynchronous-unwind-tables -falign-functions=1 -fno-exceptions -fno-rtti -T${LINK_SCRIPT} -Wl,--strip-all)
endif()

install(TARGETS ${EXE_NAME})
