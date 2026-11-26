// memory.hpp — read primitives + region type for sigfind
#pragma once

#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

struct region {
    uintptr_t start = 0;
    size_t size = 0;
    std::vector<uint8_t> buffer;
    std::string module;
};

struct module_info {
    std::string name;
    uintptr_t base = 0;
    uintptr_t size = 0;
};

// read a POD from remote process
template <typename T>
inline bool read_mem(HANDLE h, uintptr_t addr, T& out)
{
    SIZE_T got = 0;
    return ReadProcessMemory(h, reinterpret_cast<LPCVOID>(addr), &out, sizeof(T), &got)
        && got == sizeof(T);
}

// read raw bytes from remote process
inline bool read_bytes(HANDLE h, uintptr_t addr, void* out, size_t len, SIZE_T& got)
{
    return ReadProcessMemory(h, reinterpret_cast<LPCVOID>(addr), out, len, &got)
        && got == len;
}

// check if an address looks like a valid readable pointer target
inline bool looks_valid(uintptr_t addr)
{
    if (!addr) return false;
    SYSTEM_INFO si{}; GetNativeSystemInfo(&si);
    return addr >= reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress)
        && addr <= reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);
}

// read a POD from a region buffer (offline scanner)
inline bool blob_read(const std::vector<region>& regs, uintptr_t addr, void* out, size_t len)
{
    for (const auto& r : regs) {
        if (addr >= r.start && addr < r.start + r.size) {
            size_t off = static_cast<size_t>(addr - r.start);
            if (off + len > r.buffer.size()) return false;
            std::memcpy(out, r.buffer.data() + off, len);
            return true;
        }
    }
    return false;
}

inline uintptr_t blob_read_ptr(const std::vector<region>& regs, uintptr_t addr)
{
    uintptr_t v = 0;
    blob_read(regs, addr, &v, sizeof(v));
    return v;
}
