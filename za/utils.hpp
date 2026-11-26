// utils.hpp — shared helpers for sigfind
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

static inline std::string hex_str(uint64_t v)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(v));
    return buf;
}
