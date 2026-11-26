// scanner.hpp — pattern matching, RIP-relative resolution, region search
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "memory.hpp"

struct sig {
    std::vector<uint8_t> bytes;
    std::vector<bool> wildcard;

    static sig parse(const char* text)
    {
        sig s;
        const char* p = text;
        while (*p) {
            while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;
            if (!*p) break;
            if (p[0] == '?' && (p[1] == '?' || p[1] == ' ' || p[1] == '\t' || p[1] == '\0')) {
                s.bytes.push_back(0);
                s.wildcard.push_back(true);
                p += (p[1] == '?') ? 2 : 1;
            } else {
                unsigned int v = 0;
                sscanf_s(p, "%2x", &v);
                s.bytes.push_back(static_cast<uint8_t>(v));
                s.wildcard.push_back(false);
                p += 2;
            }
        }
        return s;
    }

    size_t size() const { return bytes.size(); }
};

inline uintptr_t find_pattern(const region& r, const sig& s, size_t max_hits = 8)
{
    std::vector<uintptr_t> out;
    if (r.buffer.size() < s.size()) return 0;
    size_t limit = r.buffer.size() - s.size();
    for (size_t off = 0; off <= limit; ++off) {
        bool ok = true;
        for (size_t i = 0; i < s.size(); ++i) {
            if (!s.wildcard[i] && s.bytes[i] != r.buffer[off + i]) { ok = false; break; }
        }
        if (ok) {
            out.push_back(r.start + static_cast<uintptr_t>(off));
            if (out.size() >= max_hits) break;
        }
    }
    return out.empty() ? 0 : out[0];
}

inline std::vector<uintptr_t> find_pattern_all(const region& r, const sig& s)
{
    std::vector<uintptr_t> out;
    if (r.buffer.size() < s.size()) return out;
    size_t limit = r.buffer.size() - s.size();
    for (size_t off = 0; off <= limit; ++off) {
        bool ok = true;
        for (size_t i = 0; i < s.size(); ++i) {
            if (!s.wildcard[i] && s.bytes[i] != r.buffer[off + i]) { ok = false; break; }
        }
        if (ok) out.push_back(r.start + static_cast<uintptr_t>(off));
    }
    return out;
}

// resolve `lea reg, [rip + disp32]` (48 8D 05 / 48 8D 0D / 48 8D 15 / 48 8D 1D)
// returns absolute target address
inline uintptr_t resolve_rip32(const region& r, uintptr_t instr_addr)
{
    size_t off = static_cast<size_t>(instr_addr - r.start);
    if (off + 7 > r.buffer.size()) return 0;
    uint8_t b0 = r.buffer[off];
    uint8_t b1 = r.buffer[off + 1];
    uint8_t b2 = r.buffer[off + 2];
    // lea r64, [rip + disp32] : 48 8D /r modrm
    if (b0 != 0x48 || b1 != 0x8D) return 0;
    uint8_t modrm = b2;
    uint8_t mod = (modrm >> 6) & 0x3;
    uint8_t reg = (modrm >> 3) & 0x7;
    uint8_t rm = modrm & 0x7;
    if (mod != 0 || rm != 0x5) return 0; // [rip + disp32] only
    int32_t disp = 0;
    std::memcpy(&disp, r.buffer.data() + off + 3, 4);
    return instr_addr + 7 + static_cast<uintptr_t>(disp);
}

inline uintptr_t scan_regions_for_sig(const std::vector<region>& regs, const char* hexsig,
                                      bool rip_relative = false, size_t max_hits = 8)
{
    sig s = sig::parse(hexsig);
    for (const auto& r : regs) {
        if (r.buffer.size() < s.size()) continue;
        if (!rip_relative) {
            uintptr_t hit = find_pattern(r, s, max_hits);
            if (hit) return hit;
        } else {
            auto hits = find_pattern_all(r, s);
            for (uintptr_t h : hits) {
                uintptr_t abs = resolve_rip32(r, h);
                if (abs) return abs;
            }
        }
    }
    return 0;
}

inline std::vector<uintptr_t> scan_regions_for_sig_all(const std::vector<region>& regs,
                                                       const char* hexsig,
                                                       bool rip_relative = false)
{
    std::vector<uintptr_t> out;
    sig s = sig::parse(hexsig);
    for (const auto& r : regs) {
        if (r.buffer.size() < s.size()) continue;
        if (!rip_relative) {
            auto hits = find_pattern_all(r, s);
            out.insert(out.end(), hits.begin(), hits.end());
        } else {
            auto hits = find_pattern_all(r, s);
            for (uintptr_t h : hits) {
                uintptr_t abs = resolve_rip32(r, h);
                if (abs) out.push_back(abs);
            }
        }
    }
    return out;
}
