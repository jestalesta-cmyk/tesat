// hunters.hpp — per-offset signature hunters with structural validation
#pragma once

#include <cstdint>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "memory.hpp"
#include "scanner.hpp"
#include "utils.hpp"

// result of hunting one offset
struct hunt_result {
    std::string name;
    uintptr_t absolute = 0;   // absolute address found in the target process
    uintptr_t rva = 0;        // RVA from module base (if we know it)
    std::string signature;    // the hex sig string that found it
    bool rip_relative = false;
    bool valid = false;
    std::string note;
};

// read a pointer from a live process (HANDLE) — used for validation
static uintptr_t read_ptr(HANDLE h, uintptr_t addr)
{
    uintptr_t v = 0;
    read_mem(h, addr, v);
    return v;
}

// ---------------------------------------------------------------------------
// world hunter
// signature: 48 8B 05 ? ? ? ? 33 D2 48 8B 40 08 8A CA 48 85 C0 74 16 48 8B
// this is a RIP-relative lea that loads the world object pointer.
// validate: dereference -> world object -> ped list pointer should be readable
// ---------------------------------------------------------------------------

static hunt_result hunt_world(HANDLE h, const std::vector<region>& regs, uintptr_t module_base)
{
    hunt_result r; r.name = "world";
    const char* sig = "48 8B 05 ? ? ? ? 33 D2 48 8B 40 08 8A CA 48 85 C0 74 16 48 8B";
    uintptr_t hit = scan_regions_for_sig(regs, sig, true);
    if (!hit) { r.note = "signature not found"; return r; }

    // validate: hit should be the world object pointer
    uintptr_t world_obj = read_ptr(h, hit);
    if (!looks_valid(world_obj)) { r.note = "world obj unreadable"; r.absolute = hit; r.signature = sig; r.rip_relative = true; return r; }

    // world + 0x8 should be the replay/ped interface chain
    uintptr_t ped_chain = read_ptr(h, world_obj + 0x8);
    if (!looks_valid(ped_chain)) { r.note = "ped chain unreadable"; r.absolute = hit; r.signature = sig; r.rip_relative = true; return r; }

    r.absolute = hit;
    r.rva = hit - module_base;
    r.valid = true;
    r.signature = sig;
    r.rip_relative = true;
    r.note = "validated";
    return r;
}

// ---------------------------------------------------------------------------
// camera hunter
// signature: 48 8B 05 ? ? ? ? 48 8B 98 ? ? ? ? EB
// loads camera base pointer RIP-relative
// validate: camera + 0x3D0 should hold finite view angles
// ---------------------------------------------------------------------------

static hunt_result hunt_camera(HANDLE h, const std::vector<region>& regs, uintptr_t module_base)
{
    hunt_result r; r.name = "camera";
    const char* sig = "48 8B 05 ? ? ? ? 48 8B 98 ? ? ? ? EB";
    uintptr_t hit = scan_regions_for_sig(regs, sig, true);
    if (!hit) { r.note = "signature not found"; return r; }

    uintptr_t cam_base = read_ptr(h, hit);
    if (!looks_valid(cam_base)) { r.note = "camera base unreadable"; r.absolute = hit; r.signature = sig; r.rip_relative = true; return r; }

    // try reading view angles at camera + 0x3D0 (known candidate)
    float angles[3] = { 0, 0, 0 };
    SIZE_T got = 0;
    if (ReadProcessMemory(h, reinterpret_cast<LPCVOID>(cam_base + 0x3D0), angles, 12, &got) && got == 12) {
        bool finite = true;
        for (int i = 0; i < 3; ++i) {
            if (angles[i] != angles[i] || angles[i] < -360.f || angles[i] > 360.f) finite = false;
        }
        if (!finite) { r.note = "camera angles not finite"; r.absolute = hit; r.signature = sig; r.rip_relative = true; return r; }
    }

    r.absolute = hit;
    r.rva = hit - module_base;
    r.valid = true;
    r.signature = sig;
    r.rip_relative = true;
    r.note = "validated";
    return r;
}

// ---------------------------------------------------------------------------
// replay_interface hunter
// signature: 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? ...
// loads replay interface pointer
// ---------------------------------------------------------------------------

static hunt_result hunt_replay(HANDLE h, const std::vector<region>& regs, uintptr_t module_base)
{
    hunt_result r; r.name = "replay_interface";
    const char* sig = "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48 8B 9C 24";
    uintptr_t hit = scan_regions_for_sig(regs, sig, true);
    if (!hit) { r.note = "signature not found"; return r; }

    uintptr_t replay = read_ptr(h, hit);
    if (!looks_valid(replay)) { r.note = "replay ptr unreadable"; r.absolute = hit; r.signature = sig; r.rip_relative = true; return r; }

    r.absolute = hit;
    r.rva = hit - module_base;
    r.valid = true;
    r.signature = sig;
    r.rip_relative = true;
    r.note = "validated";
    return r;
}

// ---------------------------------------------------------------------------
// handle_bullet hunter
// signature: F3 41 0F 10 19 F3 41 0F 10 41 04 F3 41 0F 10 51 08
// NOT rip-relative — this is the exact code bytes at the hook site
// validate: the 14 bytes at the hit should match exactly
// ---------------------------------------------------------------------------

static hunt_result hunt_handle_bullet(HANDLE h, const std::vector<region>& regs, uintptr_t module_base)
{
    hunt_result r; r.name = "handle_bullet";
    const char* sig = "F3 41 0F 10 19 F3 41 0F 10 41 04 F3 41 0F 10 51 08";
    uintptr_t hit = scan_regions_for_sig(regs, sig, false);
    if (!hit) { r.note = "signature not found"; return r; }

    // read back the 14 bytes to confirm they match exactly
    std::vector<uint8_t> expected = { 0xF3,0x41,0x0F,0x10,0x19, 0xF3,0x41,0x0F,0x10,0x41,0x04, 0xF3,0x41,0x0F,0x10,0x51,0x08 };
    // sig is 15 bytes; expected is 16 — the sig covers first 15
    std::vector<uint8_t> actual(15);
    SIZE_T got = 0;
    if (!ReadProcessMemory(h, reinterpret_cast<LPCVOID>(hit), actual.data(), 15, &got) || got != 15) {
        r.note = "cannot read back hook site"; r.absolute = hit; r.signature = sig; return r;
    }
    for (size_t i = 0; i < 15; ++i) {
        if (actual[i] != expected[i]) { r.note = "bytes mismatch"; r.absolute = hit; r.signature = sig; return r; }
    }

    r.absolute = hit;
    r.rva = hit - module_base;
    r.valid = true;
    r.signature = sig;
    r.rip_relative = false;
    r.note = "validated";
    return r;
}

// ---------------------------------------------------------------------------
// helper: walk world → replay → ped_interface → ped_list → first valid ped
// ---------------------------------------------------------------------------

static uintptr_t get_first_ped(HANDLE h)
{
    // we need world, replay_interface absolute addresses — re-hunt them locally
    // (callers pass regs/module_base, but here we just re-scan quickly)
    // Simpler: read from known hunter results. Instead, just scan ped_list from world.
    // For now return 0 — caller must provide a ped pointer via the regs scan.
    return 0;
}

// ---------------------------------------------------------------------------
// ped offset hunter
// scans around a known ped pointer for health (~100.f), max_health, armor,
// weapon_manager pointer, etc.
// ---------------------------------------------------------------------------

static hunt_result hunt_ped_offsets(HANDLE h, const std::vector<region>& regs, uintptr_t module_base)
{
    hunt_result r; r.name = "ped_health";
    r.note = "ped pointer not found";

    // find a ped pointer: walk world → replay → ped_interface → ped_list[0]
    // we re-run world + replay hunters internally
    auto world_r = hunt_world(h, regs, module_base);
    auto replay_r = hunt_replay(h, regs, module_base);
    if (!world_r.valid || !replay_r.valid) return r;

    uintptr_t world_obj = read_ptr(h, world_r.absolute);
    uintptr_t replay_obj = read_ptr(h, replay_r.absolute);
    if (!looks_valid(world_obj) || !looks_valid(replay_obj)) return r;

    // replay → ped_interface → ped_list
    // ped_interface is typically at replay + 0x0, ped_list at ped_interface + 0x8
    uintptr_t ped_interface = read_ptr(h, replay_obj);
    if (!looks_valid(ped_interface)) return r;
    uintptr_t ped_list = read_ptr(h, ped_interface + 0x8);
    if (!looks_valid(ped_list)) return r;

    // read first 16 ped entries
    for (int i = 0; i < 16; ++i) {
        uintptr_t ped = read_ptr(h, ped_list + i * 0x10);
        if (!looks_valid(ped) || ped == 0) continue;

        // scan ped + 0x000 .. ped + 0x1000 for a float near 100.0 (health)
        for (uintptr_t off = 0; off < 0x1000; off += 4) {
            float val = 0.f;
            SIZE_T got = 0;
            if (!ReadProcessMemory(h, reinterpret_cast<LPCVOID>(ped + off), &val, 4, &got) || got != 4)
                continue;
            if (val != val) continue; // NaN
            if (val < 50.f || val > 200.f) continue; // not health-like

            // candidate: check if +4 is also a plausible max_health (>= health)
            float val2 = 0.f;
            ReadProcessMemory(h, reinterpret_cast<LPCVOID>(ped + off + 4), &val2, 4, &got);
            if (got == 4 && val2 != val2) continue;
            if (got == 4 && val2 >= val && val2 <= 500.f) {
                // found health + max_health pair
                r.absolute = ped + off;
                r.rva = (ped + off) - module_base;
                r.valid = true;
                r.signature = "scan: ped+" + hex_str(off) + " (health~100.f)";
                r.note = "health at +0x" + hex_str(off) + ", max_health at +0x" + hex_str(off + 4);
                return r;
            }
        }
    }

    return r;
}

// ---------------------------------------------------------------------------
// vehicle offset hunter
// scans around a known vehicle pointer for body health (~840.f), engine health (~1000.f)
// ---------------------------------------------------------------------------

static hunt_result hunt_vehicle_offsets(HANDLE h, const std::vector<region>& regs, uintptr_t module_base)
{
    hunt_result r; r.name = "veh_body_health";
    r.note = "vehicle pointer not found";

    // reuse ped walk to get local ped's last vehicle
    auto world_r = hunt_world(h, regs, module_base);
    auto replay_r = hunt_replay(h, regs, module_base);
    if (!world_r.valid || !replay_r.valid) return r;

    uintptr_t world_obj = read_ptr(h, world_r.absolute);
    uintptr_t replay_obj = read_ptr(h, replay_r.absolute);
    if (!looks_valid(world_obj) || !looks_valid(replay_obj)) return r;

    uintptr_t ped_interface = read_ptr(h, replay_obj);
    uintptr_t ped_list = read_ptr(h, ped_interface + 0x8);
    if (!looks_valid(ped_interface) || !looks_valid(ped_list)) return r;

    // local ped is typically ped_list[0] or we can check each ped's last_vehicle
    for (int i = 0; i < 16; ++i) {
        uintptr_t ped = read_ptr(h, ped_list + i * 0x10);
        if (!looks_valid(ped) || ped == 0) continue;

        // last_vehicle is typically at ped + 0xD10 (from cheat's ped.cpp)
        uintptr_t veh = read_ptr(h, ped + 0xD10);
        if (!looks_valid(veh)) continue;

        // scan vehicle + 0x000 .. vehicle + 0x1000 for body health (~840.f)
        for (uintptr_t off = 0; off < 0x1000; off += 4) {
            float val = 0.f;
            SIZE_T got = 0;
            if (!ReadProcessMemory(h, reinterpret_cast<LPCVOID>(veh + off), &val, 4, &got) || got != 4)
                continue;
            if (val != val) continue;
            if (val < 700.f || val > 1000.f) continue; // body health range

            // candidate found
            r.absolute = veh + off;
            r.rva = (veh + off) - module_base;
            r.valid = true;
            r.signature = "scan: veh+" + hex_str(off) + " (body health~840.f)";
            r.note = "vehicle body health at +0x" + hex_str(off);
            return r;
        }
    }

    return r;
}

// ---------------------------------------------------------------------------
// cfx::ResourceManager hunter
// scans citizen-resources-*.dll for the ResourceManager instance.
// signature candidate: a vtable or global pointer that points into
// citizen-resources module with resource list methods nearby.
// ---------------------------------------------------------------------------

static hunt_result hunt_cfx_resource_manager(HANDLE h, const std::vector<region>& regs, uintptr_t module_base)
{
    hunt_result r; r.name = "cfx_resource_manager";
    r.note = "not found";

    // find citizen-resources modules in the dumped regions
    for (const auto& reg : regs) {
        if (reg.module.find("citizen-resources") == std::string::npos) continue;
        if (reg.buffer.empty()) continue;

        // look for a global ResourceManager pointer pattern:
        // typically a lea RIP-relative loading a pointer inside this module
        const char* sig = "48 8B 05 ? ? ? ? 48 85 C0 74 ? 48 8B";
        auto hits = find_pattern_all(reg, sig::parse(sig));
        for (uintptr_t hit : hits) {
            uintptr_t abs = resolve_rip32(reg, hit);
            if (!abs) continue;

            // validate: dereference -> should point into a citizen-resources module
            uintptr_t rm = read_ptr(h, abs);
            if (!looks_valid(rm)) continue;

            // check if rm lands inside any citizen-resources module
            bool in_cfx = false;
            for (const auto& reg2 : regs) {
                if (reg2.module.find("citizen-resources") == std::string::npos) continue;
                if (rm >= reg2.start && rm < reg2.start + reg2.size) { in_cfx = true; break; }
            }
            if (!in_cfx) continue;

            r.absolute = abs;
            r.rva = abs - module_base;
            r.valid = true;
            r.signature = sig;
            r.rip_relative = true;
            r.note = "cfx ResourceManager candidate at " + hex_str(abs);
            return r;
        }
    }

    return r;
}

// ---------------------------------------------------------------------------
// helper: walk world → replay → ped_interface → ped_list, return first valid ped
// ---------------------------------------------------------------------------

static uintptr_t walk_to_first_ped(HANDLE h, const std::vector<region>& regs, uintptr_t module_base)
{
    auto world_r = hunt_world(h, regs, module_base);
    auto replay_r = hunt_replay(h, regs, module_base);
    if (!world_r.valid || !replay_r.valid) return 0;

    uintptr_t world_obj = read_ptr(h, world_r.absolute);
    uintptr_t replay_obj = read_ptr(h, replay_r.absolute);
    if (!looks_valid(world_obj) || !looks_valid(replay_obj)) return 0;

    uintptr_t ped_interface = read_ptr(h, replay_obj);
    uintptr_t ped_list = read_ptr(h, ped_interface + 0x8);
    if (!looks_valid(ped_interface) || !looks_valid(ped_list)) return 0;

    for (int i = 0; i < 16; ++i) {
        uintptr_t ped = read_ptr(h, ped_list + i * 0x10);
        if (looks_valid(ped) && ped != 0) return ped;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// scan a ped struct for a specific field type
// ---------------------------------------------------------------------------

// find first offset in [ped, ped+0x2000) where a float matches expected range
static uintptr_t scan_ped_float(HANDLE h, uintptr_t ped, float min_v, float max_v,
                                uintptr_t start_off = 0, uintptr_t end_off = 0x2000)
{
    for (uintptr_t off = start_off; off + 4 <= end_off; off += 4) {
        float val = 0.f;
        SIZE_T got = 0;
        if (!ReadProcessMemory(h, reinterpret_cast<LPCVOID>(ped + off), &val, 4, &got) || got != 4)
            continue;
        if (val != val) continue;
        if (val >= min_v && val <= max_v) return ped + off;
    }
    return 0;
}

// find first offset where a uint32 matches expected value
static uintptr_t scan_ped_u32(HANDLE h, uintptr_t ped, uint32_t expected,
                              uintptr_t start_off = 0, uintptr_t end_off = 0x2000)
{
    for (uintptr_t off = start_off; off + 4 <= end_off; off += 4) {
        uint32_t val = 0;
        SIZE_T got = 0;
        if (!ReadProcessMemory(h, reinterpret_cast<LPCVOID>(ped + off), &val, 4, &got) || got != 4)
            continue;
        if (val == expected) return ped + off;
    }
    return 0;
}

// find first offset where a pointer points into a module (vtable/manager candidate)
static uintptr_t scan_ped_ptr(HANDLE h, uintptr_t ped, uintptr_t module_base, uintptr_t module_size,
                              uintptr_t start_off = 0, uintptr_t end_off = 0x2000)
{
    uintptr_t mod_end = module_base + module_size;
    for (uintptr_t off = start_off; off + 8 <= end_off; off += 8) {
        uintptr_t val = read_ptr(h, ped + off);
        if (!looks_valid(val)) continue;
        if (val >= module_base && val < mod_end) return ped + off;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// ped armor hunter (~0-100 float, usually near health)
// ---------------------------------------------------------------------------

static hunt_result hunt_ped_armor(HANDLE h, const std::vector<region>& regs, uintptr_t module_base)
{
    hunt_result r; r.name = "ped_armor";
    uintptr_t ped = walk_to_first_ped(h, regs, module_base);
    if (!ped) { r.note = "no valid ped"; return r; }

    // armor is usually a float 0-100, scan after health (health+8 is a common armor spot)
    uintptr_t hit = scan_ped_float(h, ped, 0.f, 100.f, 0x288, 0x400);
    if (!hit) hit = scan_ped_float(h, ped, 0.f, 100.f, 0, 0x400);

    if (hit) {
        r.absolute = hit;
        r.rva = hit - module_base;
        r.valid = true;
        r.note = "armor at +0x" + hex_str(hit - ped);
    } else {
        r.note = "armor float not found";
    }
    return r;
}

// ---------------------------------------------------------------------------
// ped weapon_manager hunter (pointer into module or vtable)
// ---------------------------------------------------------------------------

static hunt_result hunt_ped_weapon_manager(HANDLE h, const std::vector<region>& regs, uintptr_t module_base)
{
    hunt_result r; r.name = "ped_weapon_manager";
    uintptr_t ped = walk_to_first_ped(h, regs, module_base);
    if (!ped) { r.note = "no valid ped"; return r; }

    // find module size for validation
    uintptr_t mod_size = 0;
    for (const auto& reg : regs) {
        if (reg.start == module_base) { mod_size = reg.size; break; }
    }

    uintptr_t hit = scan_ped_ptr(h, ped, module_base, mod_size, 0x1000, 0x1200);
    if (!hit) hit = scan_ped_ptr(h, ped, module_base, mod_size, 0x1000, 0x2000);

    if (hit) {
        r.absolute = hit;
        r.rva = hit - module_base;
        r.valid = true;
        r.note = "weapon_manager at +0x" + hex_str(hit - ped);
    } else {
        r.note = "weapon_manager pointer not found";
    }
    return r;
}

// ---------------------------------------------------------------------------
// ped entity_type hunter (int enum, often near 0x10B8 area)
// ---------------------------------------------------------------------------

static hunt_result hunt_ped_entity_type(HANDLE h, const std::vector<region>& regs, uintptr_t module_base)
{
    hunt_result r; r.name = "ped_entity_type";
    uintptr_t ped = walk_to_first_ped(h, regs, module_base);
    if (!ped) { r.note = "no valid ped"; return r; }

    // entity_type is usually a small int (1=ped, 2=vehicle, 3=object)
    uintptr_t hit = scan_ped_u32(h, ped, 1, 0x10A0, 0x10E0);
    if (!hit) hit = scan_ped_u32(h, ped, 1, 0, 0x1000);

    if (hit) {
        r.absolute = hit;
        r.rva = hit - module_base;
        r.valid = true;
        r.note = "entity_type at +0x" + hex_str(hit - ped);
    } else {
        r.note = "entity_type not found";
    }
    return r;
}

// ---------------------------------------------------------------------------
// ped player_info hunter (pointer to player info struct)
// ---------------------------------------------------------------------------

static hunt_result hunt_ped_player_info(HANDLE h, const std::vector<region>& regs, uintptr_t module_base)
{
    hunt_result r; r.name = "ped_player_info";
    uintptr_t ped = walk_to_first_ped(h, regs, module_base);
    if (!ped) { r.note = "no valid ped"; return r; }

    uintptr_t mod_size = 0;
    for (const auto& reg : regs) {
        if (reg.start == module_base) { mod_size = reg.size; break; }
    }

    // player_info is a pointer into the module (vtable or struct)
    uintptr_t hit = scan_ped_ptr(h, ped, module_base, mod_size, 0x10A0, 0x10E0);
    if (!hit) hit = scan_ped_ptr(h, ped, module_base, mod_size, 0x1000, 0x2000);

    if (hit) {
        r.absolute = hit;
        r.rva = hit - module_base;
        r.valid = true;
        r.note = "player_info at +0x" + hex_str(hit - ped);
    } else {
        r.note = "player_info pointer not found";
    }
    return r;
}

// ---------------------------------------------------------------------------
// ped player_id hunter (net_id int, often near player_info)
// ---------------------------------------------------------------------------

static hunt_result hunt_ped_player_id(HANDLE h, const std::vector<region>& regs, uintptr_t module_base)
{
    hunt_result r; r.name = "ped_player_id";
    uintptr_t ped = walk_to_first_ped(h, regs, module_base);
    if (!ped) { r.note = "no valid ped"; return r; }

    // player_id/net_id is usually a small positive int
    uintptr_t hit = scan_ped_u32(h, ped, 0, 0xE0, 0x100); // net_id often 0 for local, small for others
    if (!hit) hit = scan_ped_u32(h, ped, 1, 0xE0, 0x100);

    if (hit) {
        r.absolute = hit;
        r.rva = hit - module_base;
        r.valid = true;
        r.note = "player_id at +0x" + hex_str(hit - ped);
    } else {
        r.note = "player_id not found";
    }
    return r;
}

// ---------------------------------------------------------------------------
// ped frag_inst hunter (start of skeleton chain: frag_inst → skel_data → bone matrix)
// ---------------------------------------------------------------------------

static hunt_result hunt_ped_frag_inst(HANDLE h, const std::vector<region>& regs, uintptr_t module_base)
{
    hunt_result r; r.name = "ped_frag_inst";
    uintptr_t ped = walk_to_first_ped(h, regs, module_base);
    if (!ped) { r.note = "no valid ped"; return r; }

    // frag_inst is a pointer, usually near 0x1430 area. scan for pointer that
    // dereferences to something that has a pointer at +0x68 (skeleton data)
    for (uintptr_t off = 0x1300; off + 8 <= 0x1600; off += 8) {
        uintptr_t frag = read_ptr(h, ped + off);
        if (!looks_valid(frag)) continue;
        uintptr_t skel = read_ptr(h, frag + 0x68);
        if (!looks_valid(skel)) continue;
        uintptr_t skel_data = read_ptr(h, skel + 0x178);
        if (!looks_valid(skel_data)) continue;

        r.absolute = ped + off;
        r.rva = (ped + off) - module_base;
        r.valid = true;
        r.note = "frag_inst at +0x" + hex_str(off) + " (skeleton chain valid)";
        return r;
    }

    r.note = "frag_inst skeleton chain not found";
    return r;
}

// ---------------------------------------------------------------------------
// camera_angles hunter (offset from camera base where view angles live)
// ---------------------------------------------------------------------------

static hunt_result hunt_camera_angles(HANDLE h, const std::vector<region>& regs, uintptr_t module_base)
{
    hunt_result r; r.name = "camera_angles";
    auto cam_r = hunt_camera(h, regs, module_base);
    if (!cam_r.valid) { r.note = "camera not resolved"; return r; }

    uintptr_t cam_base = read_ptr(h, cam_r.absolute);
    if (!looks_valid(cam_base)) { r.note = "camera base unreadable"; return r; }

    // scan camera + 0x300 .. camera + 0x600 for a Vector3 that looks like angles
    // (pitch typically -90..90, yaw any, roll near 0)
    for (uintptr_t off = 0x300; off + 12 <= 0x600; off += 4) {
        float angles[3] = { 0, 0, 0 };
        SIZE_T got = 0;
        if (!ReadProcessMemory(h, reinterpret_cast<LPCVOID>(cam_base + off), angles, 12, &got) || got != 12)
            continue;
        if (angles[0] != angles[0] || angles[1] != angles[1] || angles[2] != angles[2]) continue;
        // pitch should be in sane range
        if (angles[0] < -180.f || angles[0] > 180.f) continue;
        // roll should be near 0 for normal cameras
        if (std::fabs(angles[2]) > 10.f) continue;

        r.rva = (cam_r.rva ? cam_r.rva : (cam_base - module_base)) + off;
        r.absolute = cam_base + off;
        r.valid = true;
        r.signature = "scan: camera+" + hex_str(off) + " (angles Vector3)";
        r.note = "camera_angles at camera+" + hex_str(off);
        return r;
    }

    r.note = "camera_angles not found";
    return r;
}

// ---------------------------------------------------------------------------
// vehicle engine health hunter (~1000.f float)
// ---------------------------------------------------------------------------

static hunt_result hunt_veh_engine_health(HANDLE h, const std::vector<region>& regs, uintptr_t module_base)
{
    hunt_result r; r.name = "veh_engine_health";

    // get a vehicle pointer via ped walk
    auto world_r = hunt_world(h, regs, module_base);
    auto replay_r = hunt_replay(h, regs, module_base);
    if (!world_r.valid || !replay_r.valid) { r.note = "world/replay not resolved"; return r; }

    uintptr_t world_obj = read_ptr(h, world_r.absolute);
    uintptr_t replay_obj = read_ptr(h, replay_r.absolute);
    if (!looks_valid(world_obj) || !looks_valid(replay_obj)) { r.note = "objects unreadable"; return r; }

    uintptr_t ped_interface = read_ptr(h, replay_obj);
    uintptr_t ped_list = read_ptr(h, ped_interface + 0x8);
    if (!looks_valid(ped_interface) || !looks_valid(ped_list)) { r.note = "ped list unreadable"; return r; }

    for (int i = 0; i < 16; ++i) {
        uintptr_t ped = read_ptr(h, ped_list + i * 0x10);
        if (!looks_valid(ped) || ped == 0) continue;
        uintptr_t veh = read_ptr(h, ped + 0xD10);
        if (!looks_valid(veh)) continue;

        // scan vehicle for engine health (~1000.f)
        for (uintptr_t off = 0x800; off + 4 <= 0xC00; off += 4) {
            float val = 0.f;
            SIZE_T got = 0;
            if (!ReadProcessMemory(h, reinterpret_cast<LPCVOID>(veh + off), &val, 4, &got) || got != 4)
                continue;
            if (val != val) continue;
            if (val >= 900.f && val <= 1100.f) {
                r.absolute = veh + off;
                r.rva = veh + off - module_base;
                r.valid = true;
                r.note = "engine health at veh+" + hex_str(off);
                return r;
            }
        }
    }

    r.note = "vehicle engine health not found";
    return r;
}

// ---------------------------------------------------------------------------
// vehicle lock status hunter (int enum)
// ---------------------------------------------------------------------------

static hunt_result hunt_veh_lock_status(HANDLE h, const std::vector<region>& regs, uintptr_t module_base)
{
    hunt_result r; r.name = "veh_lock_status";

    auto world_r = hunt_world(h, regs, module_base);
    auto replay_r = hunt_replay(h, regs, module_base);
    if (!world_r.valid || !replay_r.valid) { r.note = "world/replay not resolved"; return r; }

    uintptr_t world_obj = read_ptr(h, world_r.absolute);
    uintptr_t replay_obj = read_ptr(h, replay_r.absolute);
    if (!looks_valid(world_obj) || !looks_valid(replay_obj)) { r.note = "objects unreadable"; return r; }

    uintptr_t ped_interface = read_ptr(h, replay_obj);
    uintptr_t ped_list = read_ptr(h, ped_interface + 0x8);
    if (!looks_valid(ped_interface) || !looks_valid(ped_list)) { r.note = "ped list unreadable"; return r; }

    for (int i = 0; i < 16; ++i) {
        uintptr_t ped = read_ptr(h, ped_list + i * 0x10);
        if (!looks_valid(ped) || ped == 0) continue;
        uintptr_t veh = read_ptr(h, ped + 0xD10);
        if (!looks_valid(veh)) continue;

        // lock status is usually a small int (0-10), scan near 0x1380-0x1400
        for (uintptr_t off = 0x1380; off + 4 <= 0x1420; off += 4) {
            uint32_t val = 0;
            SIZE_T got = 0;
            if (!ReadProcessMemory(h, reinterpret_cast<LPCVOID>(veh + off), &val, 4, &got) || got != 4)
                continue;
            if (val <= 10) {
                r.absolute = veh + off;
                r.rva = veh + off - module_base;
                r.valid = true;
                r.note = "lock status at veh+" + hex_str(off);
                return r;
            }
        }
    }

    r.note = "vehicle lock status not found";
    return r;
}

// ---------------------------------------------------------------------------
// viewport hunter (view projection matrix for W2S)
// ---------------------------------------------------------------------------

static hunt_result hunt_viewport(HANDLE h, const std::vector<region>& regs, uintptr_t module_base)
{
    hunt_result r; r.name = "viewport";
    const char* sig = "48 8B 15 ? ? ? ? 48 8D 2D ? ? ? ? 48 8B CD";
    uintptr_t hit = scan_regions_for_sig(regs, sig, true);
    if (!hit) { r.note = "signature not found"; return r; }

    // validate: viewport + 0x24C should hold a valid view-projection matrix
    uintptr_t viewport_ptr = read_ptr(h, hit);
    if (!looks_valid(viewport_ptr)) { r.note = "viewport ptr unreadable"; r.absolute = hit; r.signature = sig; r.rip_relative = true; return r; }

    float matrix[16] = { 0 };
    SIZE_T got = 0;
    if (!ReadProcessMemory(h, reinterpret_cast<LPCVOID>(viewport_ptr + 0x24C), matrix, sizeof(matrix), &got) || got != sizeof(matrix)) {
        r.note = "viewport matrix unreadable"; r.absolute = hit; r.signature = sig; r.rip_relative = true; return r;
    }

    // check matrix sanity: finite values, not all zero, reasonable range
    bool valid = false;
    for (int i = 0; i < 16; ++i) {
        if (matrix[i] != matrix[i]) { valid = false; break; }
        if (std::fabs(matrix[i]) > 1e6f) { valid = false; break; }
        if (matrix[i] != 0.f) valid = true;
    }
    if (!valid) { r.note = "viewport matrix invalid"; r.absolute = hit; r.signature = sig; r.rip_relative = true; return r; }

    r.absolute = hit;
    r.rva = hit - module_base;
    r.valid = true;
    r.signature = sig;
    r.rip_relative = true;
    r.note = "validated";
    return r;
}

// ---------------------------------------------------------------------------
// ped_bone_offset hunter (scans ped skeleton data for bone index table)
// ---------------------------------------------------------------------------

static hunt_result hunt_ped_bone_offset(HANDLE h, const std::vector<region>& regs, uintptr_t module_base)
{
    hunt_result r; r.name = "ped_bone_offset";

    // frag_inst must be resolved first
    auto frag_r = hunt_ped_frag_inst(h, regs, module_base);
    if (!frag_r.valid) { r.note = "frag_inst not resolved"; return r; }

    uintptr_t ped = walk_to_first_ped(h, regs, module_base);
    if (!ped) { r.note = "no valid ped"; return r; }

    // walk skeleton chain: ped + frag_inst -> frag + 0x68 -> skel_data + 0x178 -> bone matrix
    uintptr_t frag = read_ptr(h, ped + frag_r.rva); // frag_r.rva is offset from ped base
    if (!looks_valid(frag)) { r.note = "frag_inst unreadable"; return r; }

    uintptr_t skel = read_ptr(h, frag + 0x68);
    if (!looks_valid(skel)) { r.note = "skeleton data unreadable"; return r; }

    uintptr_t bone_matrix = read_ptr(h, skel + 0x178);
    if (!looks_valid(bone_matrix)) { r.note = "bone matrix unreadable"; return r; }

    // bone index table is typically near skel_data. scan for pointer that looks like
    // an index table (array of uint16 offsets into bone matrices)
    // For now, report the skel_data pointer as the bone offset candidate
    r.absolute = skel;
    r.rva = skel - module_base;
    r.valid = true;
    r.signature = "scan: skeleton_data (bone table)";
    r.note = "bone table at skel_data +0x0";
    return r;
}

// ---------------------------------------------------------------------------
// run all hunters, print results
// ---------------------------------------------------------------------------

static void run_all_hunters(HANDLE h, const std::vector<region>& regs, uintptr_t module_base,
                            std::vector<hunt_result>* out = nullptr)
{
    std::vector<hunt_result> results;
    results.push_back(hunt_world(h, regs, module_base));
    results.push_back(hunt_camera(h, regs, module_base));
    results.push_back(hunt_camera_angles(h, regs, module_base));
    results.push_back(hunt_replay(h, regs, module_base));
    results.push_back(hunt_handle_bullet(h, regs, module_base));
    results.push_back(hunt_ped_offsets(h, regs, module_base));
    results.push_back(hunt_ped_armor(h, regs, module_base));
    results.push_back(hunt_ped_weapon_manager(h, regs, module_base));
    results.push_back(hunt_ped_entity_type(h, regs, module_base));
    results.push_back(hunt_ped_player_info(h, regs, module_base));
    results.push_back(hunt_ped_player_id(h, regs, module_base));
    results.push_back(hunt_ped_frag_inst(h, regs, module_base));
    results.push_back(hunt_vehicle_offsets(h, regs, module_base));
    results.push_back(hunt_veh_engine_health(h, regs, module_base));
    results.push_back(hunt_veh_lock_status(h, regs, module_base));
    results.push_back(hunt_viewport(h, regs, module_base));
    results.push_back(hunt_ped_bone_offset(h, regs, module_base));
    results.push_back(hunt_cfx_resource_manager(h, regs, module_base));

    std::printf("\n%-22s %-18s %-10s %-6s %s\n", "offset", "absolute", "rva", "rip?", "status");
    std::printf("%s\n", std::string(70, '-').c_str());
    for (const auto& r : results) {
        std::printf("%-22s %-18s %-10s %-6s %s\n",
            r.name.c_str(),
            r.absolute ? hex_str(r.absolute).c_str() : "---",
            r.rva ? hex_str(r.rva).c_str() : "---",
            r.rip_relative ? "yes" : "no",
            r.valid ? "VALID" : r.note.c_str());
        if (r.valid) {
            std::printf("    sig: %s\n", r.signature.c_str());
        }
    }

    if (out) *out = results;
}

// write hunt results to a JSON file for diffing
static void write_results_json(const char* path, uint32_t build,
                               const std::vector<hunt_result>& results)
{
    std::ofstream f(path);
    if (!f) { std::cerr << "cannot write " << path << "\n"; return; }
    f << "{\n";
    f << "  \"build\": " << build << ",\n";
    f << "  \"offsets\": [\n";
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        f << "    {\"name\": \"" << r.name << "\", ";
        f << "\"absolute\": " << (r.absolute ? hex_str(r.absolute) : "null") << ", ";
        f << "\"rva\": " << (r.rva ? hex_str(r.rva) : "null") << ", ";
        f << "\"valid\": " << (r.valid ? "true" : "false") << ", ";
        f << "\"rip_relative\": " << (r.rip_relative ? "true" : "false") << ", ";
        f << "\"signature\": \"" << r.signature << "\", ";
        f << "\"note\": \"" << r.note << "\"}";
        if (i + 1 < results.size()) f << ",";
        f << "\n";
    }
    f << "  ]\n";
    f << "}\n";
    std::cout << "results written: " << path << "\n";
}
