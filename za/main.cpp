// sigfind — FiveM offset hunter & build-table generator
// language: C++, target: Windows 11, MSVC
//
// usage:
//   sigfind dump    --name FiveM_bXXXX_GTAProcess   (or --pid <pid>)
//   sigfind scan    --dump dumps\build_XXXX.bin [--out results.json] --all
//   sigfind scan-offline --dump dumps\build_XXXX.json [--out results.json] [--build N]
//   sigfind diff    --old results_A.json --new results_B.json
//   sigfind gen     --build <n> --in results.json [--out snippet.h]

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <atomic>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "kernel32.lib")

#include "scanner.hpp"
#include "utils.hpp"
#include "hunters.hpp"
#include "memory.hpp"

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// process helpers
// ---------------------------------------------------------------------------

static DWORD find_pid_by_window_class(const char* class_name)
{
    HWND w = FindWindowA(class_name, nullptr);
    if (!w) return 0;
    DWORD pid = 0;
    GetWindowThreadProcessId(w, &pid);
    return pid;
}

static DWORD find_pid_by_prefix(const char* prefix)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
    DWORD result = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_strnicmp(pe.szExeFile, prefix, strlen(prefix)) == 0) {
                result = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return result;
}

static std::string get_process_name(DWORD pid)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return "";
    char buf[MAX_PATH]{};
    DWORD n = sizeof(buf);
    if (!QueryFullProcessImageNameA(h, 0, buf, &n)) { CloseHandle(h); return ""; }
    CloseHandle(h);
    std::string s(buf);
    auto pos = s.find_last_of("\\/");
    return (pos != std::string::npos) ? s.substr(pos + 1) : s;
}

// ---------------------------------------------------------------------------
// module enumeration
// ---------------------------------------------------------------------------

static std::vector<module_info> enum_modules(DWORD pid)
{
    std::vector<module_info> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return out;
    MODULEENTRY32 me{}; me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) {
        do {
            module_info mi;
            mi.name = me.szModule;
            mi.base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
            mi.size = me.modBaseSize;
            out.push_back(mi);
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return out;
}

// ---------------------------------------------------------------------------
// memory dumping
// ---------------------------------------------------------------------------

static bool read_region(HANDLE h, uintptr_t start, size_t size, std::vector<uint8_t>& out)
{
    out.clear();
    out.reserve(size);
    constexpr size_t chunk = 0x1000;
    std::vector<uint8_t> tmp(chunk);
    for (size_t off = 0; off < size; off += chunk) {
        SIZE_T want = static_cast<SIZE_T>((off + chunk <= size) ? chunk : (size - off));
        SIZE_T got = 0;
        if (ReadProcessMemory(h, reinterpret_cast<LPCVOID>(start + off), tmp.data(), want, &got))
            out.insert(out.end(), tmp.data(), tmp.data() + got);
        else
            out.insert(out.end(), want, 0x00);
    }
    return true;
}

static std::vector<region> dump_process(HANDLE h, const std::vector<module_info>& mods)
{
    std::vector<region> regions;
    MEMORY_BASIC_INFORMATION mbi{};
    SYSTEM_INFO si{}; GetNativeSystemInfo(&si);
    uintptr_t addr = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    uintptr_t max_addr = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

    // Phase 1: collect candidate regions
    while (addr < max_addr) {
        if (!VirtualQueryEx(h, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) break;
        uintptr_t rstart = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        size_t rsize = mbi.RegionSize;

        bool readable = (mbi.State == MEM_COMMIT) &&
            !(mbi.Protect & PAGE_NOACCESS) &&
            !(mbi.Protect & PAGE_GUARD);

        if (readable && rsize >= 4096) {
            // Skip small private regions that don't belong to a known module
            // and aren't image-backed (they're usually thread stacks/heaps).
            bool in_module = false;
            for (const auto& m : mods) {
                if (rstart >= m.base && rstart < m.base + m.size) {
                    in_module = true;
                    break;
                }
            }
            bool is_image = (mbi.Type == MEM_IMAGE);
            if (in_module || is_image) {
                region r;
                r.start = rstart;
                r.size = rsize;
                for (const auto& m : mods) {
                    if (rstart >= m.base && rstart < m.base + m.size) {
                        r.module = m.name;
                        break;
                    }
                }
                regions.push_back(std::move(r));
            }
        }

        addr = rstart + rsize;
        if (addr <= rstart) break;
    }

    // Phase 2: read regions in parallel (64 KB chunks)
    constexpr size_t k_chunk = 0x10000;  // 64 KB per ReadProcessMemory call
    std::mutex out_mtx;
    std::vector<region> out;
    out.reserve(regions.size());

    unsigned int nthreads = std::thread::hardware_concurrency();
    if (nthreads == 0 || nthreads > 16) nthreads = 8;

    std::atomic<size_t> next_region{0};
    auto worker = [&]() {
        while (true) {
            size_t i = next_region.fetch_add(1);
            if (i >= regions.size()) break;

            const auto& reg = regions[i];
            region r;
            r.start = reg.start;
            r.size = reg.size;
            r.module = reg.module;
            r.buffer.resize(reg.size);

            SIZE_T total_read = 0;
            bool ok = true;
            for (size_t off = 0; off < reg.size; off += k_chunk) {
                SIZE_T want = static_cast<SIZE_T>((off + k_chunk <= reg.size) ? k_chunk : (reg.size - off));
                SIZE_T got = 0;
                if (!ReadProcessMemory(h, reinterpret_cast<LPCVOID>(reg.start + off),
                    r.buffer.data() + off, want, &got) || got != want) {
                    ok = false;
                    break;
                }
                total_read += got;
            }

            if (ok && total_read == reg.size) {
                std::lock_guard<std::mutex> lock(out_mtx);
                out.push_back(std::move(r));
            }
        }
    };

    std::vector<std::thread> threads;
    for (unsigned int t = 0; t < nthreads; ++t)
        threads.emplace_back(worker);
    for (auto& th : threads) th.join();

    // Also dump module ranges specifically (even if split across VQL regions)
    for (const auto& m : mods) {
        region mr;
        mr.start = m.base;
        mr.size = m.size;
        mr.module = m.name;
        mr.buffer.resize(m.size);
        SIZE_T total_read = 0;
        bool ok = true;
        for (size_t off = 0; off < m.size; off += k_chunk) {
            SIZE_T want = static_cast<SIZE_T>((off + k_chunk <= m.size) ? k_chunk : (m.size - off));
            SIZE_T got = 0;
            if (!ReadProcessMemory(h, reinterpret_cast<LPCVOID>(m.base + off),
                mr.buffer.data() + off, want, &got) || got != want) {
                ok = false;
                break;
            }
            total_read += got;
        }
        if (ok && total_read == m.size)
            out.push_back(std::move(mr));
    }

    return out;
}

// ---------------------------------------------------------------------------
// Binary dump format v2 (raw bytes, no hex encoding)
// ---------------------------------------------------------------------------
//
// File layout:
//   [header]
//     char        magic[8]   = "SIGFIND2"
//     uint32_t    version    = 2
//     uint32_t    pid
//     uint32_t    build      (0 = unknown)
//     uint64_t    index_offset
//   [index table, region_count entries]
//     uint64_t    start
//     uint64_t    size
//     uint64_t    data_offset
//     char        module[64]  (null-padded)
//   [raw data blocks]
//     uint8_t     data[size]  for each region in order
// ---------------------------------------------------------------------------

static void write_dump_binary(const char* path, DWORD pid, uint32_t build,
                              const std::vector<region>& regs)
{
    std::ofstream f(path, std::ios::binary);
    if (!f) { std::cerr << "cannot write " << path << "\n"; return; }

    // Header
    char magic[8] = { 'S','I','G','F','I','N','D','2' };
    uint32_t version = 2;
    uint32_t region_count = static_cast<uint32_t>(regs.size());
    uint64_t index_offset = 8 + 4 + 4 + 4 + 4 + 8;  // magic + version + pid + build + count + index_offset

    f.write(magic, 8);
    f.write(reinterpret_cast<const char*>(&version), 4);
    f.write(reinterpret_cast<const char*>(&pid), 4);
    f.write(reinterpret_cast<const char*>(&build), 4);
    f.write(reinterpret_cast<const char*>(&region_count), 4);
    f.write(reinterpret_cast<const char*>(&index_offset), 8);

    // Index table
    uint64_t data_offset = index_offset + static_cast<uint64_t>(region_count) * (8 + 8 + 8 + 64);
    for (size_t i = 0; i < regs.size(); ++i) {
        const auto& r = regs[i];
        f.write(reinterpret_cast<const char*>(&r.start), 8);
        f.write(reinterpret_cast<const char*>(&r.size), 8);
        f.write(reinterpret_cast<const char*>(&data_offset), 8);
        char module[64] = { 0 };
        size_t mlen = r.module.size();
        if (mlen > 63) mlen = 63;
        std::memcpy(module, r.module.c_str(), mlen);
        f.write(module, 64);
        data_offset += r.size;
    }

    // Raw data blocks
    for (const auto& r : regs) {
        if (!r.buffer.empty())
            f.write(reinterpret_cast<const char*>(r.buffer.data()), static_cast<std::streamsize>(r.buffer.size()));
    }

    f.close();
    std::cout << "dump written: " << path << " (" << regs.size() << " regions)\n";
}

// Load regions from a binary dump v2 file
static std::vector<region> load_regions_from_dump(const char* path)
{
    std::vector<region> out;
    std::ifstream f(path, std::ios::binary);
    if (!f) { std::cerr << "cannot open " << path << "\n"; return out; }

    // Read header
    char magic[8] = { 0 };
    f.read(magic, 8);
    if (std::memcmp(magic, "SIGFIND2", 8) != 0) {
        std::cerr << "not a sigfind v2 dump file\n";
        return out;
    }
    uint32_t version = 0, pid = 0, build = 0, region_count = 0;
    uint64_t index_offset = 0;
    f.read(reinterpret_cast<char*>(&version), 4);
    f.read(reinterpret_cast<char*>(&pid), 4);
    f.read(reinterpret_cast<char*>(&build), 4);
    f.read(reinterpret_cast<char*>(&region_count), 4);
    f.read(reinterpret_cast<char*>(&index_offset), 8);

    if (version != 2) {
        std::cerr << "unsupported dump version: " << version << "\n";
        return out;
    }

    // Read index table (exactly region_count entries)
    f.seekg(index_offset);
    std::vector<uint64_t> starts, sizes, data_offsets;
    std::vector<std::string> modules;
    starts.reserve(region_count);
    sizes.reserve(region_count);
    data_offsets.reserve(region_count);
    modules.reserve(region_count);

    for (uint32_t i = 0; i < region_count; ++i) {
        uint64_t start = 0, size = 0, data_off = 0;
        f.read(reinterpret_cast<char*>(&start), 8);
        f.read(reinterpret_cast<char*>(&size), 8);
        f.read(reinterpret_cast<char*>(&data_off), 8);
        char module[65] = { 0 };
        f.read(module, 64);
        if (f.fail()) break;

        starts.push_back(start);
        sizes.push_back(size);
        data_offsets.push_back(data_off);
        modules.emplace_back(module);
    }

    // Read data blocks (skip unreasonably large ones)
    const uint64_t k_max_region_size = 256ull * 1024 * 1024;  // 256 MB max per region
    out.reserve(starts.size());
    for (size_t i = 0; i < starts.size(); ++i) {
        if (sizes[i] == 0 || sizes[i] > k_max_region_size) continue;

        region r;
        r.start = starts[i];
        r.size = sizes[i];
        r.module = modules[i];
        r.buffer.resize(sizes[i]);

        f.seekg(data_offsets[i]);
        f.read(reinterpret_cast<char*>(r.buffer.data()), static_cast<std::streamsize>(sizes[i]));
        out.push_back(std::move(r));
    }

    std::cout << "loaded " << out.size() << " regions from " << path << "\n";
    return out;
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------

static int cmd_dump(int argc, char** argv)
{
    DWORD pid = 0;
    std::string name;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--pid" && i + 1 < argc) pid = static_cast<DWORD>(std::strtoul(argv[++i], nullptr, 10));
        else if (std::string(argv[i]) == "--name" && i + 1 < argc) name = argv[++i];
    }

    if (!pid && name.empty()) {
        std::cerr << "usage: sigfind dump --pid <pid> | --name FiveM_bXXXX_GTAProcess\n";
        return 1;
    }
    if (!pid) pid = find_pid_by_prefix(name.c_str());
    if (!pid) { std::cerr << "process not found\n"; return 1; }

    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) { std::cerr << "OpenProcess failed: " << GetLastError() << "\n"; return 1; }

    std::string proc_name = get_process_name(pid);
    auto mods = enum_modules(pid);
    auto regs = dump_process(h, mods);
    CloseHandle(h);

    fs::create_directories("dumps");
    std::string path = "dumps\\build_" + std::to_string(pid) + ".bin";
    write_dump_binary(path.c_str(), pid, 0, regs);
    return 0;
}

static int cmd_scan(int argc, char** argv)
{
    std::string dump_path;
    std::string out_path;
    bool all = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--dump" && i + 1 < argc) dump_path = argv[++i];
        else if (a == "--out" && i + 1 < argc) out_path = argv[++i];
        else if (a == "--all") all = true;
    }
    if (dump_path.empty()) {
        std::cerr << "usage: sigfind scan --dump dumps\\build_XXXX.bin [--out results.json] --all\n";
        return 1;
    }

    size_t pos = dump_path.find_last_of("\\/");
    std::string fname = (pos != std::string::npos) ? dump_path.substr(pos + 1) : dump_path;
    size_t b = fname.find("build_");
    size_t e = fname.find(".json");
    if (b == std::string::npos || e == std::string::npos) {
        std::cerr << "cannot parse pid from dump filename\n";
        return 1;
    }
    DWORD pid = static_cast<DWORD>(std::strtoul(fname.substr(b + 6, e - b - 6).c_str(), nullptr, 10));
    uint32_t build = 0;
    std::string proc_name = get_process_name(pid);
    size_t pb = proc_name.find("_b");
    if (pb != std::string::npos && pb + 6 <= proc_name.size()) {
        try { build = static_cast<uint32_t>(std::stoul(proc_name.substr(pb + 2, 4))); } catch (...) {}
    }

    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) { std::cerr << "OpenProcess failed: " << GetLastError() << "\n"; return 1; }

    auto mods = enum_modules(pid);
    uintptr_t module_base = 0;
    for (const auto& m : mods) {
        if (m.name == proc_name || m.name == proc_name.substr(0, proc_name.find('.'))) {
            module_base = m.base;
            break;
        }
    }
    if (!module_base && !mods.empty()) module_base = mods[0].base;

    auto regs = dump_process(h, mods);

    std::vector<hunt_result> results;
    run_all_hunters(h, regs, module_base, &results);
    CloseHandle(h);

    if (!out_path.empty()) {
        write_results_json(out_path.c_str(), build, results);
    }

    (void)all;
    return 0;
}

// parse a results JSON file into hunt_result vectors (simple hand-rolled parser)
static std::vector<hunt_result> read_results_json(const char* path, uint32_t& out_build)
{
    std::vector<hunt_result> results;
    out_build = 0;
    std::ifstream f(path);
    if (!f) { std::cerr << "cannot open " << path << "\n"; return results; }
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    size_t bd = content.find("\"build\":");
    if (bd != std::string::npos) {
        size_t start = content.find_first_of("0123456789", bd + 8);
        if (start != std::string::npos) {
            size_t end = content.find_first_not_of("0123456789", start);
            out_build = static_cast<uint32_t>(std::stoul(content.substr(start, end - start)));
        }
    }

    size_t pos = 0;
    while ((pos = content.find("\"name\":", pos)) != std::string::npos) {
        hunt_result r;
        size_t qs = content.find('"', pos + 7);
        size_t qe = content.find('"', qs + 1);
        if (qs == std::string::npos || qe == std::string::npos) break;
        r.name = content.substr(qs + 1, qe - qs - 1);

        auto get_field = [&](const char* field, std::string& out) {
            size_t fs = content.find(field, pos);
            if (fs == std::string::npos) return false;
            size_t q1 = content.find('"', fs + strlen(field));
            if (q1 == std::string::npos) return false;
            size_t q2 = content.find('"', q1 + 1);
            if (q2 == std::string::npos) return false;
            out = content.substr(q1 + 1, q2 - q1 - 1);
            return true;
        };

        auto get_hex = [&](const char* field, uintptr_t& out) {
            size_t fs = content.find(field, pos);
            if (fs == std::string::npos) return false;
            size_t vs = content.find_first_of("0123456789", fs + strlen(field));
            if (vs == std::string::npos) { out = 0; return true; }
            size_t ve = content.find_first_not_of("0123456789abcdefxX", vs);
            std::string hex = content.substr(vs, ve - vs);
            out = static_cast<uintptr_t>(std::stoull(hex, nullptr, 16));
            return true;
        };

        auto get_bool = [&](const char* field, bool& out) {
            size_t fs = content.find(field, pos);
            if (fs == std::string::npos) return false;
            size_t vs = content.find_first_of("tf", fs + strlen(field));
            if (vs == std::string::npos) return false;
            out = (content[vs] == 't');
            return true;
        };

        get_field("\"signature\": \"", r.signature);
        get_field("\"note\": \"", r.note);
        get_hex("\"absolute\": ", r.absolute);
        get_hex("\"rva\": ", r.rva);
        get_bool("\"valid\": ", r.valid);
        get_bool("\"rip_relative\": ", r.rip_relative);

        results.push_back(r);
        pos = qe + 1;
    }

    return results;
}

static int cmd_scan_offline(int argc, char** argv)
{
    std::string dump_path;
    std::string out_path;
    uint32_t build = 0;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--dump" && i + 1 < argc) dump_path = argv[++i];
        else if (a == "--out" && i + 1 < argc) out_path = argv[++i];
        else if (a == "--build" && i + 1 < argc) build = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
    }
    if (dump_path.empty()) {
        std::cerr << "usage: sigfind scan-offline --dump dumps\\build_XXXX.json [--out results.json] [--build N]\n";
        return 1;
    }

    // load regions from binary dump v2
    std::vector<region> regs = load_regions_from_dump(dump_path.c_str());
    if (regs.empty()) return 1;

    // find module base
    uintptr_t module_base = 0;
    for (const auto& r : regs) {
        if (!r.module.empty() && r.module.find("FiveM") != std::string::npos) {
            module_base = r.start;
            break;
        }
    }
    if (!module_base && !regs.empty()) module_base = regs[0].start;

    // offline hunters using blob_read instead of ReadProcessMemory
    std::vector<hunt_result> results;

    // --- world ---
    {
        hunt_result r; r.name = "world";
        const char* sig = "48 8B 05 ? ? ? ? 33 D2 48 8B 40 08 8A CA 48 85 C0 74 16 48 8B";
        uintptr_t hit = scan_regions_for_sig(regs, sig, true);
        if (hit) {
            uintptr_t world_obj = blob_read_ptr(regs, hit);
            if (looks_valid(world_obj)) {
                uintptr_t ped_chain = blob_read_ptr(regs, world_obj + 0x8);
                if (looks_valid(ped_chain)) {
                    r.absolute = hit;
                    r.rva = hit - module_base;
                    r.valid = true;
                    r.signature = sig;
                    r.rip_relative = true;
                    r.note = "validated (offline)";
                } else {
                    r.note = "ped chain unreadable (offline)";
                    r.absolute = hit; r.signature = sig; r.rip_relative = true;
                }
            } else {
                r.note = "world obj unreadable (offline)";
                r.absolute = hit; r.signature = sig; r.rip_relative = true;
            }
        } else {
            r.note = "signature not found";
        }
        results.push_back(r);
    }

    // --- camera ---
    {
        hunt_result r; r.name = "camera";
        const char* sig = "48 8B 05 ? ? ? ? 48 8B 98 ? ? ? ? EB";
        uintptr_t hit = scan_regions_for_sig(regs, sig, true);
        if (hit) {
            uintptr_t cam_base = blob_read_ptr(regs, hit);
            if (looks_valid(cam_base)) {
                float angles[3] = { 0, 0, 0 };
                if (blob_read(regs, cam_base + 0x3D0, angles, 12)) {
                    bool valid = true;
                    for (int i = 0; i < 3; ++i) {
                        if (angles[i] != angles[i] || angles[i] < -360.f || angles[i] > 360.f) valid = false;
                    }
                    if (valid) {
                        r.absolute = hit;
                        r.rva = hit - module_base;
                        r.valid = true;
                        r.signature = sig;
                        r.rip_relative = true;
                        r.note = "validated (offline)";
                    } else {
                        r.note = "camera angles not finite (offline)";
                        r.absolute = hit; r.signature = sig; r.rip_relative = true;
                    }
                } else {
                    r.note = "camera angles unreadable (offline)";
                    r.absolute = hit; r.signature = sig; r.rip_relative = true;
                }
            } else {
                r.note = "camera base unreadable (offline)";
                r.absolute = hit; r.signature = sig; r.rip_relative = true;
            }
        } else {
            r.note = "signature not found";
        }
        results.push_back(r);
    }

    // --- replay_interface ---
    {
        hunt_result r; r.name = "replay_interface";
        const char* sig = "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48 8D 4C 24 ?? E8 ?? ?? ?? ?? 48 8B 9C 24";
        uintptr_t hit = scan_regions_for_sig(regs, sig, true);
        if (hit) {
            uintptr_t replay = blob_read_ptr(regs, hit);
            if (looks_valid(replay)) {
                r.absolute = hit;
                r.rva = hit - module_base;
                r.valid = true;
                r.signature = sig;
                r.rip_relative = true;
                r.note = "validated (offline)";
            } else {
                r.note = "replay ptr unreadable (offline)";
                r.absolute = hit; r.signature = sig; r.rip_relative = true;
            }
        } else {
            r.note = "signature not found";
        }
        results.push_back(r);
    }

    // --- handle_bullet ---
    {
        hunt_result r; r.name = "handle_bullet";
        const char* sig = "F3 41 0F 10 19 F3 41 0F 10 41 04 F3 41 0F 10 51 08";
        uintptr_t hit = scan_regions_for_sig(regs, sig, false);
        if (hit) {
            std::vector<uint8_t> actual(15);
            if (blob_read(regs, hit, actual.data(), 15)) {
                std::vector<uint8_t> expected = { 0xF3,0x41,0x0F,0x10,0x19, 0xF3,0x41,0x0F,0x10,0x41,0x04, 0xF3,0x41,0x0F,0x10,0x51,0x08 };
                bool match = true;
                for (size_t i = 0; i < 15; ++i) {
                    if (actual[i] != expected[i]) { match = false; break; }
                }
                if (match) {
                    r.absolute = hit;
                    r.rva = hit - module_base;
                    r.valid = true;
                    r.signature = sig;
                    r.rip_relative = false;
                    r.note = "validated (offline)";
                } else {
                    r.note = "bytes mismatch (offline)";
                    r.absolute = hit; r.signature = sig;
                }
            } else {
                r.note = "cannot read hook site (offline)";
                r.absolute = hit; r.signature = sig;
            }
        } else {
            r.note = "signature not found";
        }
        results.push_back(r);
    }

    // print results
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

    if (!out_path.empty()) {
        write_results_json(out_path.c_str(), build, results);
    }

    return 0;
}

static int cmd_diff(int argc, char** argv)
{
    std::string old_path, new_path;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--old" && i + 1 < argc) old_path = argv[++i];
        else if (a == "--new" && i + 1 < argc) new_path = argv[++i];
    }
    if (old_path.empty() || new_path.empty()) {
        std::cerr << "usage: sigfind diff --old results_A.json --new results_B.json\n";
        return 1;
    }

    uint32_t build_a = 0, build_b = 0;
    auto ra = read_results_json(old_path.c_str(), build_a);
    auto rb = read_results_json(new_path.c_str(), build_b);

    std::unordered_map<std::string, hunt_result> ma, mb;
    for (const auto& r : ra) ma[r.name] = r;
    for (const auto& r : rb) mb[r.name] = r;

    std::printf("\n%-22s %-18s %-18s %-10s %s\n", "offset", "old RVA", "new RVA", "status", "note");
    std::printf("%s\n", std::string(70, '-').c_str());

    for (const auto& kv : ma) {
        const std::string& name = kv.first;
        const hunt_result& rA = kv.second;
        auto it = mb.find(name);
        if (it == mb.end()) {
            std::printf("%-22s %-18s %-18s %-10s %s\n",
                name.c_str(),
                rA.rva ? hex_str(rA.rva).c_str() : "---",
                "---",
                "MISSING",
                rA.note.c_str());
            continue;
        }
        const hunt_result& rB = it->second;

        if (!rA.valid && !rB.valid) {
            std::printf("%-22s %-18s %-18s %-10s %s\n",
                name.c_str(), "---", "---", "BOTH_INVALID", "signature missing in both");
        } else if (rA.valid && !rB.valid) {
            std::printf("%-22s %-18s %-18s %-10s %s\n",
                name.c_str(), hex_str(rA.rva).c_str(), "---", "BROKEN", rB.note.c_str());
        } else if (!rA.valid && rB.valid) {
            std::printf("%-22s %-18s %-18s %-10s %s\n",
                name.c_str(), "---", hex_str(rB.rva).c_str(), "FIXED", "newly resolved");
        } else if (rA.rva == rB.rva) {
            std::printf("%-22s %-18s %-18s %-10s %s\n",
                name.c_str(), hex_str(rA.rva).c_str(), hex_str(rB.rva).c_str(), "STABLE", "unchanged");
        } else {
            int64_t delta = static_cast<int64_t>(rB.rva) - static_cast<int64_t>(rA.rva);
            std::string delta_str = (delta > 0 ? "+" : "") + std::to_string(delta);
            std::printf("%-22s %-18s %-18s %-10s %s\n",
                name.c_str(), hex_str(rA.rva).c_str(), hex_str(rB.rva).c_str(), "SHIFTED", delta_str.c_str());
        }
    }

    for (const auto& kv : mb) {
        const std::string& name = kv.first;
        if (ma.find(name) == ma.end()) {
            const hunt_result& rB = kv.second;
            std::printf("%-22s %-18s %-18s %-10s %s\n",
                name.c_str(), "---", rB.rva ? hex_str(rB.rva).c_str() : "---", "NEW", rB.note.c_str());
        }
    }

    std::printf("\nbuild %u -> build %u\n", build_a, build_b);
    return 0;
}

static int cmd_gen(int argc, char** argv)
{
    std::string in_path, out_path, merge_path;
    uint32_t build = 0;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--build" && i + 1 < argc) build = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 10));
        else if (a == "--in" && i + 1 < argc) in_path = argv[++i];
        else if (a == "--out" && i + 1 < argc) out_path = argv[++i];
        else if (a == "--merge" && i + 1 < argc) merge_path = argv[++i];
    }
    if (in_path.empty()) {
        std::cerr << "usage: sigfind gen --build <n> --in results.json [--out snippet.h] [--merge build_table.hpp]\n";
        return 1;
    }

    uint32_t file_build = 0;
    auto results = read_results_json(in_path.c_str(), file_build);
    if (!build) build = file_build;

    auto find_rva = [&](const char* name) -> uintptr_t {
        for (const auto& r : results) {
            if (r.name == name && r.valid) return r.rva;
        }
        return 0;
    };

    // Build the entry text - exactly 21 fields matching build_entry struct
    std::vector<uintptr_t> values;
    values.push_back(find_rva("world"));               // world_rva
    values.push_back(find_rva("replay_interface"));    // replay_rva
    values.push_back(find_rva("viewport"));            // viewport_rva
    values.push_back(find_rva("camera"));              // camera_rva
    values.push_back(find_rva("camera_angles"));       // camera_angles_rva
    values.push_back(find_rva("handle_bullet"));       // handle_bullet_rva
    uintptr_t ped_health = find_rva("ped_health");
    values.push_back(ped_health);                      // health
    values.push_back(ped_health ? ped_health + 4 : 0); // max_health
    values.push_back(find_rva("ped_armor"));           // armor
    values.push_back(find_rva("ped_weapon_manager"));  // weapon_manager
    values.push_back(find_rva("ped_entity_type"));     // entity_type
    values.push_back(find_rva("ped_player_info"));     // player_info
    values.push_back(find_rva("ped_player_id"));       // player_id
    values.push_back(find_rva("ped_bone_offset"));     // bone_offset
    values.push_back(find_rva("ped_frag_inst"));       // frag_inst
    values.push_back(0x10);                            // vehicle_interface
    values.push_back(0x180);                           // vehicle_list
    values.push_back(0x188);                           // vehicle_maximum
    values.push_back(find_rva("veh_body_health"));     // veh_body_health
    values.push_back(find_rva("veh_engine_health"));   // veh_engine_health
    values.push_back(find_rva("veh_lock_status"));     // veh_lock_status

    // Build entry line
    std::string entry = "{";
    entry += std::to_string(build) + ", {\n    ";
    for (size_t i = 0; i < values.size(); ++i) {
        entry += hex_str(values[i]);
        if (i + 1 < values.size()) entry += ", ";
    }
    entry += "\n}";

    std::string entry_line = entry + "},\n";

    // Merge into existing build_table.hpp if requested
    if (!merge_path.empty()) {
        std::ifstream mf(merge_path);
        if (!mf) { std::cerr << "cannot open " << merge_path << "\n"; return 1; }
        std::string content((std::istreambuf_iterator<char>(mf)), std::istreambuf_iterator<char>());
        mf.close();

        // Find existing entry for this build
        std::string search = "{" + std::to_string(build) + ", {";
        size_t pos = content.find(search);
        if (pos != std::string::npos) {
            // Replace existing entry: find the closing "}},\n" after this entry
            size_t end = content.find("}},\n", pos);
            if (end != std::string::npos) {
                end += 4;  // include "}},\n"
                content.replace(pos, end - pos, entry_line);
            } else {
                std::cerr << "warning: could not find end of existing entry for build " << build << "\n";
            }
        } else {
            // Append before "// To add a new FiveM build" comment
            size_t comment_pos = content.find("// To add a new FiveM build");
            if (comment_pos != std::string::npos) {
                content.insert(comment_pos, entry_line);
            } else {
                size_t last_close = content.rfind("}},\n");
                if (last_close != std::string::npos) {
                    content.insert(last_close, entry_line);
                } else {
                    std::cerr << "warning: could not find insertion point in " << merge_path << "\n";
                }
            }
        }

        std::ofstream of(merge_path);
        if (!of) { std::cerr << "cannot write " << merge_path << "\n"; return 1; }
        of << content;
        of.close();
        std::cout << "merged build " << build << " into " << merge_path << "\n";
    }

    std::ostream* os = &std::cout;
    std::ofstream out_file;
    if (!out_path.empty()) {
        out_file.open(out_path);
        if (!out_file) { std::cerr << "cannot open " << out_path << "\n"; return 1; }
        os = &out_file;
    }

    *os << "// auto-generated by sigfind for build " << build << "\n";
    *os << entry_line;

    if (!out_path.empty()) {
        out_file.close();
        std::cout << "snippet written: " << out_path << "\n";
    }

    return 0;
}

static int cmd_help()
{
    std::cout << "sigfind — FiveM offset hunter\n"
              << "commands:\n"
              << "  dump  --pid <n> | --name <exe>   dump process memory to dumps/\n"
              << "  scan  --dump <file> [--out results.json] --all   hunt signatures (live)\n"
              << "  scan-offline --dump <file> [--out results.json] [--build N]   hunt signatures from dump (no attach)\n"
              << "  diff  --old <file> --new <file>   compare two build result files\n"
              << "  gen   --build <n> --in <json> [--out snippet.h] [--merge build_table.hpp]   emit build_table snippet\n"
              << "\n";
    return 0;
}

int main(int argc, char** argv)
{
    if (argc < 2) return cmd_help();
    std::string cmd = argv[1];
    if (cmd == "dump") return cmd_dump(argc - 1, argv + 1);
    if (cmd == "scan") return cmd_scan(argc - 1, argv + 1);
    if (cmd == "scan-offline") return cmd_scan_offline(argc - 1, argv + 1);
    if (cmd == "diff") return cmd_diff(argc - 1, argv + 1);
    if (cmd == "gen") return cmd_gen(argc - 1, argv + 1);
    if (cmd == "help" || cmd == "--help" || cmd == "-h") return cmd_help();
    std::cerr << "unknown command: " << cmd << "\n";
    return cmd_help();
}


