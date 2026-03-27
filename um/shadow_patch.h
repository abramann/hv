#pragma once

// ============================================================
//  shadow_patch.h  –  EPT shadow-patching helpers
//
//  HOW IT WORKS:
//    EPT lets us keep TWO physical pages for the same GPA:
//      orig_pfn  →  used for READ / WRITE access  (clean, unpatched)
//      exec_pfn  →  used for EXECUTE access        (our patched copy)
//
//  Debuggers / memory scanners that read() the page see the
//  original bytes.  The CPU executes your patched bytes.
//
//  The exit-handler in exit-handlers.cpp already swaps the PTE's
//  page_frame_number on every EPT-violation, so we just need to:
//    1.  Read the original page via the hypervisor.
//    2.  Apply our byte patch to a copy.
//    3.  Allocate + VirtualLock a new page, copy patched bytes in.
//    4.  Hand both PFNs to install_ept_hook() on every logical CPU.
// ============================================================

#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <cstdio>
#include <cstdint>

#include "hv.h"   // um/hv.h – hypercall wrappers

namespace shadow {

    // ── Patch handle ────────────────────────────────────────────
    // Keep this alive for as long as the hook must stay active.
    // Destroying it without calling remove() leaves a dangling hook.
    struct patch_handle {
        uint64_t orig_pfn = 0;       // PFN of the real (unpatched) page
        uint8_t* exec_page = nullptr; // VirtualAlloc'd + VirtualLock'd exec copy
        bool     valid = false;
    };

    // ── Process helpers ─────────────────────────────────────────

    inline DWORD find_pid(const wchar_t* process_name) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return 0;

        PROCESSENTRY32W e{ sizeof(e) };
        DWORD pid = 0;
        if (Process32FirstW(snap, &e)) {
            do {
                if (!_wcsicmp(e.szExeFile, process_name)) {
                    pid = e.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snap, &e));
        }
        CloseHandle(snap);
        return pid;
    }

    // Returns the load address of a DLL *inside a remote process*.
    // Works even when ASLR shifts the base between boots.
    inline uintptr_t get_remote_module_base(DWORD pid, const wchar_t* mod_name) {
        HANDLE snap = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap == INVALID_HANDLE_VALUE) return 0;

        MODULEENTRY32W e{ sizeof(e) };
        uintptr_t base = 0;
        if (Module32FirstW(snap, &e)) {
            do {
                if (!_wcsicmp(e.szModule, mod_name)) {
                    base = reinterpret_cast<uintptr_t>(e.modBaseAddr);
                    break;
                }
            } while (Module32NextW(snap, &e));
        }
        CloseHandle(snap);
        return base;
    }

    // ── Core shadow-patch install ────────────────────────────────
    //
    //  target_cr3   – kernel CR3 of the target process
    //                 (from hv::query_process_cr3)
    //  target_va    – virtual address of the FIRST BYTE to patch
    //  patch_bytes  – replacement bytes
    //  patch_size   – number of bytes to replace
    //
    //  IMPORTANT: the patch must not cross a 4 KB page boundary.
    //  If you need to patch across pages, call install() twice.
    inline patch_handle install(
        uint64_t       target_cr3,
        uintptr_t      target_va,
        const uint8_t* patch_bytes,
        size_t         patch_size)
    {
        patch_handle result{};

        const uintptr_t page_va = target_va & ~0xFFFull;   // round down to page
        const size_t    offset = target_va & 0xFFFull;   // byte offset within page

        if (offset + patch_size > 0x1000) {
            printf("[-] shadow::install – patch crosses page boundary "
                "(offset=0x%zX size=0x%zX)\n", offset, patch_size);
            return result;
        }

        // ── 1. Read the original page through the hypervisor ──────
        //    This goes through the guest page tables, so we get exactly
        //    what the target process would see.
        std::vector<uint8_t> orig_page(0x1000, 0);
        size_t bytes_read = hv::read_virt_mem(
            target_cr3, orig_page.data(), reinterpret_cast<void*>(page_va), 0x1000);

        if (bytes_read != 0x1000) {
            // Page might not be present yet (demand-paging).
            // You can work around this by touching the page in the target
            // process first (e.g. via WriteProcessMemory of 1 byte).
            printf("[-] shadow::install – read_virt_mem only returned %zu bytes "
                "(page paged out?)\n", bytes_read);
            return result;
        }

        // ── 2. Get the physical page frame number of the original page ─
        uint64_t orig_pa = hv::get_physical_address(target_cr3,
            reinterpret_cast<void*>(page_va));
        if (!orig_pa) {
            printf("[-] shadow::install – get_physical_address returned 0 "
                "for VA 0x%llX\n", static_cast<uint64_t>(page_va));
            return result;
        }
        uint64_t orig_pfn = orig_pa >> 12;
        printf("[+] Original page  VA=0x%llX  PA=0x%llX  PFN=0x%llX\n",
            static_cast<uint64_t>(page_va), orig_pa, orig_pfn);

        // ── 3. Build the patched copy in a local buffer ────────────
        std::vector<uint8_t> patched_page = orig_page;   // start with original
        memcpy(patched_page.data() + offset, patch_bytes, patch_size);

        printf("[+] Patching bytes at offset 0x%zX: ", offset);
        for (size_t i = 0; i < patch_size; ++i)
            printf("%02X ", patch_bytes[i]);
        printf("\n");

        // ── 4. Allocate an executable page that won't be paged out ─
        //    VirtualLock guarantees the page stays in RAM (no physical
        //    address change) for as long as we hold the lock.
        uint8_t* exec_page = static_cast<uint8_t*>(VirtualAlloc(
            nullptr, 0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE));

        if (!exec_page) {
            printf("[-] shadow::install – VirtualAlloc failed (%lu)\n",
                GetLastError());
            return result;
        }

        // Touch the page so the OS actually maps it to a physical frame
        // before we try to lock it.
        *exec_page = 0xCC;

        if (!VirtualLock(exec_page, 0x1000)) {
            // Usually fails if the process doesn't have the
            // SeLockMemoryPrivilege or has hit its working-set limit.
            // Run the client as Administrator to be safe.
            printf("[-] shadow::install – VirtualLock failed (%lu)\n"
                "    Try running the client as Administrator.\n",
                GetLastError());
            VirtualFree(exec_page, 0, MEM_RELEASE);
            return result;
        }

        memcpy(exec_page, patched_page.data(), 0x1000);

        // ── 5. Get the PFN of our exec page ───────────────────────
        //    query_process_cr3(GetCurrentProcessId()) gives us the kernel
        //    CR3 for our own process, which the hypervisor needs to walk
        //    our page tables and find the physical address.
        uint64_t our_cr3 = hv::query_process_cr3(GetCurrentProcessId());
        uint64_t exec_pa = hv::get_physical_address(our_cr3, exec_page);
        if (!exec_pa) {
            printf("[-] shadow::install – failed to get PA of exec page\n");
            VirtualUnlock(exec_page, 0x1000);
            VirtualFree(exec_page, 0, MEM_RELEASE);
            return result;
        }
        uint64_t exec_pfn = exec_pa >> 12;
        printf("[+] Exec     page  VA=0x%p    PA=0x%llX  PFN=0x%llX\n",
            exec_page, exec_pa, exec_pfn);

        // ── 6. Install the EPT hook on EVERY logical processor ────
        //    install_ept_hook() modifies the EPT structures of the current
        //    vCPU only, so we pin the thread to each CPU in turn.
        bool all_ok = true;
        hv::for_each_cpu([&](uint32_t cpu_idx) {
            if (!hv::install_ept_hook(orig_pfn, exec_pfn)) {
                printf("[-] install_ept_hook failed on CPU %u\n", cpu_idx);
                all_ok = false;
            }
            else {
                printf("[+] Hook installed on CPU %u\n", cpu_idx);
            }
            });

        if (!all_ok) {
            // Best-effort cleanup – try to remove whatever got installed
            hv::for_each_cpu([&](uint32_t) {
                hv::remove_ept_hook(orig_pfn);
                });
            VirtualUnlock(exec_page, 0x1000);
            VirtualFree(exec_page, 0, MEM_RELEASE);
            return result;
        }

        result.orig_pfn = orig_pfn;
        result.exec_page = exec_page;
        result.valid = true;
        printf("[+] Shadow patch active.\n");
        return result;
    }

    // ── Remove a shadow patch ────────────────────────────────────
    inline void remove(patch_handle& h) {
        if (!h.valid) return;

        hv::for_each_cpu([&](uint32_t cpu_idx) {
            hv::remove_ept_hook(h.orig_pfn);
            printf("[+] Hook removed on CPU %u\n", cpu_idx);
            });

        VirtualUnlock(h.exec_page, 0x1000);
        VirtualFree(h.exec_page, 0, MEM_RELEASE);

        h = {};   // zero everything, mark invalid
        printf("[+] Shadow patch removed.\n");
    }

} // namespace shadow