#include <iostream>
#include <Windows.h>
#include "hv.h"
#include "shadow_patch.h"

// ================================================================
//  Demo: shadow-patch MessageBoxW inside notepad.exe
//
//  What it does:
//    Replace the first 6 bytes of MessageBoxW with:
//      mov eax, 1   ; IDOK
//      ret
//    When notepad calls MessageBoxW, it silently returns IDOK.
//    Any tool that reads notepad's USER32.dll page sees the
//    original, unpatched bytes — stealth by design.
//
//  To trigger:
//    1. Open notepad, type something, then close the window.
//    2. Windows shows "Save changes?" — with the hook active
//       the dialog disappears instantly (MessageBoxW → IDOK).
//
//  IMPORTANT NOTES:
//    * Run as Administrator (needed for VirtualLock and to load
//      the driver / communicate with the HV).
//    * Launch notepad.exe BEFORE running this tool so its pages
//      are already mapped into physical memory.
//    * USER32.dll pages are SHARED across all processes (CoW).
//      This patch will affect MessageBoxW for every process that
//      shares that physical page until you call shadow::remove().
//      For a process-isolated hook see the "per-process" note below.
// ================================================================

// ── Patch bytes ─────────────────────────────────────────────────
//
//   B8 01 00 00 00   mov eax, 1   ; return value = IDOK
//   C3               ret
//
// These 6 bytes overwrite the very first instruction(s) of
// MessageBoxW.  On MSVC x64 the function prologue is typically:
//   mov [rsp+8], rbx  (4C 89 44 24 08)  – 5 bytes
//   push rdi          (57)               – 1 byte
// ...so 6 bytes is a clean replacement.
static constexpr uint8_t k_patch[] = {
    0xEB                          
};

// ────────────────────────────────────────────────────────────────
//  PER-PROCESS ISOLATION  (advanced note)
//
//  DLL pages are physically shared via copy-on-write.  If you need
//  the patch to affect ONLY notepad and not every process:
//
//    Step 1 – force a private physical copy by writing a dummy byte
//             via WriteProcessMemory (triggers CoW in the kernel).
//    Step 2 – NOW get_physical_address() will return a page that is
//             private to notepad, so the EPT hook is isolated.
//
//  Implementation:
//      HANDLE hp = OpenProcess(PROCESS_VM_WRITE|PROCESS_VM_OPERATION,
//                              FALSE, pid);
//      BYTE tmp = 0x90;
//      WriteProcessMemory(hp, (LPVOID)target_va, &tmp, 1, nullptr);
//      // Immediately restore original byte so the page content is
//      // still correct before we apply our shadow patch.
//      WriteProcessMemory(hp, (LPVOID)target_va, &orig_byte, 1, nullptr);
//      CloseHandle(hp);
//  After this, the physical page for that VA is private to notepad.
// ────────────────────────────────────────────────────────────────



int main() {
    // ── Check HV ────────────────────────────────────────────────
    if (!hv::is_hv_running()) {
        printf("[-] Hypervisor is not running. Load hv.sys first.\n");
        return 1;
    }
    printf("[+] Hypervisor is running (signature matched)\n");

    // ── Find notepad ────────────────────────────────────────────
    DWORD pid = shadow::find_pid(L"crackme.exe");
    if (!pid) {
        printf("[-] crackme.exe is not running. Launch it first.\n");
        return 1;
    }
    printf("[+] Found crackme.exe  PID=%lu\n", pid);

    // ── Get notepad's kernel CR3 ─────────────────────────────────
    uint64_t target_cr3 = hv::query_process_cr3(pid);
    if (!target_cr3) {
        printf("[-] query_process_cr3 failed\n");
        return 1;
    }
    printf("[+] crackme.exe  CR3=0x%llX\n", target_cr3);

    uintptr_t target_va = 0x000000014000131D;
    printf("[+] MessageBoxW in notepad: 0x%llX\n",
        static_cast<uint64_t>(target_va));

    // ── Print original bytes (as seen by a debugger) ─────────────
    {
        uint8_t orig[1] = {};
        hv::read_virt_mem(target_cr3, orig,
            reinterpret_cast<void*>(target_va), sizeof(orig));
        printf("[+] Original bytes at MessageBoxW: ");
        for (auto b : orig) printf("%02X ", b);
        printf("\n");
    }

    // ── Install shadow patch ─────────────────────────────────────
    printf("\n[*] Installing shadow patch...\n");
    auto hook = shadow::install(target_cr3, target_va,
        k_patch, sizeof(k_patch));
    if (!hook.valid) {
        printf("[-] shadow::install failed\n");
        return 1;
    }

    // ── Verify: reading back should still show ORIGINAL bytes ────
    {
        uint8_t check[1] = {};
        hv::read_virt_mem(target_cr3, check,
            reinterpret_cast<void*>(target_va), sizeof(check));
        printf("\n[*] Bytes as seen by a memory reader (should be original): ");
        for (auto b : check) printf("%02X ", b);
        printf("\n");
    }

    printf("\n========================================\n");
    printf("  Shadow patch is ACTIVE.\n");
    printf("  In notepad: type something and close\n");
    printf("  the window – the save dialog will\n");
    printf("  vanish (MessageBoxW returns IDOK).\n");
    printf("========================================\n");
    printf("\nPress ENTER to remove the hook...\n");
    (void)getchar();

    // ── Remove hook and clean up ─────────────────────────────────
    printf("\n[*] Removing shadow patch...\n");
    shadow::remove(hook);

    printf("[+] Done.\n");
    return 0;
}