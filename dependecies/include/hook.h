#pragma once
#include "../include/process.h"

struct Hook {
    void** targetSlot;  // address of the pointer we're replacing
    void* original;     // original function pointer

    bool hook(Process& proc, void* jmpInstruction, void* newTarget) {
        // calculate address of the pointer slot
        // jmp [rip + offset] - offset is at byte 3, pointer is at instruction + 7 + offset
        int32_t offset = 0;
        SIZE_T read;
        proc.read_mem((PVOID)((uintptr_t)jmpInstruction + 3), &offset, sizeof(int32_t), &read);

        targetSlot = (void**)((uintptr_t)jmpInstruction + 7 + offset);

        // read original
        proc.read_mem(targetSlot, &original, sizeof(void*), &read);
        std::cout << "Original target: " << original << std::endl;

        // write new target
        ULONG oldProt;
        proc.change_protection(targetSlot, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProt);
        SIZE_T written;
        proc.write_mem(targetSlot, &newTarget, sizeof(void*), &written);
        proc.change_protection(targetSlot, sizeof(void*), oldProt, &oldProt);

        std::cout << "Hooked! New target: " << newTarget << std::endl;
        return true;
    }

    bool unhook(Process& proc) {
        ULONG oldProt;
        proc.change_protection(targetSlot, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProt);
        SIZE_T written;
        proc.write_mem(targetSlot, &original, sizeof(void*), &written);
        proc.change_protection(targetSlot, sizeof(void*), oldProt, &oldProt);
        std::cout << "Unhooked!" << std::endl;
        return true;
    }
};
