#pragma once
#include "framework.h"
#include "../system_calls/syscalls_all.h"

class Process
{
private:
	std::string name;
	DWORD pid;
	HANDLE handle;

	HANDLE hijack_handle(DWORD pid);
	DWORD GetPID(std::string name);
public:
	Process(std::string name);
	~Process();
	Process(const Process& other) = delete;
	Process& operator=(const Process& other) = delete;
	Process(Process&& other) noexcept;
	Process& operator=(Process&& other) noexcept;

	DWORD get_pid();
	HANDLE get_handle();

	NTSTATUS read_mem(PVOID base, PVOID buf, SIZE_T size, PSIZE_T read);
	NTSTATUS write_mem(PVOID base, PVOID buf, SIZE_T size, PSIZE_T written);
	NTSTATUS change_protection(PVOID base, SIZE_T size, ULONG prot, PULONG oldProt);
	PVOID allocate_mem(SIZE_T size, ULONG type, ULONG prot);

	void suspend_all_threads();
	void resume_all_threads();
	HANDLE get_io_completion_port();

	struct Module {
		std::string name;
		BYTE* base;
		int size;
	};

	std::vector<Module> get_all_modules();
	Module* get_module_by_name(const std::vector<Module>& modules, const std::string& name);
	PVOID scan_for_codecave(const Module& mod, size_t caveSize, BYTE caveByte, uintptr_t startAddr);

	void create_thread_in_threadpool(HANDLE iohandle, LPVOID addr);
};