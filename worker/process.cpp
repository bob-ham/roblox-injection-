#include "../dependecies/include/mmap.h"

HANDLE Process::get_handle()
{
	return this->handle;
}

DWORD Process::GetPID(std::string name)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) return 0;

	PROCESSENTRY32W PE;
	PE.dwSize = sizeof(PROCESSENTRY32W);

	std::wstring wname(name.begin(), name.end());

	if (Process32FirstW(snapshot, &PE))
	{
		do
		{
			if (wcscmp(PE.szExeFile, wname.c_str()) == 0)
			{
				CloseHandle(snapshot);
				return PE.th32ProcessID;
			} 
		} while (Process32NextW(snapshot, &PE));
	}
	CloseHandle(snapshot);
	return 0;
}

DWORD Process::get_pid()
{
	return this->pid;
}

// to hijack a handle
HANDLE Process::hijack_handle(DWORD pid)
{
	HMODULE ntdll = GetModuleHandleA("ntdll");
	typedef NTSTATUS(NTAPI* _RtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
	auto RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
	BOOLEAN oldPriv;
	RtlAdjustPrivilege(20, TRUE, FALSE, &oldPriv);


	ULONG size = 0x10000;
	PSYSTEM_HANDLE_INFORMATION hInfo = nullptr;

	NTSTATUS status;
	do 
	{
		delete[] hInfo;
		hInfo = (PSYSTEM_HANDLE_INFORMATION) new BYTE[size];
		status = Sw3NtQuerySystemInformation(SystemHandleInformation, hInfo, size, &size);
		size *= 2;
	} while (status == 0xC0000004);
	if (!NT_SUCCESS(status))
	{
		delete[] hInfo;
		return nullptr;
	}
	HANDLE result = nullptr;
	OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };


	for (ULONG i = 0; i < hInfo->HandleCount; i++)
	{
		SYSTEM_HANDLE sh = hInfo->Handles[i];

		if (!sh.Handle) continue;

		CLIENT_ID CID = { (HANDLE)(ULONG_PTR)sh.ProcessId,nullptr };
		HANDLE ownerHandle = nullptr;
		status = Sw3NtOpenProcess(&ownerHandle, PROCESS_DUP_HANDLE, &objAttr, &CID);
		if (!NT_SUCCESS(status) || !ownerHandle) continue;

		HANDLE dupHandle = nullptr;
		status = Sw3NtDuplicateObject(ownerHandle, (HANDLE)(ULONG_PTR)sh.Handle, GetCurrentProcess(), &dupHandle, PROCESS_ALL_ACCESS, 0, 0);
		Sw3NtClose(ownerHandle);

		if (!NT_SUCCESS(status) || !dupHandle) continue;

		if (GetProcessId(dupHandle) == pid)
		{
			result = dupHandle;
			break;
		}

		Sw3NtClose(dupHandle);

	}
	delete[] hInfo;
	return result;

}
Process::Process(std::string name)
{
	this->name = name;
	this->pid = GetPID(name);
	this->handle = hijack_handle(this->pid);

	if (this->handle == nullptr)
	{
		std::cerr << "Failed to hijack handle for " << name << std::endl;
	}
}
HANDLE Process::get_io_completion_port()
{
	ULONG size = 0x10000;
	PSYSTEM_HANDLE_INFORMATION hInfo = nullptr;
	NTSTATUS status;

	do 
	{
		delete[] hInfo;
		hInfo = (PSYSTEM_HANDLE_INFORMATION) new BYTE[size];
		status = Sw3NtQuerySystemInformation(SystemHandleInformation, hInfo, size, &size);
		size *= 2;
	} while (status == 0xC0000004);
	if (!NT_SUCCESS(status))
	{
		delete[] hInfo;
		return nullptr;
	}

	HANDLE result = nullptr;
	OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };

	for (ULONG i = 0; i < hInfo->HandleCount; i++)
	{
		SYSTEM_HANDLE sh = hInfo->Handles[i];

		if (sh.ProcessId != this->pid) continue;
		if (!sh.Handle) continue;

		HANDLE dupHandle = nullptr;
		status = Sw3NtDuplicateObject(this->handle, (HANDLE)(ULONG_PTR)sh.Handle, GetCurrentProcess(), &dupHandle, 0, 0, DUPLICATE_SAME_ACCESS);
		if (!NT_SUCCESS(status) || !dupHandle) continue;

		ULONG retLen = 0;
		BYTE typeBuf[0x200] = {};
		status = Sw3NtQueryObject(dupHandle, ObjectTypeInformation, typeBuf, sizeof(typeBuf), &retLen);
		if (!NT_SUCCESS(status))
		{
			Sw3NtClose(dupHandle);
			continue;
		}

		auto typeInfo = (POBJECT_TYPE_INFORMATION)typeBuf;
		std::wstring typeName(typeInfo->TypeName.Buffer, typeInfo->TypeName.Length / sizeof(WCHAR));
		if (typeName == L"IoCompletion")
		{
			result = dupHandle;
			break;
		}

		Sw3NtClose(dupHandle);

	}
	delete[] hInfo;
	return result;
}
// closing
Process::~Process()
{
	if (handle != nullptr)
	{
		Sw3NtClose(handle);
		handle = nullptr;
	}
}
// short hand names for these, also we dont have to pass the handle
NTSTATUS Process::read_mem(PVOID base, PVOID buf, SIZE_T size, PSIZE_T read)
{
	return Sw3NtReadVirtualMemory(this->handle, base, buf, size, read);
}
NTSTATUS Process::write_mem(PVOID base, PVOID buf, SIZE_T size, PSIZE_T written)
{
	return Sw3NtWriteVirtualMemory(this->handle, base, buf, size, written);
}
NTSTATUS Process::change_protection(PVOID base, SIZE_T size, ULONG prot, PULONG oldProt)
{
	return Sw3NtProtectVirtualMemory(this->handle,&base, &size, prot, oldProt);
}
PVOID Process::allocate_mem(SIZE_T size, ULONG type, ULONG prot)
{
	PVOID base = nullptr;
	Sw3NtAllocateVirtualMemory(this->handle, &base, 0, &size, type, prot);
	return base;
}

std::vector<Process::Module> Process::get_all_modules()
{
	std::cout << "get_all_modules called" << std::endl;
	using vecMod = std::vector<Process::Module>;
	vecMod modules;
	HANDLE hModules = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, this->pid);
	std::cout << "Snapshot handle: " << hModules << std::endl;
	if (hModules == INVALID_HANDLE_VALUE)
	{
		std::cerr << "Module snapshot failed, error: " << GetLastError() << std::endl;
		return modules;
	}

	MODULEENTRY32 ME;
	ME.dwSize = sizeof(MODULEENTRY32);
	
	if (Module32First(hModules, &ME))
	{
		std::cout << "Module32First succeeded" << std::endl;
		do 
		{
			Module MOD;
			MOD.base = ME.modBaseAddr;
			MOD.size = ME.modBaseSize;
			MOD.name = ME.szModule;
			modules.push_back(MOD);
		} while (Module32Next(hModules, &ME));
	}
	else
	{
		std::cerr << "Module32First failed, error: " << GetLastError() << std::endl;
	}
	CloseHandle(hModules);
	return modules;
}
Process::Module* Process::get_module_by_name(const std::vector<Module>& modules, const std::string& name)
{
	for (auto& mod : modules)
	{
		if (mod.name == name)
		{
			return const_cast<Module*>(&mod);
		}
	}
	return nullptr;
}
PVOID Process::scan_for_codecave(const Module& mod, size_t caveSize, BYTE caveByte, uintptr_t startAddr)
{
	if (!mod.base || mod.size == 0 || caveSize == 0) return nullptr;
	uintptr_t current = startAddr ? startAddr : (uintptr_t)mod.base;
	uintptr_t end = (uintptr_t)mod.base + mod.size;

	while (current < end)
	{
		MEMORY_BASIC_INFORMATION MBI;
		NTSTATUS status = Sw3NtQueryVirtualMemory(this->handle, (PVOID)current, MemoryBasicInformation, &MBI, sizeof(MBI), nullptr);
		if (!NT_SUCCESS(status)) break;

		uintptr_t regionEnd = (uintptr_t)MBI.BaseAddress + MBI.RegionSize;
		uintptr_t clampedEnd = min(regionEnd, end);

		bool readable = (MBI.State == MEM_COMMIT) &&
			(MBI.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));

		if (readable)
		{
			SIZE_T readSize = clampedEnd - current;
			std::vector<BYTE> buffer(readSize);
			SIZE_T bytesRead = 0;
			read_mem((PVOID)current, buffer.data(), readSize, &bytesRead);

			size_t count = 0;
			for (size_t i = 0; i < bytesRead; i++)
			{
				if (buffer[i] == caveByte)
				{
					count++;
					if (count >= caveSize)
					{
						uintptr_t caveStart = current + i - caveSize + 1;
						uintptr_t caveEnd = caveStart + caveSize;

						// verify entire cave fits within this region
						if (caveEnd <= clampedEnd)
						{
							return (PVOID)caveStart;
						}

						// cave spans boundary, reset and continue
						count = 0;
					}
				}
				else
				{
					count = 0;
				}
			}
		}

		current = regionEnd;
	}
	return nullptr;
}