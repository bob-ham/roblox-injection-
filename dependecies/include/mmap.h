#pragma once
#include "framework.h"
#include "process.h"

class Mapper
{
private:
	Process& process;

	bool fix_relocations(PVOID localBase, uintptr_t remoteBase);
	bool resolve_imports(PVOID localBase);
	bool register_seh(PVOID localBase, uintptr_t remoteBase, SIZE_T imageSize);

public:
	Mapper(Process& process);

	struct MapResult
	{
		uintptr_t remoteBase;
		uintptr_t entryPoint;
		bool success;
	};

	MapResult map(const std::wstring& DllPath);
};