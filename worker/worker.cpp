#include "../dependecies/include/process.h"
#include "../dependecies/include/server.h"
#include "../dependecies/include/mmap.h"
#include "../dependecies/include/hook.h"
#include "../dependecies/system_calls/syscalls_all.h"

#include "../../Shared/shared.hpp"



void Worker()
{


	Process proc("RobloxPlayerBeta.exe");
	DWORD robloxPID = proc.get_pid();

	if (proc.get_handle() == nullptr)
	{
		std::cerr << "Failed to get roblox handle!" << std::endl;
	}

	std::cout << "[+] PID: " << proc.get_pid() << std::endl;
	std::cout << "[+] Handle: " << proc.get_handle() << std::endl;

	Mapper mapper(proc);
	auto result = mapper.map(L"C:\\Proton Executor\\x64\\Release\\TuffAPI.dll");
	if (!result.success)
	{
		std::cerr << "Mapping failed! " << std::endl;
	}
	std::cout << "[+] Mapped at: " << std::hex << result.remoteBase << std::endl;
	std::cout << "[+] Entry point: " << std::hex << result.entryPoint << std::endl;


    void* QPC = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "QueryPerformanceCounter");



	Hook hook;
	Sleep(3000);
    hook.hook(proc, QPC, (void*)result.entryPoint);


    Sleep(1000);
	hook.unhook(proc);

	Sleep(5000);

	

	Sleep(1000);
	// read pipe name from file
	HANDLE hFile = CreateFileA("C:\\Users\\Public\\pipename.txt",
		GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	char pipeName[256] = {};
	DWORD bytesRead;
	ReadFile(hFile, pipeName, sizeof(pipeName) - 1, &bytesRead, NULL);
	CloseHandle(hFile);

	Sleep(1000);

	std::string pipeNameStr(pipeName);



	HANDLE hPipe = INVALID_HANDLE_VALUE;
	int attempts = 0;
	while (hPipe == INVALID_HANDLE_VALUE && attempts < 50) {
		hPipe = CreateFileA(pipeNameStr.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hPipe == INVALID_HANDLE_VALUE) {
			attempts++;
			std::cout << "[+] Retrying pipe... attempt " << attempts << std::endl;
			Sleep(200);
		}
	}

	if (hPipe == INVALID_HANDLE_VALUE) {
		std::cout << "[+] Failed to connect to pipe!" << std::endl;
		return;
	}

	Packet packet = {};
	strncpy_s(packet.script, "print('hello')", sizeof(packet.script));

	DWORD written;
	BOOL send_result = WriteFile(hPipe, &packet, sizeof(Packet), &written, NULL);
	if (send_result) {
		std::cout << "[+] Sent " << written << " bytes" << std::endl;
	}
	else {
		std::cout << "[-] WriteFile failed: " << GetLastError() << std::endl;
	}
	CloseHandle(hPipe);
	printf("[+] Send packet to DLL!");

}