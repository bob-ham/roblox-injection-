#pragma once

#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <ws2tcpip.h>
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif
#include <ntstatus.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <tlhelp32.h>
#include <psapi.h>
#include <iomanip>
#include <shellapi.h>
#include <tchar.h>
#include <d3d11.h>
#include <dxgi.h>
#include <thread>
#include <filesystem>

#include "typedefs.h"