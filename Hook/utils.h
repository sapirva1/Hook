#pragma once
#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winternl.h>

#define WIN32_LEAN_AND_MEAN

#pragma comment(lib, "ws2_32.lib")

constexpr auto JUMP_TO_64_ADDRESS_SIZE = 13;
constexpr auto JMP_RELATIVE_OPCODE_SIZE = 5;
constexpr auto MAX_NAME = 256;

enum {
	connectFunc,
	WSAConnectFunc,
	LdrLoadDllFunc,
};


namespace Utils {
	inline void Error(const std::string& errMsg);
	//int getProcessUsername(LPWSTR pUsername);
	//int is64BitProcess(SYSTEM_INFO& sysinf);

	// Hook related
	LPVOID findFreePage(LPCVOID tagetFunction, SYSTEM_INFO& sysinf);
	int createHook(LPVOID targetFucntion, SYSTEM_INFO& sysinf, UINT8 stolenBytes, LPVOID hookFunction);
	int createTrampolineBack(LPVOID targetFucntion, SYSTEM_INFO& sysinf, UINT8 stolenBytes, UINT8 funcToHookType);
	int hookWrapper(LPVOID hookFunction, UINT8 stolenBytes, LPCWSTR dllName, LPCSTR dllFunctionName, UINT8 funcToHookType);

	// Hook functions
	int WSAAPI connectHook(SOCKET s, const sockaddr* name, int namelen);
	int WSAAPI WSAConnectHook(SOCKET s, const sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);
	NTSTATUS WINAPI LdrLoadDllHook(PWSTR PathToFile, PULONG Flags, PUNICODE_STRING ModuleFileName, PVOID ModuleHandle);
}