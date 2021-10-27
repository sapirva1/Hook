#pragma once
#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winternl.h>
#include <psapi.h>
#include <intrin.h>

#define WIN32_LEAN_AND_MEAN
#define JUMP_TO_64_ADDRESS_SIZE 13
#define JMP_RELATIVE_OPCODE_SIZE 5
#define ACCOUNT_NAME_SIZE 256

#pragma comment(lib, "ws2_32.lib")

enum {
	connectFunc,
	WSAConnectFunc,
	LdrLoadDllFunc,
};

namespace Utils {
	inline void Error(const std::string& errMsg);
    void getProcessUsername(PWCHAR pProcessUsername);
    void getProcessName(PWCHAR pProcessName);
    BOOL Wow64Process();

	// Hook related
	LPVOID findFreePage(LPVOID tagetFunction, SYSTEM_INFO& sysinf);
	int createHook(LPVOID targetFucntion, SYSTEM_INFO& sysinf, UINT8 stolenBytes, LPVOID hookFunction);
	int createTrampolineBack(LPVOID targetFucntion, SYSTEM_INFO& sysinf, UINT8 stolenBytes, UINT8 funcToHookType);
	int hookWrapper(LPVOID hookFunction, UINT8 stolenBytes, LPCWSTR dllName, LPCSTR dllFunctionName, UINT8 funcToHookType);

	// Hook functions
	int WSAAPI connectHook(SOCKET s, const sockaddr* name, int namelen);
	int WSAAPI WSAConnectHook(SOCKET s, const sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);
	NTSTATUS WINAPI LdrLoadDllHook(PWSTR PathToFile, PULONG Flags, PUNICODE_STRING ModuleFileName, PVOID ModuleHandle);
}

class ProcessInfo {
public:
    ProcessInfo();
    inline PWCHAR getProcessName();
    inline PWCHAR getProcessUser();
private:
    WCHAR processName[MAX_PATH] = { 0 };
    WCHAR processUser[ACCOUNT_NAME_SIZE] = { 0 };
};

template<class T, int size>
class Array {
public:
    Array(T resetValue);
    ~Array() = default;
    T getArray();
    int getCurrentSize();
    void push(T value);
private:
    T privateArray[size];
    T resetValue;
    int currSize = 0;
};

template<class T, int size>
Array<T, size>::Array(T resetVal) {
    for (int index = 0; index < size; ++index) {
        this->privateArray[index] = resetVal;
    }
    this->resetValue = resetVal;
}

template<class T, int size>
inline T Array<T, size>::getArray()
{
    return this->privateArray;
}

template<class T, int size>
inline int Array<T, size>::getCurrentSize() {
    return this->currSize;
}

template<class T, int size>
void Array<T, size>::push(T value) {
    UINT8 foundEmptyCell = FALSE;
    int index = 0;
    while (index < size && !foundEmptyCell) {
        if (this->privateArray[index] == this->resetValue) {
            this->privateArray[index] = value;
            foundEmptyCell = TRUE;
            ++this->currSize;
        }
        else {
            ++index;
        }
    }
}

#ifdef _WIN64
_declspec(selectany) Array<LPVOID, 6> addressesToFree = { nullptr };
#else
_declspec(selectany) Array<LPVOID, 3> addressesToFree = { nullptr };
#endif