#include "utils.h"

int WINAPI Utils::MessageBoxWHook(HWND handle, LPCWSTR text, LPCWSTR caption, UINT type) {
    std::wcout << text << std::endl;
    std::wcout << caption << std::endl;

    if (!wcscmp(text, L"GL")) {
        return generalMessageBoxW(handle, text, caption, type);
    }
    else {
        return NULL;
    }
}

int WSAAPI Utils::connectHook(SOCKET s, const sockaddr* name, int namelen) {
    std::string ipAddress = "";

    ipAddress += std::to_string((int)((sockaddr_in*)name)->sin_addr.S_un.S_un_b.s_b1) + ".";
    ipAddress += std::to_string((int)((sockaddr_in*)name)->sin_addr.S_un.S_un_b.s_b2) + ".";
    ipAddress += std::to_string((int)((sockaddr_in*)name)->sin_addr.S_un.S_un_b.s_b3) + ".";
    ipAddress += std::to_string((int)((sockaddr_in*)name)->sin_addr.S_un.S_un_b.s_b4);

    std::cout << "address: " << ipAddress << std::endl;
    std::cout << "port: " << ntohs(((sockaddr_in*)name)->sin_port) << std::endl;

    if (ipAddress == "127.0.0.1") {
        return generalConnect(s, name, namelen);
    }
    else {
        return NULL;
    }
}

int WSAAPI Utils::WSAConnectHook(SOCKET s, const sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS) {
    std::string ipAddress = "";

    ipAddress += std::to_string((int)((sockaddr_in*)name)->sin_addr.S_un.S_un_b.s_b1) + ".";
    ipAddress += std::to_string((int)((sockaddr_in*)name)->sin_addr.S_un.S_un_b.s_b2) + ".";
    ipAddress += std::to_string((int)((sockaddr_in*)name)->sin_addr.S_un.S_un_b.s_b3) + ".";
    ipAddress += std::to_string((int)((sockaddr_in*)name)->sin_addr.S_un.S_un_b.s_b4);

    std::cout << "address: " << ipAddress << std::endl;
    std::cout << "port: " << ntohs(((sockaddr_in*)name)->sin_port) << std::endl;

    if (ipAddress == "127.0.0.1") {
        return generalWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    }
    else {
        return NULL;
    }
}

NTSTATUS WINAPI Utils::LdrLoadDllHook(PWSTR PathToFile, PULONG Flags, PUNICODE_STRING ModuleFileName, PVOID ModuleHandle) {
    std::wstring dllName = ModuleFileName->Buffer;
    std::wcout << "dllName : " << dllName << std::endl;
    if (dllName.find(L"ws2_32") != std::string::npos) {
        std::cout << "**************************************ws2_32 - This is correct dll***************************************************" << std::endl;
        if (Utils::hookWrapper(&Utils::connectHook, 7, L"C:\\Windows\\System32\\ws2_32.dll", "connect", connectFunc)) { // 64 bit
            Utils::Error("Failed Hook ws2_32 - connect");
        }

        if (Utils::hookWrapper(&Utils::connectHook, 7, L"C:\\Windows\\System32\\ws2_32.dll", "WSAConnect", WSAConnectFunc)) { // 64 bit
            Utils::Error("Failed Hook ws2_32 - WSAConnect");
        }
    }
    else if (dllName.find(L"wsock32") != std::string::npos) {
        std::cout << "**************************************wsock32 - This is correct dll***************************************************" << std::endl;
        if (Utils::hookWrapper(&Utils::connectHook, 7, L"wsock32", "connect", connectFunc)) { // 64 bit
            Utils::Error("Failed Hook wsock32 - connect");
            return EXIT_FAILURE;
        }
    }
    else {
        std::cout << "Not hooking to you" << std::endl;
    }
    return generalLdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle);
}

inline void Utils::Error(const std::string& errMsg) {
	std::cout << "[-] " << errMsg << ":" << GetLastError() << "\n";
}

LPVOID Utils::findFreePage(LPCVOID tagetFunction, SYSTEM_INFO& sysinf) {
    UINT64 pageCounter = 1, offset = NULL, highAddress = NULL, lowAddress = NULL, minAddress = NULL, maxAddress = NULL, startPage = NULL;
    UINT32 pageSize = NULL;
    LPVOID address = nullptr;

    pageSize = sysinf.dwPageSize;
    minAddress = (UINT64)sysinf.lpMinimumApplicationAddress > (UINT64)tagetFunction - 0xFFFFFFFF ? (UINT64)tagetFunction - 0xFFFFFFFF : (UINT64)sysinf.lpMinimumApplicationAddress; //Create limitation of 32 bit jump address
    maxAddress = (UINT64)sysinf.lpMaximumApplicationAddress < (UINT64)tagetFunction + 0xFFFFFFFF ? (UINT64)tagetFunction + 0xFFFFFFFF : (UINT64)sysinf.lpMaximumApplicationAddress;

    startPage = ((UINT64)tagetFunction / pageSize) * pageSize;
    
    while (1) {
        offset = pageCounter * pageSize;
        highAddress = startPage + offset;
        lowAddress = startPage - offset;

        if (highAddress < maxAddress) {
            address = VirtualAlloc((LPVOID)highAddress, pageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (address) {
                return address;
            }
        }

        if (lowAddress > minAddress) {
            address = VirtualAlloc((LPVOID)lowAddress, pageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (address) {
                return address;
            }
        }

        if (highAddress > maxAddress && lowAddress < minAddress) {
            Utils::Error("Did not find any available page");
            break;
        }

        ++pageCounter;
    }

    return nullptr;
}

int Utils::createHook(LPVOID targetFucntion, SYSTEM_INFO& sysinf, UINT8 stolenBytes, LPVOID hookFunction) {
    PUINT8 nopInstructions = nullptr;
    UINT8 nopInstructionsSize = NULL;
    DWORD oldProtectionPage = NULL;
#ifdef _WIN64
    LPVOID bridgeJumpAddress = nullptr;
    UINT64 relativeAddress64Bit = NULL;
    UINT8 jumpToBridge[JMP_RELATIVE_OPCODE_SIZE] = { 0xE9, 0x00, 0x00, 0x00, 0x00}; // JMP (relative address)
    UINT8 jumpTo64address[JUMP_TO_64_ADDRESS_SIZE] = { 0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV r10, address
                                                       0x41, 0xFF, 0xE2 }; // JMP r10
#else
    UINT8 jumpToHookFunction[JMP_RELATIVE_OPCODE_SIZE] = { 0xE9, 0x00, 0x00, 0x00, 0x00}; // JMP (relative address)
    UINT32 relativeAddress32Bit = NULL;
#endif
    
    nopInstructionsSize = stolenBytes - JMP_RELATIVE_OPCODE_SIZE;
    
#ifdef _WIN64
    bridgeJumpAddress = Utils::findFreePage(targetFucntion, sysinf);
    if (!bridgeJumpAddress) {
        return EXIT_FAILURE;
    }
#endif

    // Allocate X bytes in stack (faster) or in heap if exceeded _ALLOCA_S_THRESHOLD
    nopInstructions = (UINT8*)_malloca(nopInstructionsSize);// X NOP instructions to fully destroy chain of opcodes

    if (!nopInstructions) {
        Utils::Error("Failed allocate on the stack");
        return EXIT_FAILURE;
    }

    // Initialize NOP instructions
    for (int i = 0; i < nopInstructionsSize; ++i) {
        *(nopInstructions + i) = 0x90;
    }

    //Relative displacement to the next instruction after E9 opcode
#ifdef _WIN64
    relativeAddress64Bit = (UINT64)bridgeJumpAddress - ((UINT64)targetFucntion + 5);
#else
    relativeAddress32Bit = (UINT64)hookFunction - ((UINT64)targetFucntion + 5);
#endif

#ifdef _WIN64
    if (memcpy_s(jumpToBridge + 1, 4, &relativeAddress64Bit, 4)) {
        Utils::Error("Failed copy relative address to bridge");
        return EXIT_FAILURE;
    }
#else
    if (memcpy_s(jumpToHookFunction + 1, 4, &relativeAddress32Bit, 4)) {
        Utils::Error("Failed copy relative address to hook function");
        return EXIT_FAILURE;
    }
#endif
    
#ifdef _WIN64
    if (memcpy_s(jumpTo64address + 2, sizeof(hookFunction), &hookFunction, sizeof(hookFunction))) {
        Utils::Error("Failed copy hook function to jump 64 address");
        return EXIT_FAILURE;
    }
#endif

    if (!VirtualProtect(targetFucntion, stolenBytes, PAGE_READWRITE, &oldProtectionPage)) {
        Utils::Error("Failed change to PAGE_EXECUTE_READWRITE permission to target function");
        return EXIT_FAILURE;
    }

#ifdef _WIN64
    if (memcpy_s(targetFucntion, JMP_RELATIVE_OPCODE_SIZE, &jumpToBridge, JMP_RELATIVE_OPCODE_SIZE)) {
        Utils::Error("Failed copy to target function bridge bytes");
        return EXIT_FAILURE;
    }
#else
    if (memcpy_s(targetFucntion, JMP_RELATIVE_OPCODE_SIZE, &jumpToHookFunction, JMP_RELATIVE_OPCODE_SIZE)) {
        Utils::Error("Failed copy to target function bridge bytes");
        return EXIT_FAILURE;
    }
#endif

    if (nopInstructionsSize) {
        if (memcpy_s((LPVOID)((UINT64)targetFucntion + JMP_RELATIVE_OPCODE_SIZE), nopInstructionsSize, nopInstructions, nopInstructionsSize)) {
            Utils::Error("Failed copy to target function X NOP instructions");
            return EXIT_FAILURE;
        }
    }

    if (!VirtualProtect(targetFucntion, stolenBytes, oldProtectionPage, &oldProtectionPage)) {
        Utils::Error("Failed restore old permission to target function");
        return EXIT_FAILURE;
    }

#ifdef _WIN64
    if (memcpy_s(bridgeJumpAddress, JUMP_TO_64_ADDRESS_SIZE, &jumpTo64address, JUMP_TO_64_ADDRESS_SIZE)) {
        Utils::Error("Failed copy to jump bridge jump 64 address bytes");
        return EXIT_FAILURE;
    }

    if (!VirtualProtect(bridgeJumpAddress, sysinf.dwPageSize, PAGE_EXECUTE_READ, &oldProtectionPage)) {
        Utils::Error("Failed change allocated page permission to PAGE_EXECUTE_READ to bridgeJumpAddress");
        return EXIT_FAILURE;
    }
#endif

    return EXIT_SUCCESS;
}

int Utils::createTrampolineBack(LPVOID targetFucntion, SYSTEM_INFO& sysinf, UINT8 stolenBytes, UINT8 funcToHookType) {
    UINT8 jumpToOriginalTargetFunction[JMP_RELATIVE_OPCODE_SIZE] = { 0xE9, 0x00, 0x00, 0x00, 0x00 }; // JMP (relative address)
#ifdef  _WIN64
    UINT64 relativeAddress64bit = NULL;
#else
    UINT32 relativeAddress32bit = NULL;
#endif    
    DWORD oldProtectionPage = NULL;
    LPVOID trampolineBackAddress = nullptr;

#ifdef  _WIN64
    trampolineBackAddress = Utils::findFreePage(targetFucntion, sysinf);
#else
    trampolineBackAddress = VirtualAlloc(NULL, sysinf.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#endif

    if (!trampolineBackAddress) {
        return EXIT_FAILURE;
    }

    //Relative displacement to the next instruction after E9 opcode
#ifdef  _WIN64
    relativeAddress64bit = (UINT64)targetFucntion - ((UINT64)trampolineBackAddress + 5);
#else
    relativeAddress32bit = (UINT32)targetFucntion - ((UINT32)trampolineBackAddress + 5);
#endif

    if (memcpy_s(trampolineBackAddress, stolenBytes, targetFucntion, stolenBytes)) {
        Utils::Error("Failed copy stolen bytes from target function");
        return EXIT_FAILURE;
    }

#ifdef  _WIN64
    if (memcpy_s(jumpToOriginalTargetFunction + 1, 4, &relativeAddress64bit, 4)) {
        Utils::Error("Failed copy relative address to jump back to original function");
        return EXIT_FAILURE;
    }
#else
    if (memcpy_s(jumpToOriginalTargetFunction + 1, 4, &relativeAddress32bit, 4)) {
        Utils::Error("Failed copy relative address to jump back to original function");
        return EXIT_FAILURE;
    }
#endif

#ifdef  _WIN64
    if (memcpy_s((LPVOID)((UINT64)trampolineBackAddress + stolenBytes), sizeof(jumpToOriginalTargetFunction), jumpToOriginalTargetFunction, sizeof(jumpToOriginalTargetFunction))) {
        Utils::Error("Failed copy to trampolineBackAddress relative jump bytes");
        return EXIT_FAILURE;
    }
#else
    if (memcpy_s((LPVOID)((UINT32)trampolineBackAddress + stolenBytes), sizeof(jumpToOriginalTargetFunction), jumpToOriginalTargetFunction, sizeof(jumpToOriginalTargetFunction))) {
        Utils::Error("Failed copy to trampolineBackAddress relative jump bytes");
        return EXIT_FAILURE;
    }
#endif

    if (!VirtualProtect(trampolineBackAddress, sysinf.dwPageSize, PAGE_EXECUTE_READ, &oldProtectionPage)) {
        Utils::Error("Failed change allocated page permission to PAGE_EXECUTE_READ to trampolineBackAddress");
        return EXIT_FAILURE;
    }

    switch (funcToHookType)
    {
    case MessageBoxWFunc:
        generalMessageBoxW = (pMessageBoxW)trampolineBackAddress;
        break;
    case connectFunc:
        generalConnect = (pConnect)trampolineBackAddress;
        break;
    case WSAConnectFunc:
        generalWSAConnect = (pWSAConnect)trampolineBackAddress;
        break;
    case LdrLoadDllFunc:
        generalLdrLoadDll = (pLdrLoadDll)trampolineBackAddress;
        break;
    default:
        break;
    }

    return EXIT_SUCCESS;
}

int Utils::hookWrapper(LPVOID hookFunction, UINT8 stolenBytes, LPCWSTR dllName, LPCSTR dllFunctionName, UINT8 funcToHookType) {
    SYSTEM_INFO sysinf;
    LPVOID targetFunction = nullptr;
    HMODULE hWs2_32 = NULL, hUser32 = NULL, tHandle = NULL;

    tHandle = GetModuleHandleW(dllName);

    if (!tHandle) {
        Utils::Error("Failed get handle to module");
        return EXIT_FAILURE;
    }

    targetFunction = GetProcAddress(tHandle, dllFunctionName);

    if (!targetFunction) {
        Utils::Error("Failed get address of function from the dll");
        return EXIT_FAILURE;
    }

    if (stolenBytes < JMP_RELATIVE_OPCODE_SIZE) {
        Utils::Error("Can't create hook with less than 5 bytes");
        return EXIT_FAILURE;
    }

    GetSystemInfo(&sysinf);

    if (Utils::createTrampolineBack(targetFunction, sysinf, stolenBytes, funcToHookType)) {
        Utils::Error("Failed to create trampoline back to original function");
        return EXIT_FAILURE;
    }

    if (Utils::createHook(targetFunction, sysinf, stolenBytes, hookFunction)) {
        Utils::Error("Failed to create 64 hook");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/*
int Utils::getProcessUsername(LPWSTR pUsername) {
    HANDLE token = NULL;
    PTOKEN_OWNER pTokenOwner = nullptr;
    DWORD tokenInformationLength = NULL, accountNameSize = MAX_NAME;
    SID_NAME_USE SidType;
    WCHAR accountName[MAX_NAME] = { 0 }, domainName[MAX_NAME] = { 0 };

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        Utils::Error("Failed get handle to process token");
        return EXIT_FAILURE;
    }

    // Get size for token information
    if(!GetTokenInformation(token, TokenOwner, NULL, NULL, &tokenInformationLength)){
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            CloseHandle(token);
            Utils::Error("Failed get size for token information");
            return EXIT_FAILURE;
        }
    }

    pTokenOwner = (PTOKEN_OWNER)malloc(tokenInformationLength);

    // Get token information
    if (!GetTokenInformation(token, TokenOwner, pTokenOwner, tokenInformationLength, &tokenInformationLength)) {
        CloseHandle(token);
        free(pTokenOwner);
        Utils::Error("Failed get token information");
        return EXIT_FAILURE;
    }

    if (!LookupAccountSidW(NULL, pTokenOwner->Owner, accountName, &accountNameSize, domainName, &accountNameSize, &SidType)) {
        CloseHandle(token);
        free(pTokenOwner);
        Utils::Error("Failed retrieve account information");
        return EXIT_FAILURE;
    }
    
    if (wmemcpy_s(pUsername, accountNameSize, accountName, accountNameSize)) {
        CloseHandle(token);
        free(pTokenOwner);
        Utils::Error("Failed copy account name");
        return EXIT_FAILURE;
    }

    free(pTokenOwner);
    CloseHandle(token);
    return EXIT_SUCCESS;
}

int Utils::is64BitProcess(SYSTEM_INFO& sysinf) {
    BOOL isWow64Process = FALSE;

    if (!IsWow64Process(GetCurrentProcess(), &isWow64Process)) {
        Utils::Error("Failed check if process is Wow64");
        return -1;
    }

    if (sysinf.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
        return FALSE;
    }
    else if (sysinf.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 && isWow64Process) {
        return FALSE;
    }
    else{
        return TRUE;
    }
}*/