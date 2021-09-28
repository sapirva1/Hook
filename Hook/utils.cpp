#include "utils.h"

typedef int(WINAPI* pGeneralMsgBox)(HWND handle, LPCWSTR text, LPCWSTR caption, UINT type);
typedef int(WSAAPI* pConnect)(SOCKET s, const sockaddr* name, int namelen);
typedef int(WSAAPI* pWSAConnect)(SOCKET s, const sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);

pGeneralMsgBox generalMsgBox = nullptr;
pConnect generalConnect = nullptr;
pWSAConnect generalWSAConnect = nullptr;

int WINAPI Utils::MessageBoxWHook(HWND handle, LPCWSTR text, LPCWSTR caption, UINT type) {
    std::wcout << text << std::endl;
    std::wcout << caption << std::endl;

    if (!wcscmp(text, L"GL")) {
        return generalMsgBox(handle, text, caption, type);
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

int Utils::createHook64(LPVOID targetFucntion, SYSTEM_INFO& sysinf, UINT8 stolenBytes, LPVOID hookFunction) {
    UINT8* nopInstructions = nullptr;
    LPVOID bridgeJumpAddress = nullptr;
    DWORD oldProtectionPage = NULL;
    UINT64 relativeAddress = NULL;
    UINT8 nopInstructionsSize = NULL;
    UINT8 jumpToBridge[RELATIVE_JMP_OPCODE_SIZE] = { 0xE9, 0x00, 0x00, 0x00, 0x00}; // JMP (relative address)
    UINT8 jumpTo64address[JUMP_TO_64_ADDRESS_SIZE] = { 0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV r10, address
                                                       0x41, 0xFF, 0xE2 }; // JMP r10
    
    nopInstructionsSize = stolenBytes - RELATIVE_JMP_OPCODE_SIZE;

    bridgeJumpAddress = Utils::findFreePage(targetFucntion, sysinf);
    
    if (!bridgeJumpAddress) {
        return EXIT_FAILURE;
    }

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
    relativeAddress = (UINT64)bridgeJumpAddress - ((UINT64)targetFucntion + 5);

    if (memcpy_s(jumpToBridge + 1, 4, &relativeAddress, 4)) {
        Utils::Error("Failed copy relative address to bridge");
        return EXIT_FAILURE;
    }

    if (memcpy_s(jumpTo64address + 2, sizeof(hookFunction), &hookFunction, sizeof(hookFunction))) {
        Utils::Error("Failed copy hook function to jump 64 address");
        return EXIT_FAILURE;
    }

    if (!VirtualProtect(targetFucntion, stolenBytes, PAGE_EXECUTE_READWRITE, &oldProtectionPage)) {
        Utils::Error("Failed change to PAGE_EXECUTE_READWRITE permission to target function");
        return EXIT_FAILURE;
    }

    if (memcpy_s(targetFucntion, RELATIVE_JMP_OPCODE_SIZE, &jumpToBridge, RELATIVE_JMP_OPCODE_SIZE)) {
        Utils::Error("Failed copy to target function bridge bytes");
        return EXIT_FAILURE;
    }

    if (nopInstructionsSize) {
        if (memcpy_s((LPVOID)((UINT64)targetFucntion + RELATIVE_JMP_OPCODE_SIZE), nopInstructionsSize, nopInstructions, nopInstructionsSize)) {
            Utils::Error("Failed copy to target function X NOP instructions");
            return EXIT_FAILURE;
        }
    }

    if (!VirtualProtect(targetFucntion, stolenBytes, oldProtectionPage, &oldProtectionPage)) {
        Utils::Error("Failed restore old permission to target function");
        return EXIT_FAILURE;
    }

    if (memcpy_s(bridgeJumpAddress, JUMP_TO_64_ADDRESS_SIZE, &jumpTo64address, JUMP_TO_64_ADDRESS_SIZE)) {
        Utils::Error("Failed copy to jump bridge jump 64 address bytes");
        return EXIT_FAILURE;
    }

    if (!VirtualProtect(bridgeJumpAddress, sysinf.dwPageSize, PAGE_EXECUTE_READ, &oldProtectionPage)) {
        Utils::Error("Failed change allocated page permission to PAGE_EXECUTE_READ to bridgeJumpAddress");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int Utils::createTrampolineBack(LPVOID targetFucntion, SYSTEM_INFO& sysinf, UINT8 stolenBytes, UINT8 funcToHookType) {
    UINT8 jumpToOriginalTargetFunction[RELATIVE_JMP_OPCODE_SIZE] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
    UINT64 relativeAddress = NULL;
    DWORD oldProtectionPage = NULL;
    LPVOID trampolineBackAddress = nullptr;

    trampolineBackAddress = Utils::findFreePage(targetFucntion, sysinf);

    //Relative displacement to the next instruction after E9 opcode
    relativeAddress = (UINT64)targetFucntion - ((UINT64)trampolineBackAddress + 5);

    if (memcpy_s(trampolineBackAddress, stolenBytes, targetFucntion, stolenBytes)) {
        Utils::Error("Failed copy stolen bytes from target function");
        return EXIT_FAILURE;
    }

    if (memcpy_s(jumpToOriginalTargetFunction + 1, 4, &relativeAddress, 4)) {
        Utils::Error("Failed copy relative address to jump back to original function");
        return EXIT_FAILURE;
    }

    if (memcpy_s((LPVOID)((UINT64)trampolineBackAddress + stolenBytes), sizeof(jumpToOriginalTargetFunction), jumpToOriginalTargetFunction, sizeof(jumpToOriginalTargetFunction))) {
        Utils::Error("Failed copy to trampolineBackAddress relative jump bytes");
        return EXIT_FAILURE;
    }

    if (!VirtualProtect(trampolineBackAddress, sysinf.dwPageSize, PAGE_EXECUTE_READ, &oldProtectionPage)) {
        Utils::Error("Failed change allocated page permission to PAGE_EXECUTE_READ to trampolineBackAddress");
        return EXIT_FAILURE;
    }

    switch (funcToHookType)
    {
    case MessageBoxWFunc:
        generalMsgBox = (pGeneralMsgBox)trampolineBackAddress;
        break;
    case connectFunc:
        generalConnect = (pConnect)trampolineBackAddress;
        break;
    case WSAConnectFunc:
        generalWSAConnect = (pWSAConnect)trampolineBackAddress;
        break;
    default:
        break;
    }

    return EXIT_SUCCESS;
}

int Utils::hookWrapper(LPVOID targetFunction, LPVOID hookFunction, UINT8 stolenBytes, UINT8 funcToHookType) {
    SYSTEM_INFO sysinf;
    UINT8 is64Bit = FALSE;

    if (stolenBytes < RELATIVE_JMP_OPCODE_SIZE) {
        Utils::Error("Can't create hook with less than 5 bytes");
        return EXIT_FAILURE;
    }

    GetSystemInfo(&sysinf);

    is64Bit = Utils::is64BitProcess(sysinf);

    if (is64Bit == -1) {
        Utils::Error("Can't determine process architecture");
        return EXIT_FAILURE;
    }

    if (Utils::createTrampolineBack(targetFunction, sysinf, stolenBytes, funcToHookType)) {
        Utils::Error("Failed to create trampoline back to original function");
        return EXIT_FAILURE;
    }

    if (Utils::createHook64(targetFunction, sysinf, stolenBytes, hookFunction)) {
        Utils::Error("Failed to create 64 hook");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int Utils::getProcessUsername(LPWSTR pUsername) {
    HANDLE token;
    PTOKEN_OWNER pTokenOwner;
    DWORD tokenInformationLength = NULL, accountNameSize = MAX_NAME;
    SID_NAME_USE SidType;
    wchar_t accountName[MAX_NAME], domainName[MAX_NAME];

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
}