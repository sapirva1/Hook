#include "utils.h"

/*
* Compiled with CFG + DEP + ASLR on Release
*/

//Hook ws2_32.dll - connect & WSAConnect
//Hook wsock32.dll - connect

int main() {
    /*if (Utils::hookWrapper(&Utils::LdrLoadDllHook, 5, L"C:\\Windows\\System32\\ntdll.dll", "LdrLoadDll", LdrLoadDllFunc)) { // 64 bit + 32 bit
        Utils::Error("Failed Hook ntdll - LdrLoadDll");
        return EXIT_FAILURE;
    }*/
    HMODULE bla = LoadLibraryW(L"C:\\Users\\user\\Desktop\\TrustyDll\\TrustyDll\\x64\\Release\\TrustyDll.dll");
    HMODULE bla1 = LoadLibraryW(L"ws2_32");
    HMODULE bla2 = LoadLibraryW(L"wsock32");

    /*std::cout << "connect:" << std::endl;
    int iResult = NULL;
    WSADATA wsaData;
    SOCKET ConnectSocket;
    sockaddr_in clientService = { 0 };

    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != NO_ERROR) {
        wprintf(L"WSAStartup function failed with error: %d\n", iResult);
        return 1;
    }

    ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ConnectSocket == INVALID_SOCKET) {
        wprintf(L"socket function failed with error: %ld\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    clientService.sin_family = AF_INET;
    InetPtonW(AF_INET, (PCWSTR)(L"127.0.0.1"), &clientService.sin_addr.s_addr);
    clientService.sin_port = htons(8080);

    iResult = connect(ConnectSocket, (SOCKADDR*)&clientService, sizeof(clientService));
    if (iResult == SOCKET_ERROR) {
        wprintf(L"connect function failed with error: %ld\n", WSAGetLastError());
        iResult = closesocket(ConnectSocket);
        if (iResult == SOCKET_ERROR)
            wprintf(L"closesocket function failed with error: %ld\n", WSAGetLastError());
        WSACleanup();
    }
    else {
        wprintf(L"Connected to server.\n");
        closesocket(ConnectSocket);
    }*/






    /*std::cout << "WSAConnect:" << std::endl;
    WSADATA wsaData1;
    SOCKET Winsock;//listener socket
    struct sockaddr_in clientService1;

    WSAStartup(MAKEWORD(2, 2), &wsaData1);
    Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

    //check socket status
    if (Winsock == INVALID_SOCKET)
    {
        WSACleanup();
        //return -1;
    }

    clientService1.sin_family = AF_INET;
    InetPtonW(AF_INET, (PCWSTR)(L"127.0.0.1"), &clientService1.sin_addr.s_addr);
    clientService1.sin_port = htons(8080);

    if (WSAConnect(Winsock, (SOCKADDR*)&clientService1, sizeof(clientService1), NULL, NULL, NULL, NULL) == SOCKET_ERROR)
    {
        std::cout << "Failed to coonect" << std::endl;
        WSACleanup();
    }
    else {
        std::cout << "success to coonect" << std::endl;
    }*/



    /*LPVOID  pAddressToFree = nullptr, LdrLoadDllAddress = nullptr;
    HANDLE hCurrentProcess = NULL;
    SIZE_T numberOfBytesRead = NULL;
    int index = NULL, size = NULL;

    size = addressesToFree.getCurrentSize();
    pAddressToFree = addressesToFree.getArray();
    LdrLoadDllAddress = GetProcAddress(GetModuleHandleW(L"C:\\Windows\\System32\\ntdll.dll"), "LdrLoadDll");
    hCurrentProcess = GetCurrentProcess();
    
    if (size) {
        if (!WriteProcessMemory(hCurrentProcess, LdrLoadDllAddress, (LPVOID)(*(UINT64*)(pAddressToFree)), 5, &numberOfBytesRead)) {
            Utils::Error("Failed write 5 original bytes to ntdll!LdrLoadDll");
            return EXIT_FAILURE;
        }
    }

    CloseHandle(hCurrentProcess);

#ifdef  _WIN64
    while (index < size && *(UINT64*)pAddressToFree) {
        if (!VirtualFree((LPVOID)(*(UINT64*)(pAddressToFree)), NULL, MEM_RELEASE)) {
#else
    while (index < size && *(UINT32*)pAddressToFree) {
        if (!VirtualFree((LPVOID)(*(UINT32*)(pAddressToFree)), NULL, MEM_RELEASE)) {
#endif
            Utils::Error("Failed free address");
            return EXIT_FAILURE;
        }
#ifdef  _WIN64
        pAddressToFree = (LPVOID)((UINT64)pAddressToFree + 8);
#else
        pAddressToFree = (LPVOID)((UINT32)pAddressToFree + 4);
#endif
        ++index;
    }*/

    return EXIT_SUCCESS;
}