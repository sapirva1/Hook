#include "utils.h"

/*
* Compiled with CFG + DEP + ASLR on Release - 64 bit + 32 bit
*/

//Hook ws2_32.dll - connect & WSAConnect
//Hook wsock32.dll - connect

int main() {
    if (Utils::hookWrapper(&Utils::LdrLoadDllHook, 5, L"C:\\Windows\\System32\\ntdll.dll", "LdrLoadDll", LdrLoadDllFunc)) { // 64 bit + 32 bit
        Utils::Error("Failed Hook ntdll - LdrLoadDll");
    }/*
#ifdef _WIN64
    HMODULE hTrusty = LoadLibraryW(L"C:\\Users\\sapva\\Desktop\\TrustyDll\\TrustyDll\\x64\\Release\\TrustyDll.dll");
#else
    HMODULE hTrusty = LoadLibraryW(L"C:\\Users\\sapva\\Desktop\\TrustyDll\\TrustyDll\\Release\\TrustyDll.dll");
#endif

    if (!hTrusty) {
        Utils::Error("Failed load Trusty dll");
    }*/

    HMODULE hWs2_32 = LoadLibraryW(L"ws2_32");
    HMODULE hWsock32 = LoadLibraryW(L"wsock32");

    std::cout << "connect:" << std::endl;
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
    }






    std::cout << "WSAConnect:" << std::endl;
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
    }

    return EXIT_SUCCESS;
}