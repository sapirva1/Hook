#include "utils.h"

/*
* Compiled with CFG
*/

int main() {
        MessageBoxW(NULL,L"Before", L"Before caption", MB_OK);
#ifdef _WIN64
    if (Utils::hookWrapper(&Utils::MessageBoxWHook, 7, L"user32.dll", "MessageBoxW", MessageBoxWFunc)) { // 64 bit
        Utils::Error("Failed Hook 64 bit");
        return EXIT_FAILURE;
    }
#else
    if (hookWrapper(&MessageBoxWHook, 5, L"user32.dll", "MessageBoxW", MessageBoxWFunc)) { // 32 bit
        Utils::Error("Failed Hook 32 bit");
        return EXIT_FAILURE;
    }
#endif
    MessageBoxW(NULL, L"After", L"After caption", MB_OK);
    system("pause");

    MessageBoxW(NULL, L"GL", L"After caption", MB_OK);
    system("pause");






    int iResult = NULL;
    WSADATA wsaData;
    SOCKET ConnectSocket;
    sockaddr_in clientService = { 0 };

    std::cout << "Before Hook - try connect" << std::endl;

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
    }

    closesocket(ConnectSocket);
    system("pause");

    std::cout << "After Hook - try connect" << std::endl;

    if (Utils::hookWrapper(&Utils::connectHook, 7, L"ws2_32.dll", "connect", connectFunc)) { // 64 bit
        Utils::Error("Failed Hook 64 bit");
        return EXIT_FAILURE;
    }

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
    }

    closesocket(ConnectSocket);
    system("pause");














    std::cout << "WSAConnect connect before" << std::endl;

    WSADATA wsaData1;
    SOCKET Winsock;//listener socket
    struct sockaddr_in clientService1;

    WSAStartup(MAKEWORD(2, 2), &wsaData1);
    Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

    //check socket status
    if (Winsock == INVALID_SOCKET)
    {
        WSACleanup();
        return -1;
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

    std::cout << "WSAConnect connect after" << std::endl;


    if (Utils::hookWrapper(&Utils::WSAConnectHook, 7, L"ws2_32.dll", "WSAConnect", WSAConnectFunc)) { // 64 bit
        Utils::Error("Failed Hook 64 bit");
        return EXIT_FAILURE;
    }

    WSAStartup(MAKEWORD(2, 2), &wsaData1);
    Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

    //check socket status
    if (Winsock == INVALID_SOCKET)
    {
        WSACleanup();
        return -1;
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






    system("pause");
    return EXIT_SUCCESS;
} 