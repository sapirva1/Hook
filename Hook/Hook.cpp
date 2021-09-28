#include "utils.h"

/*
* Compiled with CFG
*/

int main() {
    /*std::cout << "Before Hook" << std::endl;
    
    MessageBoxW(NULL,L"Before", L"Before caption", MB_OK);
    
    std::cout << "After Hook" << std::endl;

    if (Utils::hookWrapper(&MessageBoxW, &Utils::MessageBoxWHook, 7, MessageBoxWFunc)) {
        return EXIT_FAILURE;
    }

    MessageBoxW(NULL, L"GL", L"Fater captiopn", MB_OK);*/






    /*int iResult = NULL;
    WSADATA wsaData;
    SOCKET ConnectSocket;
    sockaddr_in clientService;

    std::cout << "Before Hook" << std::endl;

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
        system("pause");
        return 1;
    }
    else {
        wprintf(L"Connected to server.\n");
    }

    closesocket(ConnectSocket);
    system("pause");

    std::cout << "After Hook" << std::endl;

    if (Utils::hookWrapper(&connect, &Utils::connectHook, 7, connectFunc)) {
        return EXIT_FAILURE;
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
        system("pause");
        return 1;
    }
    else {
        wprintf(L"Connected to server.\n");
    }

    closesocket(ConnectSocket);*/








    /*std::cout << "WSAConnect: 0x" << &WSAConnect << std::endl;

    if (Utils::hookWrapper(&WSAConnect, &Utils::WSAConnectHook, 7, WSAConnectFunc)) {
        return EXIT_FAILURE;
    }

    WSADATA wsaData;
    SOCKET Winsock;//listener socket
    struct sockaddr_in clientService;

    WSAStartup(MAKEWORD(2, 2), &wsaData);
    Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

    //check socket status
    if (Winsock == INVALID_SOCKET)
    {
        WSACleanup();
        return -1;
    }

    clientService.sin_family = AF_INET;
    InetPtonW(AF_INET, (PCWSTR)(L"127.0.0.1"), &clientService.sin_addr.s_addr);
    clientService.sin_port = htons(8080);

    if (WSAConnect(Winsock, (SOCKADDR*)&clientService, sizeof(clientService), NULL, NULL, NULL, NULL) == SOCKET_ERROR)
    {
        std::cout << "Failed to coonect" << std::endl;
        WSACleanup();
        system("pause");
        return -1;
    }

    std::cout << "success to coonect" << std::endl;*/



    system("pause");

    return EXIT_SUCCESS;
} 