#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

static int write_file(const wchar_t *path) {
    HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return (int)GetLastError();
    DWORD written;
    BOOL ok = WriteFile(file, "sandbox\n", 8, &written, NULL);
    DWORD error = ok ? 0 : GetLastError();
    CloseHandle(file);
    return (int)error;
}
int wmain(int argc, wchar_t **argv) {
    if (argc < 2) return 99;
    if (!wcscmp(argv[1], L"identity")) {
        HANDLE token;
        DWORD appcontainer = 0, size;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 99;
        BOOL ok = GetTokenInformation(token, TokenIsAppContainer, &appcontainer, sizeof(appcontainer), &size);
        CloseHandle(token);
        return ok && appcontainer == 1 ? 0 : 98;
    }
    if (!wcscmp(argv[1], L"echo")) {
        for (int i = 2; i < argc; ++i) wprintf(L"[%ls]\n", argv[i]);
        return 0;
    }
    if (argc < 3) return 99;
    if (!wcscmp(argv[1], L"write")) return write_file(argv[2]);
    if (!wcscmp(argv[1], L"read")) {
        HANDLE file = CreateFileW(argv[2], GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (file == INVALID_HANDLE_VALUE) return (int)GetLastError();
        CloseHandle(file);
        return 0;
    }
    if (!wcscmp(argv[1], L"delete")) return DeleteFileW(argv[2]) ? 0 : (int)GetLastError();
    if (!wcscmp(argv[1], L"rename") && argc == 4)
        return MoveFileW(argv[2], argv[3]) ? 0 : (int)GetLastError();
    if (!wcscmp(argv[1], L"connect")) {
        WSADATA data;
        if (WSAStartup(MAKEWORD(2, 2), &data)) return 99;
        SOCKET socket = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
        if (socket == INVALID_SOCKET) return WSAGetLastError();
        struct sockaddr_in address;
        ZeroMemory(&address, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons((u_short)_wtoi(argv[2]));
        int code = connect(socket, (struct sockaddr *)&address, sizeof(address)) ? WSAGetLastError() : 0;
        closesocket(socket);
        WSACleanup();
        return code;
    }
    if (!wcscmp(argv[1], L"delayed-write")) { Sleep(1500); return write_file(argv[2]); }
    if (!wcscmp(argv[1], L"spawn") || !wcscmp(argv[1], L"spawn-exit")) {
        wchar_t executable[32768], line[32768];
        if (!GetModuleFileNameW(NULL, executable, 32768)) return 99;
        swprintf(line, 32768, L"\"%ls\" delayed-write \"%ls\"", executable, argv[2]);
        STARTUPINFOW startup = {0}; PROCESS_INFORMATION process = {0};
        startup.cb = sizeof(startup);
        if (!CreateProcessW(executable, line, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                            NULL, NULL, &startup, &process)) return (int)GetLastError();
        CloseHandle(process.hThread); CloseHandle(process.hProcess);
        if (!wcscmp(argv[1], L"spawn")) Sleep(10000);
        return 0;
    }
    return 99;
}
