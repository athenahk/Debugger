#include<stdio.h>
#include"debugger.h"
#include "capstone.h"

BOOL EnableDebugPrivilege(BOOL fEnable)
{
    BOOL fOk = FALSE;
    HANDLE hToken;

    // 1. 获取当前进程的令牌，令牌会被用于[开启]权限
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {

        // TOKEN_PRIVILEGES结构体 保存想要提升的权限的结构, 以下是对结构体的调整
        TOKEN_PRIVILEGES tp = { 0 };
        tp.PrivilegeCount = 1;
        // 获取指定权限的Luid(想提升什么权限，第二个参数就是什么)
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
        // 表示想要开启权限 SE_DEBUG_NAME    1默认开启   2 开启    4 关闭
        tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;

        // 2. AdjustTokenPrivileges 修改指定令牌的权限
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

        // 通过 GetLastError 确认是否成功
        fOk = (GetLastError() == ERROR_SUCCESS);
        CloseHandle(hToken);
    }
    return(fOk);
}

int main()
{
	debugger debug;
    int choice;
    printf("1.打开程序, 2.附加程序:");
    scanf_s("%d", &choice);
    if(choice == 1)
	    debug.open("ConsoleApplication1.exe");
    else if (choice == 2)
    {
        Capstone::Init();
        int pid;
        EnableDebugPrivilege(TRUE);
        printf("请输入PID:");
        scanf_s("%d", &pid);
        DebugActiveProcess(pid);
    }
	debug.run();
}