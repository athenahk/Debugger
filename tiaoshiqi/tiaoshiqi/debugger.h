#pragma once
#include<windows.h>
extern DWORD dwGlobalOldProtect;
extern LPVOID start;
class debugger
{
public:

	BOOL isSystemPoint = TRUE;
	DEBUG_EVENT debugEvent{};

	void open(LPCSTR szPath);
	void run();
	LPVOID oep;
	DWORD dwContinueStatus = DBG_CONTINUE;
	HANDLE hProcess;
	HANDLE hThread;
	void openHandles();
	void closeHandles();
	void onDispatchException();
	void GetInput();
};