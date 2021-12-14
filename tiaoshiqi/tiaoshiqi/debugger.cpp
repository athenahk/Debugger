#include<stdio.h>
#include<windows.h>
#include "debugger.h"
#include"capstone.h"
#include"breakpoint.h"
LPVOID start;
void debugger::open(LPCSTR szPath)
{
	STARTUPINFOA si{ sizeof(si) };
	PROCESS_INFORMATION pi;

	//以调试方式创建进程
	BOOL bResult = CreateProcessA(szPath,
		NULL,
		NULL,
		NULL,
		FALSE,
		DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&si,
		&pi);
	if (!bResult)
	{
		printf("进程创建失败!");
	}

	//初始化反汇编引擎，用于后续的反汇编操作
	Capstone::Init();
}
//建立调试子系统以后，通过该函数接受并处理调试信息
void debugger::run()
{
	while (WaitForDebugEvent(&debugEvent, INFINITE))
	{
		//在得到异常信息之后，需要更新句柄
		openHandles();
		switch (debugEvent.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:      //异常调试事件
			onDispatchException();
			break;
		case CREATE_PROCESS_DEBUG_EVENT: //进程创建事件
			//bp startBp;
			oep = debugEvent.u.CreateProcessInfo.lpStartAddress;
			CONTEXT context{ CONTEXT_ALL };
			GetThreadContext(hThread, &context);
			start = (LPVOID)context.Eip;
			//g_bp.push_back(startBp);
			break;
		}



		//将调试事件的处理结果返回给调试子系统，第三个参数表示调试事件有没有被处理
		ContinueDebugEvent(debugEvent.dwProcessId,
			debugEvent.dwThreadId,
			dwContinueStatus);

		closeHandles();
	}
}

void debugger::openHandles()
{
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, debugEvent.dwProcessId);
	hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debugEvent.dwThreadId);
}

void debugger::closeHandles()
{

	CloseHandle(hProcess);
	CloseHandle(hThread);
}

int isT = 0;
LPVOID g_memAddr = 0;
LPVOID memAddr;
DWORD dwGlobalOldProtect;
void debugger::onDispatchException()
{
	//异常类型
	tfFlag = 0;
	auto exceptionCode = debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
	//异常地址
	auto exceptionAddr = debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
	auto exceptionType = debugEvent.u.Exception.ExceptionRecord.ExceptionInformation[0];
	switch (exceptionCode)
	{
		//由INT 3(0XCC)所引发
	case EXCEPTION_BREAKPOINT:
		//当程序以调试状态创建时，操作系统会为其设置
		//一个系统断点，我们需要做的就是在系统断点断
		//下来的时候，为程序的OEP设置int3断点，让其
		//在oep 的位置断下来
		if (isSystemPoint)
		{
			if (oep) {
				Breakpoint::SetInt3BreakPoint(hProcess, oep);
				isSystemPoint = FALSE;
			}
			else {
				Breakpoint::SetInt3BreakPoint(hProcess, start);
				isSystemPoint = FALSE;
			}
		}

		//Breakpoint::SetInt3BreakPoint(hProcess, (LPVOID)context.Eip);

		dwContinueStatus = Breakpoint::FixInt3BreakPoint(hProcess, exceptionAddr, hThread);
		tfFlag = 0;
		break;
		//由硬件断点或者TF标志位所引发
	case EXCEPTION_SINGLE_STEP:
	{
		if (g_wp.bpType == 1)
		{
			Breakpoint::SetInt3BreakPoint(hProcess, g_addr);
			dwContinueStatus = DBG_CONTINUE;
			tfFlag = 1;
			//isT = 1;
			//isT是判断是代码tf引发的还是自己命令引发的tf，
			//如果是代码引发的tf，则不用打印反汇编，并跳
			//过输入
			if (isT == 1)
			{
				break;
			}
			//break;
			goto x;
		}
		else if (g_wp.bpType == 2)
		{
			Breakpoint::SetHwBreakPoint(hThread, g_addr, g_wp.type, g_wp.len);
			dwContinueStatus = DBG_CONTINUE;
			tfFlag = 1;
			//isT = 1;
			//isT是判断是代码tf引发的还是自己命令引发的tf，
			//如果是代码引发的tf，则不用打印反汇编，并跳
			//过输入
			if (isT == 1)
			{
				break;
			}
			//break;
			goto x;
		}
		else if (g_wp.bpType == 3)
		{
			if (g_wp.memBpType == 8)
			{
				int flag = 0;
				DWORD dwOldProtect = 0;
				//DWORD dwOldProtect = 0;
				DWORD memAttr = 0;
				//LPVOID g_memAddr = 0;
				DWORD startAddr = (DWORD)exceptionAddr - (DWORD)exceptionAddr % 0x1000;
				for (int i = 0; i < g_bp.size(); i++)
				{
					if (startAddr <= (DWORD)g_bp[i].addr && (DWORD)g_bp[i].addr <= startAddr + 0xfff)
					{
						//断到想断的地方后，需要在设置一次tf断点以方便设置内存属性以实现永久断点(下一步flag == 0代表
						//运行至内存页外)
						VirtualProtectEx(hProcess, exceptionAddr, 1, PAGE_READWRITE, &dwOldProtect);
						g_memAddr = exceptionAddr;
						flag = 1;
					}
				}

				if (flag == 0)
					VirtualProtectEx(hProcess, g_memAddr, 1, PAGE_READWRITE, &dwOldProtect);
				//VirtualProtectEx(hProcess, exceptionAddr, 1, PAGE_READWRITE, &dwOldProtect);
			}
			if (g_wp.memBpType == 1)
			{
				int flag = 0;
				DWORD dwOldProtect = 0;
				//DWORD dwOldProtect = 0;
				DWORD memAttr = 0;
				//LPVOID g_memAddr = 0;
				DWORD startAddr = (DWORD)exceptionAddr - (DWORD)exceptionAddr % 0x1000;
				//for (int i = 0; i < g_bp.size(); i++)
				//{
				//	if (g_bp[i].)
				//	{
				//		//断到想断的地方后，需要在设置一次tf断点以方便设置内存属性以实现永久断点(下一步flag == 0代表
				//		//运行至内存页外)
				//		VirtualProtectEx(hProcess, exceptionAddr, 1, PAGE_READWRITE, &dwOldProtect);
				//		g_memAddr = exceptionAddr;
				//		flag = 1;
				//	}
				//}

				VirtualProtectEx(hProcess, memAddr, 1, PAGE_EXECUTE_READ, &dwOldProtect);
				/*if (flag == 0)
					VirtualProtectEx(hProcess, g_memAddr, 1, PAGE_READWRITE, &dwOldProtect);*/
					//VirtualProtectEx(hProcess, exceptionAddr, 1, PAGE_READWRITE, &dwOldProtect);
			}
			if (isT == 1)
			{
				break;
			}
			//break;
			goto x;
		}
		Breakpoint::FixHwBreakPoint(hThread, hProcess, exceptionAddr);
		tfFlag = 0;

	}
	break;
	//由内存断点所引发
	case EXCEPTION_ACCESS_VIOLATION:
		memAddr = (LPVOID)debugEvent.u.Exception.ExceptionRecord.ExceptionInformation[1];
		int result = Breakpoint::FixMemBreakPoint(hProcess, hThread, exceptionType, exceptionAddr, memAddr);
		if (result == 1)
			goto x;
		break;
	}

	//打印反汇编代码

	Capstone::DisAsm(hProcess, exceptionAddr, 10);
	//输入指令
	GetInput();

x:	return;
}

void debugger::GetInput()
{
	char szCmd[0x10] = { 0 };
	while (1)
	{
		scanf_s("%s", szCmd, 0x10);
		if (!_stricmp(szCmd, "bp"))
		{
			DWORD addr = 0;
			scanf_s("%x", &addr);
			//软件断点INT3
			Breakpoint::SetInt3BreakPoint(hProcess, (LPVOID)addr);
		}
		else if (!_stricmp(szCmd, "t"))
		{
			//设置单步断点
			Breakpoint::SetTfBreakPoint(hThread);
			isT = 1;
			break;
		}
		//直接运行
		else if (!_stricmp(szCmd, "g"))
		{
			isT = 0;
			//Breakpoint::SetTfBreakPoint(hThread);
			break;
		}
		//下硬件断点
		else if (!_stricmp(szCmd, "ba"))
		{
			//原理：由CPU提供的Dr系列寄存器做多可以设置4个硬件断点，
			//断点的位置由Dr0~Dr3去保存，相应的Dr7中的Ln表示对应的
			//断点是否有效,Dr7寄存器还提供了RW\LEN标志位,用于设置
			//断点的类型,
			//RW:0(执行断点,它的len也必须为0）， 1(写) 3(读写）
			//len:0(1字节), 1（2字节), 2（8字节), 3（4字节)
			DWORD addr = 0;
			scanf_s("%x", &addr);
			int type;
			int len, l;
			scanf_s("%d", &type);
			scanf_s("%d", &len);
			if (len == 1)
				l = 0;
			else if (len == 2)
				l = 1;
			else if (len == 8)
				l = 2;
			else if (len == 4)
				l = 3;
			//硬件执行断点
			Breakpoint::SetHwBreakPoint(hThread, (LPVOID)addr, type, l);
		}
		else if (!_stricmp(szCmd, "u"))
		{
			DWORD addr;
			scanf_s("%d", &addr);
			Capstone::DisAsm(hProcess, (LPVOID)addr, 10);
		}
		else if (!_stricmp(szCmd, "mp"))
		{
			bp tmpBp;
			DWORD addr;
			int type;
			scanf_s("%x%d", &addr, &type);
			//0读取异常，1写入异常 8执行异常
			if (type == 8)
			{
				DWORD dwOldProtect = 0;
				VirtualProtectEx(hProcess, (LPVOID)addr, 1, PAGE_READWRITE, &dwOldProtect);
				tmpBp.isMemBp = TRUE;
				tmpBp.addr = (LPVOID)addr;
				tmpBp.oldProtect = dwOldProtect;
				tmpBp.memBpType = 0;
				g_bp.push_back(tmpBp);
			}
			if (type == 1)
			{

				DWORD dwOldProtect = 0;
				VirtualProtectEx(hProcess, (LPVOID)addr, 1, PAGE_EXECUTE_READ, &dwOldProtect);
				tmpBp.isMemBp = TRUE;
				tmpBp.addr = (LPVOID)addr;
				dwGlobalOldProtect = tmpBp.oldProtect = dwOldProtect;
				tmpBp.memBpType = 1;
				g_bp.push_back(tmpBp);
			}
			if (type == 0)
			{

				DWORD dwOldProtect = 0;
				VirtualProtectEx(hProcess, (LPVOID)addr, 1, PAGE_NOACCESS, &dwOldProtect);
				tmpBp.isMemBp = TRUE;
				tmpBp.addr = (LPVOID)addr;
				dwGlobalOldProtect = tmpBp.oldProtect = dwOldProtect;
				tmpBp.memBpType = 8;
				g_bp.push_back(tmpBp);
			}
		}
	}
}
