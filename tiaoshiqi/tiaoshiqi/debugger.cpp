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

	//�Ե��Է�ʽ��������
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
		printf("���̴���ʧ��!");
	}

	//��ʼ����������棬���ں����ķ�������
	Capstone::Init();
}
//����������ϵͳ�Ժ�ͨ���ú������ܲ����������Ϣ
void debugger::run()
{
	while (WaitForDebugEvent(&debugEvent, INFINITE))
	{
		//�ڵõ��쳣��Ϣ֮����Ҫ���¾��
		openHandles();
		switch (debugEvent.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:      //�쳣�����¼�
			onDispatchException();
			break;
		case CREATE_PROCESS_DEBUG_EVENT: //���̴����¼�
			//bp startBp;
			oep = debugEvent.u.CreateProcessInfo.lpStartAddress;
			CONTEXT context{ CONTEXT_ALL };
			GetThreadContext(hThread, &context);
			start = (LPVOID)context.Eip;
			//g_bp.push_back(startBp);
			break;
		}



		//�������¼��Ĵ��������ظ�������ϵͳ��������������ʾ�����¼���û�б�����
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
	//�쳣����
	tfFlag = 0;
	auto exceptionCode = debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
	//�쳣��ַ
	auto exceptionAddr = debugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
	auto exceptionType = debugEvent.u.Exception.ExceptionRecord.ExceptionInformation[0];
	switch (exceptionCode)
	{
		//��INT 3(0XCC)������
	case EXCEPTION_BREAKPOINT:
		//�������Ե���״̬����ʱ������ϵͳ��Ϊ������
		//һ��ϵͳ�ϵ㣬������Ҫ���ľ�����ϵͳ�ϵ��
		//������ʱ��Ϊ�����OEP����int3�ϵ㣬����
		//��oep ��λ�ö�����
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
		//��Ӳ���ϵ����TF��־λ������
	case EXCEPTION_SINGLE_STEP:
	{
		if (g_wp.bpType == 1)
		{
			Breakpoint::SetInt3BreakPoint(hProcess, g_addr);
			dwContinueStatus = DBG_CONTINUE;
			tfFlag = 1;
			//isT = 1;
			//isT���ж��Ǵ���tf�����Ļ����Լ�����������tf��
			//����Ǵ���������tf�����ô�ӡ����࣬����
			//������
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
			//isT���ж��Ǵ���tf�����Ļ����Լ�����������tf��
			//����Ǵ���������tf�����ô�ӡ����࣬����
			//������
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
						//�ϵ���ϵĵط�����Ҫ������һ��tf�ϵ��Է��������ڴ�������ʵ�����öϵ�(��һ��flag == 0����
						//�������ڴ�ҳ��)
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
				//		//�ϵ���ϵĵط�����Ҫ������һ��tf�ϵ��Է��������ڴ�������ʵ�����öϵ�(��һ��flag == 0����
				//		//�������ڴ�ҳ��)
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
	//���ڴ�ϵ�������
	case EXCEPTION_ACCESS_VIOLATION:
		memAddr = (LPVOID)debugEvent.u.Exception.ExceptionRecord.ExceptionInformation[1];
		int result = Breakpoint::FixMemBreakPoint(hProcess, hThread, exceptionType, exceptionAddr, memAddr);
		if (result == 1)
			goto x;
		break;
	}

	//��ӡ��������

	Capstone::DisAsm(hProcess, exceptionAddr, 10);
	//����ָ��
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
			//����ϵ�INT3
			Breakpoint::SetInt3BreakPoint(hProcess, (LPVOID)addr);
		}
		else if (!_stricmp(szCmd, "t"))
		{
			//���õ����ϵ�
			Breakpoint::SetTfBreakPoint(hThread);
			isT = 1;
			break;
		}
		//ֱ������
		else if (!_stricmp(szCmd, "g"))
		{
			isT = 0;
			//Breakpoint::SetTfBreakPoint(hThread);
			break;
		}
		//��Ӳ���ϵ�
		else if (!_stricmp(szCmd, "ba"))
		{
			//ԭ����CPU�ṩ��Drϵ�мĴ��������������4��Ӳ���ϵ㣬
			//�ϵ��λ����Dr0~Dr3ȥ���棬��Ӧ��Dr7�е�Ln��ʾ��Ӧ��
			//�ϵ��Ƿ���Ч,Dr7�Ĵ������ṩ��RW\LEN��־λ,��������
			//�ϵ������,
			//RW:0(ִ�жϵ�,����lenҲ����Ϊ0���� 1(д) 3(��д��
			//len:0(1�ֽ�), 1��2�ֽ�), 2��8�ֽ�), 3��4�ֽ�)
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
			//Ӳ��ִ�жϵ�
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
			//0��ȡ�쳣��1д���쳣 8ִ���쳣
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
