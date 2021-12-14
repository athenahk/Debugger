#include<vector>
#include "breakpoint.h"
#include "debugger.h"
#include "capstone.h"
using std::vector;
//�ϵ㼯��
vector<bp> g_bp;
int tfFlag = 0;
wp g_wp;
LPVOID g_addr = 0; //���ڼ�¼ʵ�����öϵ㵥����������һ��ָ��֮ǰ�����쳣�ĵ�ַ
// DR7�Ĵ����ṹ��
typedef struct _DBG_REG7 {
	unsigned L0 : 1; unsigned G0 : 1;
	unsigned L1 : 1; unsigned G1 : 1;
	unsigned L2 : 1; unsigned G2 : 1;
	unsigned L3 : 1; unsigned G3 : 1;
	unsigned LE : 1; unsigned GE : 1;
	unsigned : 6;// ��������Ч�ռ�
	unsigned RW0 : 2; unsigned LEN0 : 2;
	unsigned RW1 : 2; unsigned LEN1 : 2;
	unsigned RW2 : 2; unsigned LEN2 : 2;
	unsigned RW3 : 2; unsigned LEN3 : 2;
} R7, * PR7;


void Breakpoint::SetInt3BreakPoint(HANDLE hProcess, LPVOID addr)
{
	bp int3bp{ addr };
	DWORD dwRead = 0;
	ReadProcessMemory(hProcess, addr, &int3bp.oldBytes, 1, &dwRead);
	WriteProcessMemory(hProcess, addr, "\xcc", 1, &dwRead);
	g_bp.push_back(int3bp);
	g_wp.bpType = 0;
}

DWORD Breakpoint::FixInt3BreakPoint(HANDLE hProcess, LPVOID addr, HANDLE hThread)
{
	//ԭ��һ������ϵ���£����������������쳣�����Ե�ǰEipָ�����
	//�����쳣����һ��ָ�Ȼ������Ϊ���ó��������������У�������Ҫ��
	//EIPָ�����cc�ĵط������ҽ�ԭ�е�����д��ȥ


	for (int i = 0; i < g_bp.size(); i++)
	{
		if (addr == g_bp[i].addr)
		{
			//��ԭ��������д�ش�����
			DWORD bytes = 0;
			WriteProcessMemory(hProcess, addr, &g_bp[i].oldBytes, 1, &bytes);

			CONTEXT context{ CONTEXT_ALL };
			GetThreadContext(hThread, &context);
			context.Eip -= 1;
			SetThreadContext(hThread, &context);
			if(addr != start)
			Breakpoint::SetTfBreakPoint(hThread);
			//�����Ѵ���
			g_wp.bpType = 1;
			g_addr = addr;
			g_wp.tfFlag = 1;
			//tfFlag = 1;
			return DBG_CONTINUE;
		}
	}

	//δ������쳣
	return DBG_EXCEPTION_NOT_HANDLED;
}

void Breakpoint::SetTfBreakPoint(HANDLE hThread)
{
	//ԭ��CPU�ı�־�Ĵ����д���TF��־λ����CPUִ����һ��ָ��֮��
	//����TFλ�Ƿ�Ϊ1�� ���Ϊ1��CPU����������һ���쳣��

	//��ȡ��ǰ�̵߳������ģ����а���EFLAGS�Ĵ���
	CONTEXT context{ CONTEXT_ALL };
	GetThreadContext(hThread, &context);

	//��TFλ��1
	context.EFlags |= 0x00000100;

	SetThreadContext(hThread, &context);
}

void Breakpoint::SetHwBreakPoint(HANDLE hThread, LPVOID addr, int type, int len)
{
	//ԭ����CPU�ṩ��Drϵ�мĴ��������������4��Ӳ���ϵ㣬
	//�ϵ��λ����Dr0~Dr3ȥ���棬��Ӧ��Dr7�е�Ln��ʾ��Ӧ��
	//�ϵ��Ƿ���Ч,Dr7�Ĵ������ṩ��RW\LEN��־λ,��������
	//�ϵ������,
	//RW:0(ִ�жϵ�,����lenҲ����Ϊ0���� 1(д) 3(��д��
	//len:0(1�ֽ�), 1��2�ֽ�), 2��8�ֽ�), 3��4�ֽ�)

	if (len == 1)
		addr = (LPVOID)((DWORD)addr - (DWORD)addr % 2);
	else if (len == 3)
		addr = (LPVOID)((DWORD)addr - (DWORD)addr % 4);
	CONTEXT context{ CONTEXT_ALL };
	GetThreadContext(hThread, &context);
	bp hwbp;
	hwbp.addr = addr;
	PR7 Dr7 = (PR7)&context.Dr7;
	//Dr0������
	if (Dr7->L0 == 0)
	{
		Dr7->L0 = 1;
		Dr7->RW0 = type;
		Dr7->LEN0 = len;
		context.Dr0 = (DWORD)addr;
	}
	//Dr1������
	else if (Dr7->L1 == 0)
	{
		Dr7->L1 = 1;
		Dr7->RW1 = type;
		Dr7->LEN1 = len;
		context.Dr1 = (DWORD)addr;
	}
	//Dr2������
	else if (Dr7->L2 == 0)
	{
		Dr7->L2 = 1;
		Dr7->RW2 = type;
		Dr7->LEN2 = len;
		context.Dr2 = (DWORD)addr;
	}
	//Dr3������
	else if (Dr7->L3 == 0)
	{
		Dr7->L3 = 1;
		Dr7->RW3 = type;
		Dr7->LEN3 = len;
		context.Dr3 = (DWORD)addr;
	}
	else
	{
		printf("Ӳ���ϵ����������ܼ����洢!");
	}
	//���üĴ���
	g_wp.bpType = 0;
	g_wp.type = type;
	g_wp.len = len;
	g_bp.push_back(hwbp);
	SetThreadContext(hThread, &context);
}

void Breakpoint::FixHwBreakPoint(HANDLE hThread, HANDLE hProcess, LPVOID& addr)
{
	//ԭ�������Ӳ���ϵ�������ˣ��ڴ���ʱ�����ԼĴ���
	//Dr6�ĵ�4λ����Ӧ�ı�־λ�ͻ���Ϊ1
	//��0λ��1�ʹ���Dr0�еĶϵ�������ˣ�Ȼ�����������
	int flag = 0;
	CONTEXT context{ CONTEXT_ALL };
	GetThreadContext(hThread, &context);
	PR7 Dr7 = (PR7)&context.Dr7;
	DWORD eip = context.Eip;
	//g_wp.type = Dr7->RW0;g_wp.len = Dr7->LEN0;
	switch (context.Dr6 & 0xF)
	{
	case 1:Dr7->L0 = 0; g_wp.type = Dr7->RW0; g_wp.len = Dr7->LEN0; flag = 1; g_addr = (LPVOID)context.Dr0; break;
	case 2:Dr7->L1 = 0; g_wp.type = Dr7->RW1; g_wp.len = Dr7->LEN1; flag = 1; g_addr = (LPVOID)context.Dr1; break;
	case 4:Dr7->L2 = 0; g_wp.type = Dr7->RW2; g_wp.len = Dr7->LEN2; flag = 1; g_addr = (LPVOID)context.Dr2; break;
	case 8:Dr7->L3 = 0; g_wp.type = Dr7->RW3; g_wp.len = Dr7->LEN3; flag = 1; g_addr = (LPVOID)context.Dr3; break;
	}
	//if (g_wp.type == 1 || g_wp.type == 3)
	//{
	//	for (int i = 0; i < g_bp.size(); i++)
	//	{
	//		char code[10] = { 0 };
	//		int len = Capstone::GetInstrLen(hProcess, g_bp[i].addr, 10, code);//code���ã��˺�����ָ���
	//		if ((DWORD)g_bp[i].addr + len == (DWORD)addr)
	//		{
	//			addr = g_bp[i].addr;
	//			context.Eip = (DWORD)addr;
	//		}
	//	}
	//}
	SetThreadContext(hThread, &context);
	if (flag == 1) {
		Breakpoint::SetTfBreakPoint(hThread);
		g_wp.bpType = 2;
		g_wp.tfFlag = 1;
	}
}

int Breakpoint::FixMemBreakPoint(HANDLE hProcess,HANDLE hThread, int type, LPVOID addr, LPVOID memAddr)
{
	int result = 0;
	if (type == 8)
	{
		int flag = 0;
		for (int i = 0; i < g_bp.size(); i++)
		{
			if (g_bp[i].addr == addr && g_bp[i].isMemBp == TRUE)
			{
				DWORD dwOldProtect = 0;
				VirtualProtectEx(hProcess, addr, 1, g_bp[i].oldProtect, &dwOldProtect);
				//�ϵ���ϵĵط�����Ҫ������һ��tf�ϵ��Է��������ڴ�������ʵ�����öϵ�
				Breakpoint::SetTfBreakPoint(hThread);
				g_wp.bpType = 3;
				g_wp.memBpType = 8;
				flag = 1;
			}
		}
		if (flag == 0)
		{
			DWORD dwOldProtect = 0;
			DWORD memAttr = 0;
			DWORD startAddr = (DWORD)addr - (DWORD)addr % 0x1000;
			for (int i = 0; i < g_bp.size(); i++)
			{
				if (startAddr <= (DWORD)g_bp[i].addr &&(DWORD)g_bp[i].addr <= startAddr + 0xfff)
				{
					memAttr = g_bp[i].oldProtect;
				}
			}
			VirtualProtectEx(hProcess, addr, 1, memAttr, &dwOldProtect);
			Breakpoint::SetTfBreakPoint(hThread);
			g_wp.bpType = 3;
			g_wp.memBpType = 8;
			return 1;
		}
	}
	if (type == 1)
	{
		int flag = 0;
		for (int i = 0; i < g_bp.size(); i++)
		{
			if (g_bp[i].addr == memAddr && g_bp[i].isMemBp == TRUE)
			{
				DWORD dwOldProtect = 0;
				VirtualProtectEx(hProcess, memAddr, 1, g_bp[i].oldProtect, &dwOldProtect);
				//�ϵ���ϵĵط�����Ҫ������һ��tf�ϵ��Է��������ڴ�������ʵ�����öϵ�
				Breakpoint::SetTfBreakPoint(hThread);
				g_wp.bpType = 3;
				g_wp.memBpType = 1;
				flag = 1;
			}
		}
		if (flag == 0)
		{
			DWORD dwOldProtect = 0;
			DWORD memAttr = 0;
			DWORD startAddr = (DWORD)addr - (DWORD)addr % 0x1000;
			/*for (int i = 0; i < g_bp.size(); i++)
			{
				if (startAddr <= (DWORD)g_bp[i].addr && (DWORD)g_bp[i].addr <= startAddr + 0xfff)
				{
					memAttr = g_bp[i].oldProtect;
				}
			}*/
			VirtualProtectEx(hProcess, memAddr, 1, PAGE_READWRITE, &dwOldProtect);
			Breakpoint::SetTfBreakPoint(hThread);
			g_wp.bpType = 3;
			g_wp.memBpType = 1;
			return 1;
		}
	}
	return 0;
}
