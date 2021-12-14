#include<vector>
#include "breakpoint.h"
#include "debugger.h"
#include "capstone.h"
using std::vector;
//断点集合
vector<bp> g_bp;
int tfFlag = 0;
wp g_wp;
LPVOID g_addr = 0; //用于记录实现永久断点单步走走向下一条指令之前出现异常的地址
// DR7寄存器结构体
typedef struct _DBG_REG7 {
	unsigned L0 : 1; unsigned G0 : 1;
	unsigned L1 : 1; unsigned G1 : 1;
	unsigned L2 : 1; unsigned G2 : 1;
	unsigned L3 : 1; unsigned G3 : 1;
	unsigned LE : 1; unsigned GE : 1;
	unsigned : 6;// 保留的无效空间
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
	//原理：一但软件断点断下，由于他是陷阱类异常，所以当前Eip指向的是
	//产生异常的吓一跳指令，然后我们为了让程序能正常的运行，我们需要将
	//EIP指向产生cc的地方，并且将原有的数据写回去


	for (int i = 0; i < g_bp.size(); i++)
	{
		if (addr == g_bp[i].addr)
		{
			//将原本的数据写回代码中
			DWORD bytes = 0;
			WriteProcessMemory(hProcess, addr, &g_bp[i].oldBytes, 1, &bytes);

			CONTEXT context{ CONTEXT_ALL };
			GetThreadContext(hThread, &context);
			context.Eip -= 1;
			SetThreadContext(hThread, &context);
			if(addr != start)
			Breakpoint::SetTfBreakPoint(hThread);
			//返回已处理
			g_wp.bpType = 1;
			g_addr = addr;
			g_wp.tfFlag = 1;
			//tfFlag = 1;
			return DBG_CONTINUE;
		}
	}

	//未处理的异常
	return DBG_EXCEPTION_NOT_HANDLED;
}

void Breakpoint::SetTfBreakPoint(HANDLE hThread)
{
	//原理：CPU的标志寄存器中存在TF标志位，在CPU执行完一条指令之后
	//会检测TF位是否为1， 如果为1，CPU会主动触发一个异常。

	//获取当前线程的上下文，其中包括EFLAGS寄存器
	CONTEXT context{ CONTEXT_ALL };
	GetThreadContext(hThread, &context);

	//将TF位置1
	context.EFlags |= 0x00000100;

	SetThreadContext(hThread, &context);
}

void Breakpoint::SetHwBreakPoint(HANDLE hThread, LPVOID addr, int type, int len)
{
	//原理：由CPU提供的Dr系列寄存器做多可以设置4个硬件断点，
	//断点的位置由Dr0~Dr3去保存，相应的Dr7中的Ln表示对应的
	//断点是否有效,Dr7寄存器还提供了RW\LEN标志位,用于设置
	//断点的类型,
	//RW:0(执行断点,它的len也必须为0）， 1(写) 3(读写）
	//len:0(1字节), 1（2字节), 2（8字节), 3（4字节)

	if (len == 1)
		addr = (LPVOID)((DWORD)addr - (DWORD)addr % 2);
	else if (len == 3)
		addr = (LPVOID)((DWORD)addr - (DWORD)addr % 4);
	CONTEXT context{ CONTEXT_ALL };
	GetThreadContext(hThread, &context);
	bp hwbp;
	hwbp.addr = addr;
	PR7 Dr7 = (PR7)&context.Dr7;
	//Dr0起作用
	if (Dr7->L0 == 0)
	{
		Dr7->L0 = 1;
		Dr7->RW0 = type;
		Dr7->LEN0 = len;
		context.Dr0 = (DWORD)addr;
	}
	//Dr1起作用
	else if (Dr7->L1 == 0)
	{
		Dr7->L1 = 1;
		Dr7->RW1 = type;
		Dr7->LEN1 = len;
		context.Dr1 = (DWORD)addr;
	}
	//Dr2起作用
	else if (Dr7->L2 == 0)
	{
		Dr7->L2 = 1;
		Dr7->RW2 = type;
		Dr7->LEN2 = len;
		context.Dr2 = (DWORD)addr;
	}
	//Dr3起作用
	else if (Dr7->L3 == 0)
	{
		Dr7->L3 = 1;
		Dr7->RW3 = type;
		Dr7->LEN3 = len;
		context.Dr3 = (DWORD)addr;
	}
	else
	{
		printf("硬件断点已满，不能继续存储!");
	}
	//设置寄存器
	g_wp.bpType = 0;
	g_wp.type = type;
	g_wp.len = len;
	g_bp.push_back(hwbp);
	SetThreadContext(hThread, &context);
}

void Breakpoint::FixHwBreakPoint(HANDLE hThread, HANDLE hProcess, LPVOID& addr)
{
	//原理：如果是硬件断点断下来了，在触发时，调试寄存器
	//Dr6的低4位中相应的标志位就会置为1
	//第0位置1就代表Dr0中的断点断下来了，然后依次向后推
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
	//		int len = Capstone::GetInstrLen(hProcess, g_bp[i].addr, 10, code);//code无用，此函数求指令长度
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
				//断到想断的地方后，需要在设置一次tf断点以方便设置内存属性以实现永久断点
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
				//断到想断的地方后，需要在设置一次tf断点以方便设置内存属性以实现永久断点
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
