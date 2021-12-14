#include<vector>
#include<windows.h>
using std::vector;
typedef struct BREAKPOINTER
{
	LPVOID addr;
	BYTE oldBytes;
	DWORD oldProtect;
	BOOL isMemBp;
	int memBpType;
}bp;
extern vector<bp> g_bp;
extern int tfFlag;
typedef struct whichPoint
{
	int bpType = 0; //1����ϵ�   2Ӳ���ϵ�    3�ڴ�ϵ�
	int type;
	int len;
	int tfFlag = 0; //1�Զ�t  2��Ϊt
	int memBpType;   // 0��ȡ  1д��   8ִ��
}wp;
extern wp g_wp;
extern LPVOID g_addr;
class Breakpoint
{
public:
	//����int3�ϵ�
	static void SetInt3BreakPoint(HANDLE hProcess, LPVOID addr);
	static DWORD FixInt3BreakPoint(HANDLE hProcess, LPVOID addr, HANDLE hThread);
	static void SetTfBreakPoint(HANDLE hThread);
	static void SetHwBreakPoint(HANDLE hThread, LPVOID addr, int type, int len);
	static void FixHwBreakPoint(HANDLE hThread, HANDLE hProcess, LPVOID& addr);
	static int FixMemBreakPoint(HANDLE hProcess, HANDLE hThread, int type, LPVOID addr, LPVOID memAddr);
};
