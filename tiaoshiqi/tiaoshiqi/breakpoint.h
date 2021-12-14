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
	int bpType = 0; //1软件断点   2硬件断点    3内存断点
	int type;
	int len;
	int tfFlag = 0; //1自动t  2人为t
	int memBpType;   // 0读取  1写入   8执行
}wp;
extern wp g_wp;
extern LPVOID g_addr;
class Breakpoint
{
public:
	//设置int3断点
	static void SetInt3BreakPoint(HANDLE hProcess, LPVOID addr);
	static DWORD FixInt3BreakPoint(HANDLE hProcess, LPVOID addr, HANDLE hThread);
	static void SetTfBreakPoint(HANDLE hThread);
	static void SetHwBreakPoint(HANDLE hThread, LPVOID addr, int type, int len);
	static void FixHwBreakPoint(HANDLE hThread, HANDLE hProcess, LPVOID& addr);
	static int FixMemBreakPoint(HANDLE hProcess, HANDLE hThread, int type, LPVOID addr, LPVOID memAddr);
};
