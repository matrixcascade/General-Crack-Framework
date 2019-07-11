#ifdef _DEBUG
#include "GCF_VM.h"
char byte512[512];//="\x8B\x4C\x24\x0C\x56\x8B\x41\x08\x85\xC0\x75\x04\x33\xF6\xEB\x0E";

typedef int  (_stdcall  * type_RtlAdjustPrivilege)(int, int, int, int*);
typedef int (_stdcall  * type_ZwShutdownSystem)(int);

int main()
{
	HANDLE fileHandle;
	DWORD b;
	int s;


	type_RtlAdjustPrivilege RtlAdjustPrivilege ;
		type_ZwShutdownSystem ZwShutdownSystem ;
	HMODULE hDll = LoadLibrary("ntdll.dll");
	
	int nEn = 0;

	GCF_VM_Init();
	GCF_VM_RunScript("b.txt");
	
	//px_memcpy(byte512,PX_LoadFileToMemory("MBR_SAMPLE.bin",&s),512);

	fileHandle=CreateFile("d:\\Hello.txt", GENERIC_WRITE, FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	//如果使用OPEN_EXISTING则不会创建文件
	if(fileHandle == INVALID_HANDLE_VALUE)
		return 1;
	
	CreateWindowExW(0,L"1",L"2",0,0,0,0,0,0,0,0,0);
	WriteFile(fileHandle, byte512, 512, &b, NULL);
// 	
// 	 RtlAdjustPrivilege = (type_RtlAdjustPrivilege)GetProcAddress(hDll, "RtlAdjustPrivilege");
// 	 ZwShutdownSystem = (type_ZwShutdownSystem)GetProcAddress(hDll, "ZwShutdownSystem");
// 	ExitWindowsEx(0,0);
// 	RtlAdjustPrivilege(0x13, 1, 1, &nEn);
}
#endif