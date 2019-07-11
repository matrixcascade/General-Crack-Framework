#include "GCF_VM.h"


#define GCF_SCRIPT_DEFAULT_STACK 65536
#define GCF_TRIGGER_TABLE_COUNT 256
#define GCF_TRIGGER_FIX_SIZE (32)
#define GCF_RESOURCE_SIZE 1024*1024*2
#define GCF_PARAM_MAX_COUNT 16
//////////////////////////////////////////////////////////////////////////
//resource
//////////////////////////////////////////////////////////////////////////
px_byte GCF_Resource[GCF_RESOURCE_SIZE]="GENERALCRACKFRAMEWORKRESOURCE";
//////////////////////////////////////////////////////////////////////////
typedef struct
{
	px_dword edi;
	px_dword esi;
	px_dword ebp;
	px_dword esp;
	px_dword ebx;
	px_dword edx;
	px_dword ecx;
	px_dword eax;
}GCF_BP_REGS;

typedef union
{
	px_byte  _byte;
	px_word  _word;
	px_dword _dword;
	px_void *_pointer;
}GCF_API_PARAM;

typedef struct
{
	px_char Name[32];
	px_char Param[256];
}GCF_PARAM;

typedef struct  
{
	GCF_PARAM param[GCF_PARAM_MAX_COUNT];
	px_dword size;
	px_byte image[1];
}GCF_RESOURCE_HEADER;


#pragma pack (1)
/*
pushad
pushad  //register table
push addr
call GCF_HookFunction_Process
add sp,0x28
popad
sourcecode
push addr
ret
*/
typedef struct
{
	px_byte _1_pushad;
	px_byte _2_pushad;
	px_byte _3_push;
	px_dword _3_addr;
	px_byte _4_mov_eax;
	px_dword _4_addr;
	px_word _5_call_eax;
	px_dword _6_add_sp_24h;
	px_byte _7_popad;
	px_char User_code[GCF_TRIGGER_FIX_SIZE+32];
}GCF_BP_SHELLCODE;

typedef struct
{
	px_byte _1_push_eax;
	px_byte _2_mov_eax;
	px_dword _2_addr;
	px_byte _3_add_eax;
	px_dword _3_size;
	px_byte _4_push_eax;
	px_dword _5_mov_eax_esp_4;
	px_byte _6_ret;
	px_word _6_04h;

}GCF_BP_SHELLCODE_END;

#pragma pack ()

typedef struct
{
	GCF_BP_REGS regs;
	px_dword Addr;
}GCF_TRIGGER_PARAMS;

typedef enum
{
	GCF_API_PARAM_TYPE_CONST,
	GCF_API_PARAM_TYPE_POINTER,
}GCF_API_PARAM_TYPE;

typedef struct
{
	px_byte  origin[GCF_TRIGGER_FIX_SIZE];
	px_dword address;
	px_int size;
	px_char  scriptFunction[PX_SCRIPT_FUNCTION_NAME_MAX_LEN];
	GCF_BP_SHELLCODE shellcode;
}GCF_BP_TABLE;

static GCF_API_PARAM gcf_api_param[GCF_API_PARAMS_COUNT];
static px_int gcf_api_currentCount;
static GCF_API_PARAM_TYPE gcf_api_param_type[GCF_API_PARAMS_COUNT];

static px_memorypool  GCF_Memorypool;
static px_byte GCF_VM_Runtime[GCF_VM_RUNTIME_MEMORY];
static PX_SCRIPT_LIBRARY GCF_Scriptlibrary;
static PX_ScriptVM_Instance GCF_VMInstance;

static GCF_BP_TABLE GCF_BPTable[GCF_TRIGGER_TABLE_COUNT];
static CRITICAL_SECTION GCF_cs;
//////////////////////////////////////////////////////////////////////////
//hook proc
#define  GCF_Message printf
// px_void GCF_Message(px_char fmr[],...)
// {
// 	printf(fmr);
// }

px_int GCF_API_CALL(FARPROC dll_proc)
{
	px_int v_ret;
	px_dword *p=(px_dword *)gcf_api_param;
	
	_asm
	{
		mov ecx,gcf_api_currentCount
_PARAM_PUSH:
		cmp ecx,0
		je _PARAM_END 
		dec ecx
		mov eax,dword ptr [p]
		mov eax,dword ptr [eax+4*ecx]
		push eax
		jmp _PARAM_PUSH
_PARAM_END:
		call dll_proc
		mov v_ret,eax
	}
	return v_ret;
}


px_bool GCF_API_PARAMS(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	if (gcf_api_currentCount>=GCF_API_PARAMS_COUNT||gcf_api_currentCount<0)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	gcf_api_currentCount=PX_ScriptVM_STACK(Ins,0)._int;
	return PX_TRUE;
}
px_bool GCF_API_PARAM_BYTE(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int param[2];
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	param[0]=PX_ScriptVM_STACK(Ins,0)._int;

	if (param[0]>=GCF_API_PARAMS_COUNT||param[0]<0)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	param[1]=PX_ScriptVM_STACK(Ins,1)._int;

	if (gcf_api_param_type[param[0]]==GCF_API_PARAM_TYPE_POINTER)
	{
		MP_Free(&GCF_Memorypool,gcf_api_param[param[0]]._pointer);
		gcf_api_param_type[param[0]]=GCF_API_PARAM_TYPE_CONST;
	}
	gcf_api_param[param[0]]._dword=(px_byte)param[1];
	return PX_TRUE;
}
px_bool GCF_API_PARAM_WORD(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int param[2];
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	param[0]=PX_ScriptVM_STACK(Ins,0)._int;

	if (param[0]>=GCF_API_PARAMS_COUNT||param[0]<0)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	param[1]=PX_ScriptVM_STACK(Ins,1)._int;

	if (gcf_api_param_type[param[0]]==GCF_API_PARAM_TYPE_POINTER)
	{
		MP_Free(&GCF_Memorypool,gcf_api_param[param[0]]._pointer);
		gcf_api_param_type[param[0]]=GCF_API_PARAM_TYPE_CONST;
	}
	if (param[0]>=GCF_API_PARAMS_COUNT||param[0]<0)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	gcf_api_param[param[0]]._dword=(px_word)param[1];
	return PX_TRUE;
}
px_bool GCF_API_PARAM_DWORD(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int param[2];
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	param[0]=PX_ScriptVM_STACK(Ins,0)._int;

	if (param[0]>=GCF_API_PARAMS_COUNT||param[0]<0)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	param[1]=PX_ScriptVM_STACK(Ins,1)._int;

	if (gcf_api_param_type[param[0]]==GCF_API_PARAM_TYPE_POINTER)
	{
		MP_Free(&GCF_Memorypool,gcf_api_param[param[0]]._pointer);
		gcf_api_param_type[param[0]]=GCF_API_PARAM_TYPE_CONST;
	}
	
	gcf_api_param[param[0]]._dword=(px_dword)param[1];
	return PX_TRUE;
}
px_bool GCF_API_PARAM_STRING(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int index,len;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	index=PX_ScriptVM_STACK(Ins,0)._int;
	
	if (index>=GCF_API_PARAMS_COUNT||index<0)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_STRING)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	if (gcf_api_param_type[index]==GCF_API_PARAM_TYPE_POINTER)
	{
		MP_Free(&GCF_Memorypool,gcf_api_param[index]._pointer);
	}
	gcf_api_param_type[index]=GCF_API_PARAM_TYPE_POINTER;
	len=px_strlen(PX_ScriptVM_STACK(Ins,1)._string.buffer)+1;
	gcf_api_param[index]._pointer=MP_Malloc(&GCF_Memorypool,len);
	px_memcpy(gcf_api_param[index]._pointer,PX_ScriptVM_STACK(Ins,1)._string.buffer,len);
	return PX_TRUE;
}
px_bool GCF_API_PARAM_MEMORY(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int index;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	index=PX_ScriptVM_STACK(Ins,0)._int;
	if (index>=GCF_API_PARAMS_COUNT||index<0)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_MEMORY)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	if (PX_ScriptVM_STACK(Ins,2).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	if (gcf_api_param_type[index]==GCF_API_PARAM_TYPE_POINTER)
	{
		MP_Free(&GCF_Memorypool,gcf_api_param[index]._pointer);
	}
	gcf_api_param_type[index]=GCF_API_PARAM_TYPE_POINTER;
	gcf_api_param[index]._pointer=(px_void *)MP_Malloc(&GCF_Memorypool,PX_ScriptVM_STACK(Ins,2)._int);

	return PX_TRUE;
}
px_bool GCF_API_GET_PARAM_BYTE(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int offset;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	offset=PX_ScriptVM_STACK(Ins,0)._int;

	if (offset>=GCF_API_PARAMS_COUNT||offset<0)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(gcf_api_param[offset]._byte));
	return PX_TRUE;
}
px_bool GCF_API_GET_PARAM_WORD(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int offset;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	offset=PX_ScriptVM_STACK(Ins,0)._int;

	if (offset>=GCF_API_PARAMS_COUNT||offset<0)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(gcf_api_param[offset]._word));
	return PX_TRUE;
}
px_bool GCF_API_GET_PARAM_DWORD(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int offset;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	offset=PX_ScriptVM_STACK(Ins,0)._int;

	if (offset>=GCF_API_PARAMS_COUNT||offset<0)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(gcf_api_param[offset]._dword));
	return PX_TRUE;
}
px_bool GCF_API_GET_PARAM_STRING(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int offset;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	offset=PX_ScriptVM_STACK(Ins,0)._int;

	if (offset>=GCF_API_PARAMS_COUNT||offset<0)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	if(gcf_api_param_type[offset]==GCF_API_PARAM_TYPE_POINTER)
	PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_const_string((px_char *)gcf_api_param[offset]._pointer));
	else
	PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_const_string(""));

	return PX_TRUE;
}
px_bool GCF_API_GET_PARAM_MEMORY(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int offset,size;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	offset=PX_ScriptVM_STACK(Ins,0)._int;


	if (offset>=GCF_API_PARAMS_COUNT||offset<0)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	size=PX_ScriptVM_STACK(Ins,1)._int;

	if(gcf_api_param_type[offset]==GCF_API_PARAM_TYPE_POINTER)
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_const_memory((px_byte *)gcf_api_param[offset]._pointer,size));
	else
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_const_memory((px_byte *)"",1));

	return PX_TRUE;
}
px_bool GCF_API_RUN(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	HMODULE dllHandle;
	FARPROC dll_proc;
	px_char *dll,*proc;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_STRING)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	dll=PX_ScriptVM_STACK(Ins,0)._string.buffer;

	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_STRING)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	proc=PX_ScriptVM_STACK(Ins,1)._string.buffer;

	dllHandle=LoadLibrary(dll);
	if (dllHandle==INVALID_HANDLE_VALUE)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	dll_proc=GetProcAddress(dllHandle,proc);

	if (dll_proc==PX_NULL)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(GCF_API_CALL(dll_proc)));
	return PX_TRUE;
}


px_void GCF_TRIGGER_Process(px_dword bp_addr,GCF_BP_REGS regs)
{
	px_int i;
	GCF_TRIGGER_PARAMS params;
	params.Addr=bp_addr;
	params.regs=regs;
	params.regs.esp+=32;
	for (i=0;i<GCF_TRIGGER_TABLE_COUNT;i++)
	{
		if (GCF_BPTable[i].address==bp_addr)
		{
			EnterCriticalSection(&GCF_cs);
			if(!PX_ScriptVM_InstanceRunFunction(&GCF_VMInstance,&params,GCF_BPTable[i].scriptFunction,0))
			{
				GCF_Message("Not Trigger function %s",GCF_BPTable[i].scriptFunction);
			}
			LeaveCriticalSection(&GCF_cs);
			break;
		}
	}
}

px_int GCF_TRIGGER_ShellCode(px_dword bp_addr,px_int size,px_char callback[])
{
	px_int i;
	DWORD oldProtect;
	GCF_BP_SHELLCODE shellcode;
	GCF_BP_SHELLCODE_END *pEndShellcode;
	//Search map table
	for (i=0;i<GCF_TRIGGER_TABLE_COUNT;i++)
	{
		if (GCF_BPTable[i].address==(DWORD)bp_addr)
		{
			//already existed.
			return -1;
		}
	}
	//add new map
	for (i=0;i<GCF_TRIGGER_TABLE_COUNT;i++)
	{
		if (GCF_BPTable[i].address==0)
		{
			GCF_BPTable[i].address=(DWORD)bp_addr;
			VirtualProtect((LPVOID)bp_addr,size,PAGE_EXECUTE_READWRITE ,&oldProtect);
			px_memcpy(GCF_BPTable[i].origin,(px_void *)bp_addr,size);
			px_strcpy(GCF_BPTable[i].scriptFunction,callback,sizeof(GCF_BPTable[i].scriptFunction));
			GCF_BPTable[i].size=size;

			//Shell code
			shellcode._1_pushad=0x60;
			shellcode._2_pushad=0x60;
			shellcode._3_push=0x68;
			shellcode._3_addr=bp_addr;
			shellcode._4_mov_eax=0xb8;
			shellcode._4_addr=(px_dword)GCF_TRIGGER_Process;
			shellcode._5_call_eax=0xd0ff;
			shellcode._6_add_sp_24h=0x24c48366;
			shellcode._7_popad=0x61;
			px_memcpy(shellcode.User_code,(px_void *)GCF_BPTable[i].origin,size);
			pEndShellcode=(GCF_BP_SHELLCODE_END *)(shellcode.User_code+size);
			pEndShellcode->_1_push_eax=0x50;
			pEndShellcode->_2_mov_eax=0xB8;
			pEndShellcode->_2_addr=bp_addr;
			pEndShellcode->_3_add_eax=0x05;
			pEndShellcode->_3_size=size;
			pEndShellcode->_4_push_eax=0x50;
			pEndShellcode->_5_mov_eax_esp_4=0x0424448b;
			pEndShellcode->_6_ret=0xC2;
			pEndShellcode->_6_04h=0x0004;
			GCF_BPTable[i].shellcode=shellcode;
			VirtualProtect((LPVOID)&GCF_BPTable[i].shellcode,sizeof(GCF_BPTable[i].shellcode),PAGE_EXECUTE_READWRITE,&oldProtect);
			return i;
			break;
		}
	}

	return -1;
}


px_bool GCF_TRIGGER_BREAKPOINT(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	#pragma pack (1)
	typedef struct
	{
		px_byte _jmp;
		px_dword addr;
	}jmp_addr;
	#pragma pack ()


	DWORD old;
	SIZE_T _w;
	int BreakAddr,codeAddr,size,idx,call_addr;
	px_char* call_back;
	jmp_addr _jp;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	BreakAddr=PX_ScriptVM_STACK(Ins,0)._int;

	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	codeAddr=PX_ScriptVM_STACK(Ins,1)._int;

	if (PX_ScriptVM_STACK(Ins,2).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	size=PX_ScriptVM_STACK(Ins,2)._int;

	if (PX_ScriptVM_STACK(Ins,3).type!=PX_SCRIPTVM_VARIABLE_TYPE_STRING)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	call_back=PX_ScriptVM_STACK(Ins,3)._string.buffer;

	idx=GCF_TRIGGER_ShellCode(BreakAddr,size,call_back);
	if (idx==-1)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	call_addr=(px_dword)&(GCF_BPTable[idx].shellcode);
	//Code AddrModify
	//_asm{jmp addr}
	_jp._jmp=0xe9;
	_jp.addr=call_addr-codeAddr-5;
	VirtualProtect((LPVOID)codeAddr,sizeof(_jp),PAGE_EXECUTE_READWRITE,&old);
	if(WriteProcessMemory(GetCurrentProcess(),(LPVOID)codeAddr,&_jp,sizeof(_jp),&_w))
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(1));
		return PX_TRUE;
	}
	else
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_FALSE;
	}
}

px_bool GCF_TRIGGER_BREAKPOINTEX(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
#pragma pack (1)
	typedef struct
	{
		px_byte mov_eax;
		px_dword addr;
		px_word jmp_eax;
	}jmp_addr;
#pragma pack ()


	DWORD old;
	SIZE_T _w;
	int BreakAddr,codeAddr,size,idx,call_addr;
	px_char* call_back;
	jmp_addr _jp;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	BreakAddr=PX_ScriptVM_STACK(Ins,0)._int;

	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	codeAddr=PX_ScriptVM_STACK(Ins,1)._int;

	if (PX_ScriptVM_STACK(Ins,2).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	size=PX_ScriptVM_STACK(Ins,2)._int;

	if (PX_ScriptVM_STACK(Ins,3).type!=PX_SCRIPTVM_VARIABLE_TYPE_STRING)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	call_back=PX_ScriptVM_STACK(Ins,3)._string.buffer;

	idx=GCF_TRIGGER_ShellCode(BreakAddr,size,call_back);
	if (idx==-1)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	call_addr=(px_dword)&(GCF_BPTable[idx].shellcode);
	//Code AddrModify
	//_asm{jmp addr}
	_jp.mov_eax=0xB8;
	_jp.addr=call_addr;
	_jp.jmp_eax=0xE0FF;

	VirtualProtect((LPVOID)codeAddr,sizeof(_jp),PAGE_EXECUTE_READWRITE,&old);
	if(WriteProcessMemory(GetCurrentProcess(),(LPVOID)codeAddr,&_jp,sizeof(_jp),&_w))
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(1));
		return PX_TRUE;
	}
	else
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_FALSE;
	}
}

px_bool GCF_TRIGGER_CANCEL(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int i,addr;
	SIZE_T _w;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	addr=PX_ScriptVM_STACK(Ins,0)._int;
	for (i=0;i<GCF_TRIGGER_TABLE_COUNT;i++)
	{
		if (GCF_BPTable[i].address==addr)
		{
			if(WriteProcessMemory(GetCurrentProcess(),(LPVOID)addr,&GCF_BPTable[i].origin,GCF_BPTable[i].size,&_w))
			{
				PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(1));
				GCF_BPTable[i].address=0;
				return PX_TRUE;
			}
			else
			{
				PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
				return PX_FALSE;
			}
		}
	}
	return PX_TRUE;
}


px_bool GCF_TRIGGER_SHELLCODE(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int i,addr;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	addr=PX_ScriptVM_STACK(Ins,0)._int;
	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_MEMORY||PX_ScriptVM_STACK(Ins,1)._memory.usedsize>=GCF_TRIGGER_FIX_SIZE)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	for (i=0;i<GCF_TRIGGER_TABLE_COUNT;i++)
	{
		if (GCF_BPTable[i].address==addr)
		{
			px_memcpy(GCF_BPTable[i].shellcode.User_code,PX_ScriptVM_STACK(Ins,1)._memory.buffer,PX_ScriptVM_STACK(Ins,1)._memory.usedsize);
			break;
		}
	}
	return PX_TRUE;
}

px_bool GCF_TRIGGER_CURRENTSHELLCODE(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int i,addr;
	GCF_TRIGGER_PARAMS *pParam=(GCF_TRIGGER_PARAMS *)bp_param;
	addr=pParam->Addr;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_MEMORY||PX_ScriptVM_STACK(Ins,0)._memory.usedsize>=GCF_TRIGGER_FIX_SIZE)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	for (i=0;i<GCF_TRIGGER_TABLE_COUNT;i++)
	{
		if (GCF_BPTable[i].address==addr)
		{
			px_memcpy(GCF_BPTable[i].shellcode.User_code,PX_ScriptVM_STACK(Ins,0)._memory.buffer,PX_ScriptVM_STACK(Ins,0)._memory.usedsize);
			break;
		}
	}
	return PX_TRUE;
}



px_bool GCF_MEMORY_ALLOC(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	DWORD old;
	px_byte *buffer;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_MEMORY)
	{
		return PX_FALSE;
	}

	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		return PX_FALSE;
	}
	if(PX_ScriptVM_STACK(Ins,0)._memory.usedsize<=PX_ScriptVM_STACK(Ins,1)._int)
	{
		buffer=(px_byte *)malloc(PX_ScriptVM_STACK(Ins,1)._int);
		VirtualProtect((LPVOID)buffer,PX_ScriptVM_STACK(Ins,1)._int,PAGE_EXECUTE_READWRITE,&old);
		px_memset(buffer,0,PX_ScriptVM_STACK(Ins,1)._int);
		px_memcpy(buffer,PX_ScriptVM_STACK(Ins,0)._memory.buffer,PX_ScriptVM_STACK(Ins,0)._memory.usedsize);
	}
	else
	{
		buffer=(px_byte *)malloc(PX_ScriptVM_STACK(Ins,0)._memory.usedsize);
		VirtualProtect((LPVOID)buffer,PX_ScriptVM_STACK(Ins,0)._memory.usedsize,PAGE_EXECUTE_READWRITE,&old);
		px_memset(buffer,0,PX_ScriptVM_STACK(Ins,0)._memory.usedsize);
		px_memcpy(buffer,PX_ScriptVM_STACK(Ins,0)._memory.buffer,PX_ScriptVM_STACK(Ins,0)._memory.usedsize);
	}
	
	PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int((px_int)buffer));

	return PX_TRUE;
}
px_bool GCF_MEMORY_FREE(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{

	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	
	free((px_void *)PX_ScriptVM_STACK(Ins,0)._dword);

	return PX_TRUE;
}
px_bool GCF_MEMORY_READ_BYTE(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int addr,i_addr;
	SIZE_T r;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	addr=PX_ScriptVM_STACK(Ins,0)._dword;
	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	i_addr=PX_ScriptVM_STACK(Ins,1)._dword;
	if (Ins->_mem[i_addr].type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	Ins->_mem[i_addr]._dword=0;
	if (ReadProcessMemory(GetCurrentProcess(),(LPVOID)addr,&Ins->_mem[i_addr]._byte,1,&r))
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(1));
	}
	else
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
	}
	return PX_TRUE;
}
px_bool GCF_MEMORY_READ_WORD(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int addr,i_addr;
	SIZE_T r;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	addr=PX_ScriptVM_STACK(Ins,0)._dword;
	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	i_addr=PX_ScriptVM_STACK(Ins,1)._dword;
	if (Ins->_mem[i_addr].type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	Ins->_mem[i_addr]._dword=0;
	if (ReadProcessMemory(GetCurrentProcess(),(LPVOID)addr,&Ins->_mem[i_addr]._word,2,&r))
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(1));
	}
	else
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
	}
	return PX_TRUE;
}
px_bool GCF_MEMORY_READ_DWORD(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int addr,i_addr;
	SIZE_T r;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	addr=PX_ScriptVM_STACK(Ins,0)._dword;
	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	i_addr=PX_ScriptVM_STACK(Ins,1)._dword;
	if (Ins->_mem[i_addr].type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	Ins->_mem[i_addr]._dword=0;
	if (ReadProcessMemory(GetCurrentProcess(),(LPVOID)addr,&Ins->_mem[i_addr]._dword,4,&r))
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(1));
	}
	else
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
	}
	return PX_TRUE;
}
px_bool GCF_MEMORY_READ(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	SIZE_T rs;
	px_int Atom_ptr,addr,size;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	addr=PX_ScriptVM_STACK(Ins,0)._dword;
	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	size=PX_ScriptVM_STACK(Ins,1)._dword;
	if (PX_ScriptVM_STACK(Ins,2).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	Atom_ptr=PX_ScriptVM_STACK(Ins,2)._int;

	if (Ins->_mem[Atom_ptr].type!=PX_SCRIPTVM_VARIABLE_TYPE_MEMORY)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	if(!PX_MemoryResize(&Ins->_mem[Atom_ptr]._memory,size))
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	ReadProcessMemory(GetCurrentProcess(),(LPVOID)addr,Ins->_mem[Atom_ptr]._memory.buffer,size,&rs);
	Ins->_mem[Atom_ptr]._memory.usedsize=size;
	if (rs!=size)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
	}
	else
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(1));
	}

	return PX_TRUE;
}
px_bool GCF_MEMORY_WRITE_BYTE(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int addr,_val;
	SIZE_T w;
	DWORD old;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	addr=PX_ScriptVM_STACK(Ins,0)._dword;
	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	_val=PX_ScriptVM_STACK(Ins,1)._dword;

	if(VirtualProtect((LPVOID)addr,4,PAGE_EXECUTE_READWRITE,&old))
	{
		if (WriteProcessMemory(GetCurrentProcess(),(LPVOID)addr,&_val,1,&w))
		{
			PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(1));
			return PX_TRUE;
		}
	}
	PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
	return PX_TRUE;
}
px_bool GCF_MEMORY_WRITE_WORD(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int addr,_val;
	SIZE_T w;
	DWORD old;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	addr=PX_ScriptVM_STACK(Ins,0)._dword;
	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	_val=PX_ScriptVM_STACK(Ins,1)._dword;

	if(VirtualProtect((LPVOID)addr,4,PAGE_EXECUTE_READWRITE,&old))
	{
		if (WriteProcessMemory(GetCurrentProcess(),(LPVOID)addr,&_val,2,&w))
		{
			PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(1));
			return PX_TRUE;
		}
	}
	PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
	return PX_TRUE;
}
px_bool GCF_MEMORY_WRITE_DWORD(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int addr,_val;
	SIZE_T w;
	DWORD old;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	addr=PX_ScriptVM_STACK(Ins,0)._dword;
	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	_val=PX_ScriptVM_STACK(Ins,1)._dword;
	if(VirtualProtect((LPVOID)addr,4,PAGE_EXECUTE_READWRITE,&old))
	{
		if (WriteProcessMemory(GetCurrentProcess(),(LPVOID)addr,&_val,4,&w))
		{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(1));
		return PX_TRUE;
		}
	}
	PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
	return PX_TRUE;
}
px_bool GCF_MEMORY_WRITE(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	SIZE_T rs=0;
	px_int addr,size;
	px_byte *pBuffer;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	addr=PX_ScriptVM_STACK(Ins,0)._dword;
	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	size=PX_ScriptVM_STACK(Ins,1)._dword;

	if (PX_ScriptVM_STACK(Ins,2).type!=PX_SCRIPTVM_VARIABLE_TYPE_MEMORY)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	pBuffer=PX_ScriptVM_STACK(Ins,2)._memory.buffer;

	if ((px_dword)size>(px_dword)PX_ScriptVM_STACK(Ins,2)._memory.usedsize)
	{
		size=PX_ScriptVM_STACK(Ins,2)._memory.usedsize;
	}
	WriteProcessMemory(GetCurrentProcess(),(LPVOID)addr,pBuffer,size,&rs);

	if (rs!=size)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
	}
	else
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(1));
	}

	return PX_TRUE;
}

px_bool GCF_STACK_BYTE(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	GCF_TRIGGER_PARAMS *pParam=(GCF_TRIGGER_PARAMS *)bp_param;
	px_int offset;
	SIZE_T actuallyRead;
	px_byte _byte;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	offset=PX_ScriptVM_STACK(Ins,0)._int;

	if (ReadProcessMemory(GetCurrentProcess(),(LPVOID)(pParam->regs.esp+offset),&_byte,1,&actuallyRead))
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(_byte));
	}
	else
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
	}
	return PX_TRUE;
}
px_bool GCF_STACK_WORD(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int offset;
	SIZE_T actuallyRead;
	px_word _word;
	GCF_TRIGGER_PARAMS *pParam=(GCF_TRIGGER_PARAMS *)bp_param;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	offset=PX_ScriptVM_STACK(Ins,0)._int;

	if (ReadProcessMemory(GetCurrentProcess(),(LPVOID)(pParam->regs.esp+offset),&_word,2,&actuallyRead))
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(_word));
	}
	else
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
	}
	return PX_TRUE;
}
px_bool GCF_STACK_DWORD(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int offset;
	SIZE_T actuallyRead;
	px_dword _dword;
	GCF_TRIGGER_PARAMS *pParam=(GCF_TRIGGER_PARAMS *)bp_param;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	offset=PX_ScriptVM_STACK(Ins,0)._int;

	if (ReadProcessMemory(GetCurrentProcess(),(LPVOID)(pParam->regs.esp+offset),&_dword,4,&actuallyRead))
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(_dword));
	}
	else
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
	}
	return PX_TRUE;
}
px_bool GCF_STACK_STRING(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int offset,str_index;
	SIZE_T actuallyRead;
	px_dword string_ptr;
	px_char charactor;
	px_string readString;
	GCF_TRIGGER_PARAMS *pParam=(GCF_TRIGGER_PARAMS *)bp_param;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	offset=PX_ScriptVM_STACK(Ins,0)._int;

	str_index=PX_ScriptVM_STACK(Ins,1)._int;

	if (Ins->_mem[str_index].type!=PX_SCRIPTVM_VARIABLE_TYPE_STRING)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	string_ptr=*((DWORD *)(pParam->regs.esp+offset));
	offset=0;

	PX_StringInit(&GCF_Memorypool,&readString);

	while (PX_TRUE)
	{
		if (ReadProcessMemory(GetCurrentProcess(),(LPVOID)(string_ptr+offset),&charactor,1,&actuallyRead))
		{
			if(charactor)
			PX_StringCatChar(&readString,charactor);
			else
			{
				PX_StringCopy(&Ins->_mem[str_index]._string,&readString);
				PX_StringFree(&readString);
				PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(1));
				break;
			}
		}
		else
		{
			PX_StringFree(&readString);
			PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
			break;
		}
		offset++;
	}
	
	return PX_TRUE;
}
px_bool GCF_STACK_MEMORY(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int offset,size,mem_index,mem_ptr;
	SIZE_T actuallyRead;
	GCF_TRIGGER_PARAMS *pParam=(GCF_TRIGGER_PARAMS *)bp_param;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	offset=PX_ScriptVM_STACK(Ins,0)._int;

	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	size=PX_ScriptVM_STACK(Ins,1)._int;

	if (PX_ScriptVM_STACK(Ins,2).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	mem_index=PX_ScriptVM_STACK(Ins,2)._int;

	if (Ins->_mem[mem_index].type!=PX_SCRIPTVM_VARIABLE_TYPE_MEMORY)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	mem_ptr=*((DWORD *)(pParam->regs.esp+offset));

	if(!PX_MemoryResize(&Ins->_mem[mem_index]._memory,size))
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	

	if (ReadProcessMemory(GetCurrentProcess(),(LPVOID)(mem_ptr),Ins->_mem[mem_index]._memory.buffer,size,&actuallyRead))
	{
		Ins->_mem[mem_index]._memory.usedsize=size;
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(1));
	}
	else
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
	}


	return PX_TRUE;
}
px_bool GCF_STACK_SET_BYTE(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int offset;
	SIZE_T actuallyWrite;
	px_dword _val;
	GCF_TRIGGER_PARAMS *pParam=(GCF_TRIGGER_PARAMS *)bp_param;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	offset=PX_ScriptVM_STACK(Ins,0)._int;

	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	_val=PX_ScriptVM_STACK(Ins,1)._int;

	if (WriteProcessMemory(GetCurrentProcess(),(LPVOID)(pParam->regs.esp+offset),&_val,1,&actuallyWrite))
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(1));
	}
	else
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
	}
	return PX_TRUE;
}
px_bool GCF_STACK_SET_WORD(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int offset;
	SIZE_T actuallyWrite;
	px_dword _val;
	GCF_TRIGGER_PARAMS *pParam=(GCF_TRIGGER_PARAMS *)bp_param;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	offset=PX_ScriptVM_STACK(Ins,0)._int;

	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	_val=PX_ScriptVM_STACK(Ins,1)._int;

	if (WriteProcessMemory(GetCurrentProcess(),(LPVOID)(pParam->regs.esp+offset),&_val,2,&actuallyWrite))
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(1));
	}
	else
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
	}
	return PX_TRUE;
}
px_bool GCF_STACK_SET_DWORD(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int offset;
	SIZE_T actuallyWrite;
	px_dword _val;
	GCF_TRIGGER_PARAMS *pParam=(GCF_TRIGGER_PARAMS *)bp_param;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	offset=PX_ScriptVM_STACK(Ins,0)._int;

	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	_val=PX_ScriptVM_STACK(Ins,1)._int;

	if (WriteProcessMemory(GetCurrentProcess(),(LPVOID)(pParam->regs.esp+offset),&_val,4,&actuallyWrite))
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(1));
	}
	else
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
	}
	return PX_TRUE;
}

#define GCF_IMAGE_SEARCHCACHE_SIZE 1024

px_bool GCF_IMAGE_SEARCH(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_dword startAddr,endAddr;
	px_byte *buffer,*readBuffer=PX_NULL;
	px_uint size,offset,i,cacheSize;
	SIZE_T r_size;

	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	startAddr=PX_ScriptVM_STACK(Ins,0)._int;

	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	endAddr=PX_ScriptVM_STACK(Ins,1)._int;

	if (PX_ScriptVM_STACK(Ins,2).type!=PX_SCRIPTVM_VARIABLE_TYPE_MEMORY)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	buffer=PX_ScriptVM_STACK(Ins,2)._memory.buffer;
	size=PX_ScriptVM_STACK(Ins,2)._memory.usedsize;

	if(size<GCF_IMAGE_SEARCHCACHE_SIZE)
	{
		cacheSize=GCF_IMAGE_SEARCHCACHE_SIZE;
	}
	else
	{
		cacheSize=size;
	}

	readBuffer=(px_byte *)malloc(cacheSize);
	if (!readBuffer)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(-1));


	for (offset=startAddr;offset<=endAddr-size;)
	{
		if (ReadProcessMemory(GetCurrentProcess(),(LPVOID)offset,readBuffer,cacheSize,&r_size))
		{
			for (i=0;i<r_size-size+1;i++)
			{
				if(offset+i>=(px_uint)GCF_Memorypool.StartAddr&&offset+i<=(px_uint)GCF_Memorypool.StartAddr)
				{
					continue;
				}
				if ((memcmp(readBuffer+i,buffer,size)==0)&&(offset+i)!=(px_uint)buffer)
				{
				PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(offset+i));
				free(readBuffer);
				return PX_TRUE;
				}
			}
			offset+=r_size;
		}
		else
		{
			offset+=GCF_IMAGE_SEARCHCACHE_SIZE;
		}
	}

	free(readBuffer);
	PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(-1));
	return PX_TRUE;
}
px_bool GCF_CONTROL_TERMINATE(PX_ScriptVM_Instance *dummy,px_void *bp_param)
{
	exit(0);
}

px_bool GCF_FILE_LOAD(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_char *Path;
	px_byte *buffer;
	px_int index,size;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_STRING)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	Path=PX_ScriptVM_STACK(Ins,0)._string.buffer;

	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	index=PX_ScriptVM_STACK(Ins,1)._int;

	if (Ins->_mem[index].type!=PX_SCRIPTVM_VARIABLE_TYPE_MEMORY)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	if ((buffer=PX_LoadFileToMemory(Path,&size)))
	{
		if(!PX_MemoryResize(&Ins->_mem[index]._memory,size))
		{
			PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		}
		else
		{
			px_memset(Ins->_mem[index]._memory.buffer,0,Ins->_mem[index]._memory.allocsize);
			PX_MemoryCat(&Ins->_mem[index]._memory,buffer,size);
			PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(1));
		}
		
	}
	else
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
	}
	free(buffer);
	return PX_TRUE;
}
px_bool GCF_FILE_SAVE(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_char *Path;
	px_byte *buffer;
	px_int size;
	FILE *pf;
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_STRING)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	Path=PX_ScriptVM_STACK(Ins,0)._string.buffer;

	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_MEMORY)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}

	buffer=PX_ScriptVM_STACK(Ins,1)._memory.buffer;
	size=PX_ScriptVM_STACK(Ins,1)._memory.usedsize;

	pf=fopen(Path,"wb");
	if (pf==PX_NULL)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	fwrite(buffer,1,size,pf);
	fclose(pf);
	PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(1));
	
	return PX_TRUE;
}
px_bool GCF_PARAM_GET(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	px_int i,str_i;
	px_char *buffer;

	GCF_RESOURCE_HEADER *header=(GCF_RESOURCE_HEADER *)GCF_Resource;
	
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_STRING)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	buffer=PX_ScriptVM_STACK(Ins,0)._string.buffer;

	if (PX_ScriptVM_STACK(Ins,1).type!=PX_SCRIPTVM_VARIABLE_TYPE_INT)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	str_i=PX_ScriptVM_STACK(Ins,1)._int;

	if (Ins->_mem[str_i].type!=PX_SCRIPTVM_VARIABLE_TYPE_STRING)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	for (i=0;i<GCF_PARAM_MAX_COUNT;i++)
	{
		if (px_strequ(header->param[i].Name,buffer))
		{
			PX_StringClear(&Ins->_mem[str_i]._string);
			PX_StringCat(&Ins->_mem[str_i]._string,header->param[i].Param);
			PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(1));
			return PX_TRUE;
		}
	}
	PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
	return PX_TRUE;

}
px_bool GCF_CONSOLE_PRINT(PX_ScriptVM_Instance *Ins,px_void *bp_param)
{
	if (PX_ScriptVM_STACK(Ins,0).type!=PX_SCRIPTVM_VARIABLE_TYPE_STRING)
	{
		PX_ScriptVM_RET(Ins,PX_ScriptVM_Variable_int(0));
		return PX_TRUE;
	}
	printf(PX_ScriptVM_STACK(Ins,0)._string.buffer);
	return PX_TRUE;
}
px_byte* PX_LoadFileToMemory(px_char *path,px_int *size)
{
	px_byte *resBuffer;
	px_int fileoft=0;
	FILE *pf=fopen(path,"rb");
	px_int filesize;
	if (!pf)
	{
		*size=0;
		return PX_NULL;
	}
	fseek(pf,0,SEEK_END);
	filesize=ftell(pf);
	fseek(pf,0,SEEK_SET);

	resBuffer=(px_byte *)malloc(filesize+1);

	while (!feof(pf))
	{
		fileoft+=fread(resBuffer+fileoft,1,1024,pf);
	}
	fclose(pf);
	*size=filesize;
	resBuffer[filesize]='\0';
	return resBuffer;
}
px_bool GCF_VM_Init()
{	

	InitializeCriticalSection(&GCF_cs);
	GCF_Memorypool=MP_Create(GCF_VM_Runtime,GCF_VM_RUNTIME_MEMORY);
	return PX_TRUE;
}
px_bool GCF_VM_RunScript(px_char *Crack_Script)
{
	px_int filesize;
	px_byte *pData;
	px_int shellSize;

	px_string GCF_asmcodeString;
	px_memory GCF_shellbin;
	
	
	

	if(!PX_ScriptCompilerInit(&GCF_Scriptlibrary,&GCF_Memorypool))
	{
		goto _ERROR;
	}

	if (!(pData=PX_LoadFileToMemory(Crack_Script,&filesize)))
	{
		goto _ERROR;
	}

	if(!PX_ScriptCompilerLoad(&GCF_Scriptlibrary,(px_char *)pData))
	{
		goto _ERROR;
	}
    
	free(pData);

	PX_MemoryInit(&GCF_Memorypool,&GCF_shellbin);
	PX_StringInit(&GCF_Memorypool,&GCF_asmcodeString);

	if(PX_ScriptCompilerCompile(&GCF_Scriptlibrary,"CrackScript",&GCF_asmcodeString,GCF_SCRIPT_DEFAULT_STACK))
	{
		PX_ScriptAsmOptimization(&GCF_asmcodeString);

		if(!PX_ScriptAsmCompile(&GCF_Memorypool,GCF_asmcodeString.buffer,&GCF_shellbin))
		{
			goto _ERROR;
		}
	}
	else
	{
		goto _ERROR;
	}

	PX_StringFree(&GCF_asmcodeString);
	PX_ScriptCompilerFree(&GCF_Scriptlibrary);

	pData=(px_byte *)MP_Malloc(&GCF_Memorypool,GCF_shellbin.usedsize);
	shellSize=GCF_shellbin.usedsize;
	px_memcpy(pData,GCF_shellbin.buffer,GCF_shellbin.usedsize);

	PX_MemoryFree(&GCF_shellbin);

	return GCF_VM_Run(pData,shellSize);

_ERROR:
	MP_Release(&GCF_Memorypool);
	GCF_Message(PX_GETLOG());
	return PX_FALSE;
}
px_bool GCF_VM_Run(px_byte *Crack_Shell,px_int size)
{
	if(!PX_ScriptVM_InstanceInit(&GCF_VMInstance,&GCF_Memorypool,Crack_Shell,size))
	{
		GCF_Message("Invalid shell.");
		return PX_FALSE;
	}
	MP_Free(&GCF_Memorypool,Crack_Shell);

	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"PRINT",GCF_CONSOLE_PRINT);

	//API CALL
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"API_RUN",GCF_API_RUN);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"API_PARAMS",GCF_API_PARAMS);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"API_PARAM_BYTE",GCF_API_PARAM_BYTE);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"API_PARAM_WORD",GCF_API_PARAM_WORD);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"API_PARAM_DWORD",GCF_API_PARAM_DWORD);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"API_PARAM_STRING",GCF_API_PARAM_STRING);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"API_PARAM_MEMORY",GCF_API_PARAM_MEMORY);

	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"API_GET_PARAM_BYTE",GCF_API_GET_PARAM_BYTE);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"API_GET_PARAM_WORD",GCF_API_GET_PARAM_WORD);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"API_GET_PARAM_DWORD",GCF_API_GET_PARAM_DWORD);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"API_GET_PARAM_STRING",GCF_API_GET_PARAM_STRING);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"API_GET_PARAM_MEMORY",GCF_API_GET_PARAM_MEMORY);

	//TRIGGER
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"TRIGGER_BREAKPOINT",GCF_TRIGGER_BREAKPOINT);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"TRIGGER_BREAKPOINTEX",GCF_TRIGGER_BREAKPOINTEX);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"TRIGGER_CANCEL",GCF_TRIGGER_CANCEL);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"TRIGGER_SHELLCODE",GCF_TRIGGER_SHELLCODE);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"TRIGGER_CURRENTSHELLCODE",GCF_TRIGGER_CURRENTSHELLCODE);
	//MEMORY
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"MEMORY_ALLOC",GCF_MEMORY_ALLOC);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"MEMORY_FREE",GCF_MEMORY_FREE);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"MEMORY_READ_BYTE",GCF_MEMORY_READ_BYTE);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"MEMORY_READ_WORD",GCF_MEMORY_READ_WORD);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"MEMORY_READ_DWORD",GCF_MEMORY_READ_DWORD);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"MEMORY_READ",GCF_MEMORY_READ);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"MEMORY_WRITE_BYTE",GCF_MEMORY_WRITE_BYTE);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"MEMORY_WRITE_WORD",GCF_MEMORY_WRITE_WORD);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"MEMORY_WRITE_DWORD",GCF_MEMORY_WRITE_DWORD);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"MEMORY_WRITE",GCF_MEMORY_WRITE);


	//STACK
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"STACK_BYTE",GCF_STACK_BYTE);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"STACK_WORD",GCF_STACK_WORD);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"STACK_DWORD",GCF_STACK_DWORD);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"STACK_STRING",GCF_STACK_STRING);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"STACK_MEMORY",GCF_STACK_MEMORY);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"STACK_SET_BYTE",GCF_STACK_SET_BYTE);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"STACK_SET_WORD",GCF_STACK_SET_WORD);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"STACK_SET_DWORD",GCF_STACK_SET_DWORD);
	
	//IMAGE
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"IMAGE_SEARCH",GCF_IMAGE_SEARCH);

	//CONTROL
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"CONTROL_TERMINATE",GCF_CONTROL_TERMINATE);

	//FILE
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"FILE_LOAD",GCF_FILE_LOAD);
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"FILE_SAVE",GCF_FILE_SAVE);

	//PARAM
	PX_ScriptVM_RegistHostFunction(&GCF_VMInstance,"PARAM_GET",GCF_PARAM_GET);

	GCF_VMInstance.runInstrTick=0xffffffff;

	if(!PX_ScriptVM_InstanceRunFunction(&GCF_VMInstance,PX_NULL,"_BOOT",0))
	{
		
		GCF_Message("Could not execute crack script.");
		return PX_FALSE;
	}

	if(!PX_ScriptVM_InstanceRunFunction(&GCF_VMInstance,PX_NULL,"CRACKMAIN",0))
	{
		GCF_Message("Could not execute crack script.");
		return PX_FALSE;
	}

	return PX_TRUE;
}
px_bool GCF_VM_RunFromResource()
{
	GCF_RESOURCE_HEADER *header=(GCF_RESOURCE_HEADER *)GCF_Resource;
	return GCF_VM_Run(header->image,header->size);
}