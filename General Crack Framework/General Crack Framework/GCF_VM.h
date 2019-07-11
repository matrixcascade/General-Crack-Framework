#ifndef GCF_VM_H
#define GCG_VM_H

#include "../../PainterEngine/Kernel/PX_Kernel.h"
#include "Windows.h"
#include "stdio.h"
#include "stdlib.h"

#define GCF_VM_RUNTIME_MEMORY 1024*1024*32
#define GCF_API_PARAMS_COUNT 16

px_byte* PX_LoadFileToMemory(px_char *path,px_int *size);

px_bool GCF_CONSOLE_PRINT(PX_ScriptVM_Instance *Ins,px_void *bp_param);

px_bool GCF_API_PARAMS(PX_ScriptVM_Instance *Ins,px_void *bp_param);
px_bool GCF_API_PARAM_BYTE(PX_ScriptVM_Instance *Ins,px_void *bp_param);
px_bool GCF_API_PARAM_WORD(PX_ScriptVM_Instance *Ins,px_void *bp_param);
px_bool GCF_API_PARAM_DWORD(PX_ScriptVM_Instance *Ins,px_void *bp_param);
px_bool GCF_API_PARAM_STRING(PX_ScriptVM_Instance *Ins,px_void *bp_param);
px_bool GCF_API_PARAM_MEMORY(PX_ScriptVM_Instance *Ins,px_void *bp_param);
px_bool GCF_API_RUN(PX_ScriptVM_Instance *Ins,px_void *bp_param);

px_bool GCF_STACK_INT(PX_ScriptVM_Instance *Ins,px_void *bp_param);
px_bool GCF_STACK_STRING(PX_ScriptVM_Instance *Ins,px_void *bp_param);
px_bool GCF_STACK_MEMORY(PX_ScriptVM_Instance *Ins,px_void *bp_param);

px_bool GCF_MEMORY_STRING(PX_ScriptVM_Instance *Ins,px_void *bp_param);
px_bool GCF_MEMORY_INT(PX_ScriptVM_Instance *Ins,px_void *bp_param);

px_bool GCF_IMAGE_SEARCH(PX_ScriptVM_Instance *Ins,px_void *bp_param);

px_bool GCF_VM_Init();
px_bool GCF_VM_Run(px_byte *Crack_Shell,px_int size);
px_bool GCF_VM_RunFromResource();
px_bool GCF_VM_RunScript(px_char *Crack_Script);
#endif
