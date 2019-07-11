#include "generalcrackframeworkgui.h"

GeneralCrackFrameworkGUI::GeneralCrackFrameworkGUI(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);
	connect(&proc_dialog,SIGNAL(SIGNAL_onSelect(QString)),this,SLOT(SLOT_SelectTargetProcess(QString)));
	connect(ui.pushButton_Script,SIGNAL(clicked()),this,SLOT(SLOT_SelectScript()));
	connect(ui.pushButton_TargetFile,SIGNAL(clicked()),this,SLOT(SLOT_SelectTargetFile()));
	connect(ui.pushButton_Crack,SIGNAL(clicked()),this,SLOT(SLOT_Startup()));
	connect(ui.pushButton_process,SIGNAL(clicked()),this,SLOT(SLOT_Enumprocesses()));
	
}

HANDLE GetProcessHandleByName(QString Name)
{
	PROCESSENTRY32 procEntry = { 0 };
	procEntry.szExeFile[0]=0;
	HANDLE procSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(procSnap == INVALID_HANDLE_VALUE)
	{
		return INVALID_HANDLE_VALUE;
	}

	procEntry.dwSize = sizeof(PROCESSENTRY32);
	BOOL bRet = Process32First(procSnap,&procEntry);
	while(bRet)
	{
		if (QString::fromStdWString(procEntry.szExeFile)==Name)
		{
			CloseHandle(procSnap);
			return OpenProcess( PROCESS_ALL_ACCESS, FALSE, procEntry.th32ProcessID);
		}
		bRet = Process32Next(procSnap,&procEntry);
	}

	CloseHandle(procSnap);
	return INVALID_HANDLE_VALUE;
}

GeneralCrackFrameworkGUI::~GeneralCrackFrameworkGUI()
{

}
px_bool PX_SaveMemoryToFile(px_char *Path,px_byte *buffer,px_int size)
{
	FILE *pf=fopen(Path,"wb");
	if (pf==PX_NULL)
	{
		return PX_FALSE;
	}
	fwrite(buffer,1,size,pf);
	fclose(pf);
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

#define GCF_SCRIPT_DEFAULT_STACK 65536
#define GCF_VM_RUNTIME_MEMORY 1024*1024*8

static px_memorypool  GCF_Memorypool;
static px_byte GCF_VM_Runtime[GCF_VM_RUNTIME_MEMORY];
static PX_SCRIPT_LIBRARY GCF_Scriptlibrary;
static PX_ScriptVM_Instance GCF_VMInstance;

px_byte * CompileScript(px_char *Crack_Script,px_int *size)
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

		pData=(px_byte *)malloc(GCF_shellbin.usedsize);
		shellSize=GCF_shellbin.usedsize;
		px_memcpy(pData,GCF_shellbin.buffer,GCF_shellbin.usedsize);
		
		*size=shellSize;
		return pData;

_ERROR:
		MP_Release(&GCF_Memorypool);
		*size=0;
		return PX_NULL;
}

PX_LEXER_LEXEME_TYPE NextLexeme(px_lexer *lex)
{
	PX_LEXER_LEXEME_TYPE type;
	while ((type=PX_LexerGetNextLexeme(lex))==PX_LEXER_LEXEME_TYPE_SPACER);
	return type;
}



BOOL EnableDebugPriv() 
{
	HANDLE   hToken; 
	LUID   sedebugnameValue; 
	TOKEN_PRIVILEGES   tkp;
	if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken)) 
	{ 
		return   FALSE; 
	} 

	if(!LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&sedebugnameValue)) 
	{ 
		CloseHandle(hToken); 
		return   FALSE; 
	} 
	tkp.PrivilegeCount   =   1; 
	tkp.Privileges[0].Luid   =   sedebugnameValue; 
	tkp.Privileges[0].Attributes   =   SE_PRIVILEGE_ENABLED; 

	if(!AdjustTokenPrivileges(hToken,FALSE,&tkp,sizeof(tkp),NULL,NULL)) 
	{ 
		return   FALSE; 
	}   
	CloseHandle(hToken); 
	return TRUE;

} 

void GeneralCrackFrameworkGUI::SLOT_Startup()
{
	QString scriptPath,Target,Params,file_suffix;
	px_lexer lexer;
	QFileInfo fileinfo;
	px_byte *Shellbin=PX_NULL;
	px_byte *GCF_DLL=PX_NULL;
	px_int ShellBinSize;
	GCF_Memorypool=MP_Create(GCF_VM_Runtime,GCF_VM_RUNTIME_MEMORY);

	PX_LexerInit(&lexer,&GCF_Memorypool);
	px_uint equ;
	equ=PX_LexerRegisterDelimiter(&lexer,'=');
	PX_LexerRegisterDelimiter(&lexer,';');
	PX_LexerRegisterDelimiter(&lexer,',');
	PX_LexerRegisterDelimiter(&lexer,'+');
	PX_LexerRegisterDelimiter(&lexer,'-');
	PX_LexerRegisterDelimiter(&lexer,'*');
	PX_LexerRegisterDelimiter(&lexer,'/');
	PX_LexerRegisterDelimiter(&lexer,'?');
	PX_LexerRegisterDelimiter(&lexer,'.');
	PX_LexerRegisterDelimiter(&lexer,'(');
	PX_LexerRegisterDelimiter(&lexer,')');
	PX_LexerRegisterSpacer(&lexer,' ');
	PX_LexerRegisterSpacer(&lexer,'\t');
	PX_LexerRegisterContainer(&lexer,"\"","\"");

	scriptPath=ui.lineEdit_Path->text();
	Target=ui.lineEdit_Target->text();
	Params=ui.lineEdit_Param->text();

	if (scriptPath=="")
	{
		QMessageBox::information(this,tr("ERRPR"),tr("Script path should not be empty."),QMessageBox::Ok);
		goto _ERROR;
	}

	if (Target=="")
	{
		QMessageBox::information(this,tr("ERRPR"),tr("Script path should not be empty."),QMessageBox::Ok);
		goto _ERROR;
	}

	//Compile script
	fileinfo=QFileInfo(scriptPath);

	file_suffix = fileinfo.suffix().toUpper();

	if (file_suffix=="TXT")
	{
		Shellbin=CompileScript(scriptPath.toLocal8Bit().data(),&ShellBinSize);
		if (Shellbin==PX_NULL||ShellBinSize==0)
		{
			QMessageBox::information(this,tr("ERRPR"),tr("Compiled error."),QMessageBox::Ok);
			goto _ERROR;
		}
		scriptPath=scriptPath.left(scriptPath.length()-4);
		scriptPath+=".st";
		PX_SaveMemoryToFile(scriptPath.toLocal8Bit().data(),Shellbin,ShellBinSize);
	}
	else if(file_suffix=="ST")
	{
		Shellbin=PX_LoadFileToMemory(scriptPath.toLocal8Bit().data(),&ShellBinSize);
		if (Shellbin==PX_NULL||ShellBinSize==0)
		{
			QMessageBox::information(this,tr("ERRPR"),tr("Could not loaded script file."),QMessageBox::Ok);
			goto _ERROR;
		}
	}
	else
	{
		QMessageBox::information(this,tr("ERRPR"),tr("Unknow Script File"),QMessageBox::Ok);
		return;
	}

	//////////////////////////////////////////////////////////////////////////
	//Load Dll
	px_int GCFDLL_Size;
	GCF_DLL=PX_LoadFileToMemory("General Crack Framework Core.dll",&GCFDLL_Size);
	if (GCF_DLL==PX_NULL)
	{
		QMessageBox::information(this,tr("ERRPR"),tr("Could not Load GCF.DLL."),QMessageBox::Ok);
		goto _ERROR;
	}

	//////////////////////////////////////////////////////////////////////////
	//Seek to resource
	GCF_RESOURCE_HEADER *gcf_dll_ResourceHeader;
	int oft;
	for (oft=0;oft<GCFDLL_Size;oft++)
	{
		if (memcmp("GENERALCRACKFRAMEWORKRESOURCE",GCF_DLL+oft,sizeof("GENERALCRACKFRAMEWORKRESOURCE")-1)==0)
		{
			memset(GCF_DLL+oft,0,GCF_RESOURCE_SIZE);
			gcf_dll_ResourceHeader=(GCF_RESOURCE_HEADER *)(GCF_DLL+oft);
			break;
		}
	}
	if (oft==GCFDLL_Size)
	{
		QMessageBox::information(this,tr("ERRPR"),tr("illegal dll file."),QMessageBox::Ok);
		goto _ERROR;
	}
	//////////////////////////////////////////////////////////////////////////
	//Parse Params
	if(!PX_LexerLoadSourceFromMemory(&lexer,Params.toLocal8Bit().data()))
	{
		QMessageBox::information(this,tr("ERRPR"),tr("Parameter error."),QMessageBox::Ok);
		goto _ERROR;
	}
	PX_LEXER_LEXEME_TYPE type;
	while (PX_TRUE)
	{
		px_char Name[32];
		px_char param[256];

		type=NextLexeme(&lexer);
		if (type==PX_LEXER_LEXEME_TYPE_END)
		{
			break;
		}

		if (type!=PX_LEXER_LEXEME_TYPE_TOKEN)
		{
			QMessageBox::information(this,tr("ERRPR"),tr("Parameter error."),QMessageBox::Ok);
			goto _ERROR;
		}
		if (px_strlen(lexer.CurLexeme.buffer)>sizeof(Name)-1)
		{
			QMessageBox::information(this,tr("ERRPR"),tr("Parameter name too long."),QMessageBox::Ok);
			goto _ERROR;
		}
		px_strcpy(Name,lexer.CurLexeme.buffer,sizeof(Name));

		type=NextLexeme(&lexer);
		if (type!=PX_LEXER_LEXEME_TYPE_DELIMITER||lexer.CurrentDelimiterType!=equ)
		{
			goto _ERROR;
		}
		type=NextLexeme(&lexer);
		if (type!=PX_LEXER_LEXEME_TYPE_CONATINER)
		{
			QMessageBox::information(this,tr("ERRPR"),tr("Parameter error."),QMessageBox::Ok);
			goto _ERROR;
		}
		PX_LexerGetIncludedString(&lexer,&lexer.CurLexeme);
		if (px_strlen(lexer.CurLexeme.buffer)>sizeof(param)-1)
		{
			QMessageBox::information(this,tr("ERRPR"),tr("Parameter name too long."),QMessageBox::Ok);
			goto _ERROR;
		}
		px_strcpy(param,lexer.CurLexeme.buffer,sizeof(param));

		for (int idx=0;idx<GCF_PARAM_MAX_COUNT;idx++)
		{
			if (gcf_dll_ResourceHeader->param[idx].Name[0]==0)
			{
				px_strcpy(gcf_dll_ResourceHeader->param[idx].Name,Name,sizeof(Name));
				px_strcpy(gcf_dll_ResourceHeader->param[idx].Param,param,sizeof(param));
				break;
			}
		}
		type=NextLexeme(&lexer);
		if (type!=PX_LEXER_LEXEME_TYPE_DELIMITER||lexer.Symbol!=';')
		{
			if(type!=PX_LEXER_LEXEME_TYPE_END)
			{
			QMessageBox::information(this,tr("ERRPR"),tr("Parameter error."),QMessageBox::Ok);
			goto _ERROR;
			}
		}
	}
	//////////////////////////////////////////////////////////////////////////
	//Copy Image
	gcf_dll_ResourceHeader->size=ShellBinSize;
	px_memcpy(gcf_dll_ResourceHeader->image,Shellbin,ShellBinSize);
	

	//////////////////////////////////////////////////////////////////////////
	//Reflect injection

	
	EnableDebugPriv();

	HANDLE procHandle,ThreadHandle;
	if(targetType==TARGET_TYPE_FILE)
	{
		//////////////////////////////////////////////////////////////////////////
		//File
		STARTUPINFOA sti;
		PROCESS_INFORMATION proci;
		memset(&sti,0,sizeof(STARTUPINFO));
		memset(&proci,0,sizeof(PROCESS_INFORMATION));
		sti.cb=sizeof(STARTUPINFO);

		DWORD valc=CreateProcessA(Target.toLocal8Bit().data(),NULL,NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,&sti,&proci);
		if (valc==NULL)
		{
			QMessageBox::information(this,tr("ERROR"),tr("Could not open target PE file"));
			goto _ERROR;
		}
		procHandle=proci.hProcess;
		ThreadHandle=proci.hThread;
	}
	else
	{
		procHandle=GetProcessHandleByName(Target);
		if (procHandle==INVALID_HANDLE_VALUE)
		{
			QMessageBox::information(this,tr("ERROR"),tr("Could not open target process"));
			goto _ERROR;
		}
	}


	HANDLE hModule = LoadRemoteLibraryR( procHandle, GCF_DLL, GCFDLL_Size, NULL );

	WaitForSingleObject(hModule,-1);

	ResumeThread(ThreadHandle);
	CloseHandle(ThreadHandle);

_ERROR:
	if(Shellbin) free(Shellbin);
	if(GCF_DLL) free(GCF_DLL);
}

void GeneralCrackFrameworkGUI::SLOT_SelectScript()
{
	QString fileName = QFileDialog::getOpenFileName(this,tr("Open script File"),".",tr("StoryScript File(*.txt);;Story Shell(*.st)"));
	if(fileName.length() != 0)
	{
		ui.lineEdit_Path->setText(fileName);
	}
}

void GeneralCrackFrameworkGUI::SLOT_SelectTargetFile()
{
	QString fileName = QFileDialog::getOpenFileName(this,tr("Open target File"),".",tr("EXE File(*.exe)"));
	if(fileName.length() != 0)
	{
		ui.lineEdit_Target->setText(fileName);
	}
	targetType=TARGET_TYPE_FILE;
}

void GeneralCrackFrameworkGUI::SLOT_SelectTargetProcess(QString proc)
{
	ui.lineEdit_Target->setText(proc);
	targetType=TARGET_TYPE_PROCESS;
}

void GeneralCrackFrameworkGUI::SLOT_Enumprocesses()
{
	proc_dialog.show();
	proc_dialog.SLOT_onUpdate();
}

Process_dialog::Process_dialog(QWidget *parent /*= 0*/, Qt::WFlags flags /*= 0*/)
{	
	proc_dialog.setupUi(this);
	connect(this->proc_dialog.listWidget,SIGNAL(itemDoubleClicked(QListWidgetItem*)),this,SLOT(SLOT_itemDoubleClicked(QListWidgetItem*)));
	
}

void Process_dialog::SLOT_onUpdate()
{
	PROCESSENTRY32 procEntry = { 0 };
	procEntry.szExeFile[0]=0;
	HANDLE procSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(procSnap == INVALID_HANDLE_VALUE)
	{
		return;
	}

	procEntry.dwSize = sizeof(PROCESSENTRY32);
	BOOL bRet = Process32First(procSnap,&procEntry);
	while(bRet)
	{
		if (procEntry.szExeFile)
		{
			this->proc_dialog.listWidget->addItem(QString::fromStdWString(procEntry.szExeFile));
		}
		bRet = Process32Next(procSnap,&procEntry);
	}

	CloseHandle(procSnap);
	return;
}

void Process_dialog::SLOT_itemDoubleClicked(QListWidgetItem * item)
{
	emit SIGNAL_onSelect(item->text());
	this->close();
}

