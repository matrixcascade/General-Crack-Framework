#ifndef GENERALCRACKFRAMEWORKGUI_H
#define GENERALCRACKFRAMEWORKGUI_H

#include <QtGui/QMainWindow>
#include "ui_generalcrackframeworkgui.h"
#include "ui_processes.h"
#include "QString"
#include "QMessageBox"
#include "QFileInfo"
#include "QFileDialog"
#include "resource.h"


#include "windows.h"
#include <tlhelp32.h>

extern "C"
{
#include "../../PainterEngine/Kernel/PX_Kernel.h"
#include "LoadLibraryR.h"
};
#define GCF_PARAM_MAX_COUNT 16
#define GCF_RESOURCE_SIZE 1024*1024*2
typedef struct
{
	px_char Name[32];
	px_char Param[256];
}GCF_RESOURCE_PARAM;

typedef struct  
{
	GCF_RESOURCE_PARAM param[GCF_PARAM_MAX_COUNT];
	px_dword size;
	px_byte image[1];
}GCF_RESOURCE_HEADER;

class Process_dialog:public QWidget
{
	Q_OBJECT
public:
	Process_dialog(QWidget *parent = 0, Qt::WFlags flags = 0);
	public slots:
	void SLOT_onUpdate();
	void SLOT_itemDoubleClicked(QListWidgetItem * item);
signals:
	void SIGNAL_onSelect(QString proc_name);
private:
	Ui::ProcessesDialog proc_dialog;
};

typedef enum
{
	TARGET_TYPE_FILE,
	TARGET_TYPE_PROCESS,
}TARGET_TYPE;
class GeneralCrackFrameworkGUI : public QMainWindow
{
	Q_OBJECT

public:
	GeneralCrackFrameworkGUI(QWidget *parent = 0, Qt::WFlags flags = 0);
	~GeneralCrackFrameworkGUI();

public slots:
	void SLOT_Startup();
	void SLOT_SelectScript();
	void SLOT_Enumprocesses();
	void SLOT_SelectTargetFile();
	void SLOT_SelectTargetProcess(QString);
private:
	Ui::GeneralCrackFrameworkGUIClass ui;
	Process_dialog proc_dialog;
	TARGET_TYPE targetType;
};

#endif // GENERALCRACKFRAMEWORKGUI_H
