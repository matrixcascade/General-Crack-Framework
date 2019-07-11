#include "generalcrackframeworkgui.h"
#include <QtGui/QApplication>
#include <QTranslator>
int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	QTranslator qtTranslator;
	if(qtTranslator.load("Language.qm","./"))
		a.installTranslator(&qtTranslator);
	GeneralCrackFrameworkGUI w;
	w.show();
	return a.exec();
}
