#include "mainwindow.h"
#include <QApplication>
#include "pcap.h"

#define HAVE_REMOTE

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.setNetPort();
    w.show();
    return a.exec();
}
