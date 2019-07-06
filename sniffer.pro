#-------------------------------------------------
#
# Project created by QtCreator 2018-04-19T21:24:35
#
#-------------------------------------------------

QT       += core gui
#QT += concurrent widgets

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = sniffer
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS
INCLUDEPATH += D:\software\qt\Tools\mingw530_32\include
LIBS += D:\software\qt\Tools\mingw530_32\lib\Packet.lib
LIBS += -lpthread libwsock32 libws2_32
LIBS += D:\software\qt\Tools\mingw530_32\lib\wpcap.lib

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
        main.cpp \
        mainwindow.cpp

HEADERS += \
        mainwindow.h \
    tool.h \
    listenthread.h \
    sendpacket.h

FORMS += \
        mainwindow.ui
