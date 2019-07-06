#ifndef SENDPACKET_H
#define SENDPACKET_H
#include <QMainWindow>
#include <QThread>
#include "mainwindow.h"
#include "pcap.h"
#define HAVE_REMOTE

class sendPacketThread : public QThread
{
    Q_OBJECT
public:
    sendPacketThread(pcap_t *adhandle,QByteArray targetMac,QByteArray targetIP);
    void run();
private:
    pcap_t *adhandle;
    QByteArray targetMac;
    QByteArray targetIP;
};

#endif // SENDPACKET_H
