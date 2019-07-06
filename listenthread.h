#ifndef LISTENTHREAD_H
#define LISTENTHREAD_H

#include <QMainWindow>
#include <QThread>
#include <QStandardItemModel>
#include "mainwindow.h"
#include "pcap.h"
#define HAVE_REMOTE

class listenThread : public QThread
{
    Q_OBJECT
public:
    listenThread(MainWindow *mainW,Ui::MainWindow *ui,pcap_t *adhandle);
    //~listenThread();
    static void packet_handler(const struct pcap_pkthdr *header, const unsigned char *pkt_data);
    static int countIPPacket[4];
    static QStandardItemModel *packetTableModel;
    void run();
private:
    //static QList<QString>  packetList;

    MainWindow *mainW;
    Ui::MainWindow *ui;
    pcap_t *adhandle;
    static void packetWrite(u_char *rest_packet,int tempCount, int restPacketLen);
    static int count;
    static void analyzeIP(const u_char *rest_pkt_data,int tempCount);
    static void analyzeARP(const u_char *rest_pkt_data,int tempCount);
    static void analyzeRARP(const u_char *rest_pkt_data,int tempCount);
    static void unknownEthernetPacket(int tempCount);

};

#endif // LISTENTHREAD_H
