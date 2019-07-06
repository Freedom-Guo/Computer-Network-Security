#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QThread>
#include <QStandardItemModel>
#include "ui_mainwindow.h"
#include "pcap.h"
#define HAVE_REMOTE

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    QStandardItemModel *packet_model;
    void setNetPort();
    ~MainWindow();

private slots:

    void on_analysisButton_clicked();

    void on_netportSelectButton_clicked();

    void on_packetTable_doubleClicked(const QModelIndex &index);

    void on_tcpBox_clicked(bool checked);

    void on_udpBox_clicked(bool checked);

    void on_icmpBox_clicked(bool checked);

    void on_deveiveStartButton_clicked();

    void on_applicationBox_clicked(bool checked);

private:
    Ui::MainWindow *ui;
    pcap_if_t *alldevs,*currentDev;
    //QStandardItemModel *packet_model;
    //QList<QString> storePacket;
    int currentDevIndex;
    pcap_t *curhandle;
    void setFilterRule(QString rule);
    void packetTableInit();
    void deeperArpAnalyze(QByteArray data,QTreeWidgetItem *arpRoot);
    void deeperIPAnalyze(QByteArray data,QTreeWidgetItem *ipRoot,QTreeWidgetItem *transRoot);
    //void deeperTransAnalyze(QByteArray transData,QTreeWidgetItem *transRoot);
    void deeperTCPAnalyze(QByteArray transData,QTreeWidgetItem *transRoot);
    void deeperUDPAnalyze(QByteArray transdata,QTreeWidgetItem *transRoot);
    void deeperICMPAnalyze(QByteArray transdata,QTreeWidgetItem *transRoot);
    void deeperDNSAnalyze(QByteArray appdata);
    void deeperDHCPAnalyze(QByteArray appdata);
    void showPacketContent(QByteArray packetContent);
    QByteArray Mac2char(QString HexString);
    QByteArray IP2char(QString sourceStr);
    QTreeWidgetItem *appRoot;
    boolean isApp;

};

#endif // MAINWINDOW_H
