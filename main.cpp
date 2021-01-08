#include "Common.h"
#include "PacketMatchingEngine.h"
#include "AppWorkerThread.h"

#include "DpdkDeviceList.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include "TablePrinter.h"

#include <vector>
#include <iostream>
#include <cstdlib>
#include <string>
#include <unistd.h>

using namespace pcpp;

#define DEFAULT_MBUF_POOL_SIZE 4095

//过滤流量参数
struct FiltetTrafficArgs
{
    bool shouldStop;
    std::vector<DpdkWorkerThread*>* workerThreadsVector;
    FiltetTrafficArgs() : shouldStop(false), workerThreadsVector(nullptr) {}
};

//DPDK发包小程序
int main(int argc, char* argv[]);

//打印程序版本信息
void printAppVersion();

//打印DPDK支持的端口
void listDpdkPorts();

//为每个核心准备配置。 配置包括：从哪个DpdkDevices和哪个RX队列接收数据包，将匹配的数据包发送到哪里，等等。
void prepareCoreConfiguration(vector<DpdkDevice*>& dpdkDevicesToUse,
                              vector<SystemCore>& coresToUse,
                              bool writePacketsToDisk,
                              const string& packetFilePath,
                              DpdkDevice* sendPacketsTo,
                              AppWorkerConfig workerConfigArr[],
                              int workerConfigArrLen);

//应用程序由ctrl-c终止时要调用的回调。 进行清理并打印摘要统计信息
void onApplicationInterrupted(void* cookie);

int main(int argc, char* argv[]) {
    //展示基本信息
    AppName::init(argc, argv);
    printAppVersion();
    //listDpdkPorts();

    //保存pcap包
    bool writePacketsToDisk = false;
    string packetFilePath;

    //DPDK接收端口
    std::vector<int> dpdkPortVec = {
        0
    };

    //为机器上可用的所有核心创建核心掩码
    CoreMask coreMaskToUse = getCoreMaskForAllMachineCores();

    //DPDK发送端口
    int sendPacketsToPort = -1;

    //缓冲池大小
    uint32_t mBufPoolSize = DEFAULT_MBUF_POOL_SIZE;

    //过滤条件(地址、端口、协议类型)
    IPv4Address 	srcIPToMatch = IPv4Address::Zero;
    IPv4Address 	dstIPToMatch = IPv4Address::Zero;
    uint16_t 		srcPortToMatch = 0;
    uint16_t 		dstPortToMatch = 0;
    ProtocolType	protocolToMatch = UnknownProtocol; //TCP，UDP

    //验证列表不为空
    if (dpdkPortVec.empty()) EXIT_WITH_ERROR_AND_PRINT_USAGE("DPDK列表为空,请在当前支持的DPDK列表中选择添加.");

    //从核心遮罩中提取核心向量
    vector<SystemCore> coresToUse;
    createCoreVectorFromCoreMask(coreMaskToUse, coresToUse);

    //至少需要2个核心才能启动-1个管理核心+ 1个（或更多）辅助线程
    if (coresToUse.size() < 2) EXIT_WITH_ERROR("至少需要2个核心才能启动");

    //初始化DPDK
    if (!DpdkDeviceList::initDpdk(coreMaskToUse, mBufPoolSize)) EXIT_WITH_ERROR("Couldn't initialize DPDK");

    //从核心屏蔽中删除DPDK主核心，因为DPDK工作线程无法在主核心上运行
    coreMaskToUse = coreMaskToUse & ~(DpdkDeviceList::getInstance().getDpdkMasterCore().Mask);

    //删除主核心后重新计算要使用的核心
    coresToUse.clear();
    createCoreVectorFromCoreMask(coreMaskToUse, coresToUse);

    //收集DPDK设备列表
    vector<DpdkDevice*> dpdkDevicesToUse;
    for (int & iter : dpdkPortVec)
    {
        DpdkDevice* dev = DpdkDeviceList::getInstance().getDeviceByPort(iter);
        if (dev == nullptr) EXIT_WITH_ERROR("DPDK device for port %d doesn't exist", iter);
        dpdkDevicesToUse.push_back(dev);
    }

    //查看所有设备并打开它们
    for (auto & iter : dpdkDevicesToUse)
        if (!iter->openMultiQueues(iter->getTotalNumOfRxQueues(), iter->getTotalNumOfTxQueues()))
            EXIT_WITH_ERROR("Couldn't open DPDK device #%d, PMD '%s'", iter->getDeviceId(), iter->getPMDName().c_str());

    //获取DPDK设备以向其发送数据包（如果不存在，则为NULL）
    DpdkDevice* sendPacketsTo = DpdkDeviceList::getInstance().getDeviceByPort(sendPacketsToPort);
    if (sendPacketsTo != nullptr && !sendPacketsTo->isOpened() &&  !sendPacketsTo->open())
        EXIT_WITH_ERROR("Could not open port#%d for sending matched packets", sendPacketsToPort);

    //工作线程配置结构体数组 每个核心绑定一个工作线程配置结构体
    AppWorkerConfig workerConfigArr[coresToUse.size()];
    //为每个核心准备配置
    prepareCoreConfiguration(dpdkDevicesToUse,
                             coresToUse,
                             writePacketsToDisk,
                             packetFilePath,
                             sendPacketsTo,
                             workerConfigArr,
                             coresToUse.size());

    PacketMatchingEngine matchingEngine(srcIPToMatch, dstIPToMatch, srcPortToMatch, dstPortToMatch, protocolToMatch);

    //为每个核心创建工作线程
    vector<DpdkWorkerThread*> workerThreadVec;
    int i = 0;
    for (auto iter = coresToUse.begin(); iter != coresToUse.end(); iter++)
    {
        auto* newWorker = new AppWorkerThread(workerConfigArr[i], matchingEngine);
        workerThreadVec.push_back(newWorker);
        i++;
    }

    //启动所有工作线程
    if (!DpdkDeviceList::getInstance().startDpdkWorkerThreads(coreMaskToUse, workerThreadVec))
        EXIT_WITH_ERROR("Couldn't start worker threads");

    //注册应用程序关闭事件，以在应用程序终止时打印摘要统计信息
    FiltetTrafficArgs args;
    args.workerThreadsVector = &workerThreadVec;
    ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &args);

    //无限循环（直到程序终止）
    while (!args.shouldStop) sleep(5);

    return 0;
}

void printAppVersion()
{
    printf("AppName: %s\n", AppName::get().c_str());
    printf("PcapPlusPlusVersion: %s\n", getPcapPlusPlusVersionFull().c_str());
    printf("Built: %s\n", getBuildDateTime().c_str());
    printf("Built from: %s\n", getGitInfo().c_str());
    //exit(0);
}

void listDpdkPorts()
{
    CoreMask coreMaskToUse = getCoreMaskForAllMachineCores();

    // initialize DPDK
    if (!DpdkDeviceList::initDpdk(coreMaskToUse, DEFAULT_MBUF_POOL_SIZE))
    {
        EXIT_WITH_ERROR("couldn't initialize DPDK");
    }

    printf("DPDK port list:\n");

    // go over all available DPDK devices and print info for each one
    vector<DpdkDevice*> deviceList = DpdkDeviceList::getInstance().getDpdkDeviceList();
    for (auto dev : deviceList)
    {
        printf("    Port #%d: MAC address='%s'; PCI address='%s'; PMD='%s'\n",
               dev->getDeviceId(),
               dev->getMacAddress().toString().c_str(),
               dev->getPciAddress().c_str(),
               dev->getPMDName().c_str());
    }
}

void prepareCoreConfiguration(vector<DpdkDevice*>& dpdkDevicesToUse,//DPDK设备列表
                              vector<SystemCore>& coresToUse,//核心向量
                              bool writePacketsToDisk,//是否保存pcap包
                              const string& packetFilePath,//保存pcap的路径
                              DpdkDevice* sendPacketsTo,//发包DPDK设备
                              AppWorkerConfig workerConfigArr[],//工作线程配置结构体数组
                              int workerConfigArrLen //工作核心数量
                              )
{
    if(workerConfigArrLen < 2) return;
    //为所有请求的设备中的所有RX队列创建DpdkDevice和RX队列对列表
    uint64_t totalNumOfRxQueues = 0;
    vector<pair<DpdkDevice*, int>> deviceAndRxQVec;
    for (auto & iter : dpdkDevicesToUse)
    {
        for (int rxQueueIndex = 0; rxQueueIndex < iter->getTotalNumOfRxQueues(); rxQueueIndex++)
        {
            pair<DpdkDevice*, int> curPair(iter, rxQueueIndex);
            deviceAndRxQVec.push_back(curPair);
        }
        cout << "DpdkDeviceId:" << iter->getDeviceId() << ",TotalNumOfRxQueues:"<<iter->getTotalNumOfRxQueues()<<endl;
        totalNumOfRxQueues += iter->getTotalNumOfRxQueues();
    }

    //计算每个内核将从中读取数据包的RX队列数，我们将RX队列的总数除以内核总数
    //每个内核的Rx队列数
    int numOfRxQueuesPerCore = int(totalNumOfRxQueues / coresToUse.size());
    //Rx剩余队列
    int rxQueuesRemainder = int(totalNumOfRxQueues % coresToUse.size());

    //为每个核心准备配置：使用不同的核心为每个设备划分设备和RX队列
    int i = 0;
    vector<pair<DpdkDevice *, int> >::iterator pairVecIter;
    pairVecIter = deviceAndRxQVec.begin();

    for (auto & iter : coresToUse)
    {
        printf("使用核心 %d\n", iter.Id);
        workerConfigArr[i].CoreId = iter.Id;
        workerConfigArr[i].WriteMatchedPacketsToFile = writePacketsToDisk;

        std::stringstream packetFileName;
        packetFileName << packetFilePath << "Core" << workerConfigArr[i].CoreId << ".pcap";
        workerConfigArr[i].PathToWritePackets = packetFileName.str();

        workerConfigArr[i].SendPacketsTo = sendPacketsTo;
        for (int rxQIndex = 0; rxQIndex < numOfRxQueuesPerCore; rxQIndex++)
        {
            //将指定的DPDK驱动和队列索引放入核心配置文件
            if (pairVecIter == deviceAndRxQVec.end())
                break;
            workerConfigArr[i].InDataCfg[pairVecIter->first].push_back(pairVecIter->second);
            pairVecIter++;
        }

        //Rx剩余队列也放入核心配置中
        if (rxQueuesRemainder > 0 && (pairVecIter != deviceAndRxQVec.end()))
        {
            workerConfigArr[i].InDataCfg[pairVecIter->first].push_back(pairVecIter->second);
            pairVecIter++;
            rxQueuesRemainder--;
        }

        //打印核心的配置
        printf("   核心配置:\n");
        for (auto & iter2 : workerConfigArr[i].InDataCfg)
        {
            printf("      DPDK device#%d: ", iter2.first->getDeviceId());
            for (int & iter3 : iter2.second)
                printf("RX-Queue#%d;  ", iter3);
            printf("\n");
        }
        if (workerConfigArr[i].InDataCfg.empty())
            printf("      None\n");
        i++;
    }
}

void onApplicationInterrupted(void* cookie)
{
    auto* args = (FiltetTrafficArgs*)cookie;
    //停止工作线程
    printf("\n\nApplication stopped\n");
    DpdkDeviceList::getInstance().stopDpdkWorkerThreads();

    //创建表格打印
    std::vector<std::string> columnNames;
    std::vector<int> columnWidths;
    PacketStats::getStatsColumns(columnNames, columnWidths);
    TablePrinter printer(columnNames, columnWidths);

    //显示每个工作线程的最终状态以及所有线程和空闲工作线程内存的总和
    PacketStats aggregatedStats;
    for (auto & iter : *args->workerThreadsVector)
    {
        auto* thread = (AppWorkerThread*)iter;
        PacketStats threadStats = thread->getStats();
        aggregatedStats.collectStats(threadStats);
        printer.printRow(threadStats.getStatValuesAsString("|"), '|');
        delete thread;
    }

    printer.printSeparator();
    printer.printRow(aggregatedStats.getStatValuesAsString("|"), '|');

    args->shouldStop = true;
}


