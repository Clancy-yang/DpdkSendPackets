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

#include <getopt.h>

using namespace pcpp;

#define DEFAULT_MBUF_POOL_SIZE 4095

static struct option FilterTrafficOptions[] =
        {
                {"s",  required_argument, 0, 's'},
                {"pcap-dir-path",  required_argument, 0, 'a'},
                {"pcap-list-path",  required_argument, 0, 'b'},
                {"c",  required_argument, 0, 'c'},
                {"list", optional_argument, 0, 'l'},
                {"help", optional_argument, 0, 'h'},
                {0, 0, 0, 0}
        };

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

//应用程序由ctrl-c终止时要调用的回调。 进行清理并打印摘要统计信息
void onApplicationInterrupted(void* cookie);

void printUsage();

//指定调用的核心(从哪到哪)
CoreMask GenCoreNums(uint16_t start, uint16_t end);

int main(int argc, char* argv[]) {
    //展示基本信息
    AppName::init(argc, argv);
    printAppVersion();

    //DPDK发送端口
    int sendPacketsToPort = -1;

    //读包所用核心数
    uint16_t readPcapCoreNum = 1;

    int optionIndex = 0;
    char opt = 0;
    string pcapDirPath,pcapListPath;

    while((opt = getopt_long (argc, argv, "s:a:b:c:lh", FilterTrafficOptions, &optionIndex)) != -1)
    {
        switch (opt)
        {
            case 0:
            {
                break;
            }
            case 's':
            {
                sendPacketsToPort = atoi(optarg);
                break;
            }
            case 'a':
            {
                pcapDirPath = string(optarg);
                break;
            }
            case 'b':
            {
                pcapListPath = string(optarg);
                break;
            }
            case 'c':
            {
                readPcapCoreNum = atoi(optarg);
                break;
            }
            case 'l':
            {
                listDpdkPorts();
                return 0;
            }
            case 'h':
            {
                printUsage();
                return 0;
            }
            default:
            {
                printUsage();
                return 0;
            }
        }
    }

    //读取文件目录
    vector<string> pcapFileNameVecter;
    if(!pcapDirPath.empty()){
        //根据pcap所在文件夹读取pcap
        FindDirFile(pcapDirPath.c_str(), pcapFileNameVecter);
    }else if(!pcapListPath.empty()){
        //根据list文件读取指定pcap
        FindListFile(pcapListPath.c_str(), pcapFileNameVecter);
    }else{
        printUsage();
        exit(0);
    }
    if(pcapFileNameVecter.empty()){
        cout << "未读取到pcap" << endl;
        exit(0);
    } else
        cout << "找到" << pcapFileNameVecter.size() << "个文件" << endl;

    //为机器上可用的所有核心创建核心掩码
//    CoreMask coreMaskToUse = getCoreMaskForAllMachineCores();

    //缓冲池大小
    uint32_t mBufPoolSize = DEFAULT_MBUF_POOL_SIZE;

    //从核心遮罩中提取核心向量
    vector<SystemCore> coresToUse;
    //核心数 = 主程序 + 发包 + 读文件
    uint16_t allUseCoreNum = 1 + 1 + readPcapCoreNum;
    //为机器上可用的指定核心创建核心掩码
    CoreMask coreMaskToUse = GenCoreNums(0,allUseCoreNum);
    createCoreVectorFromCoreMask(coreMaskToUse, coresToUse);

    //至少需要2个核心才能启动-1个管理核心+ 1个（或更多）辅助线程
    if (coresToUse.size() < 2) EXIT_WITH_ERROR("至少需要2个核心才能启动");

    //初始化DPDK
    if (!DpdkDeviceList::initDpdk(coreMaskToUse, mBufPoolSize)) EXIT_WITH_ERROR("Couldn't initialize DPDK");

    cout <<"coreMaskToUse:" << coreMaskToUse << " coresToUse:" << coresToUse.size() << endl;
    //保留发包核心,屏蔽主核心和读包核心
//    CoreMask sendPacketCore = GenCoreNums(2,allUseCoreNum) | 1;
//    coreMaskToUse = coreMaskToUse & ~sendPacketCore;


    //从核心屏蔽中删除DPDK主核心，因为DPDK工作线程无法在主核心上运行
    coreMaskToUse = coreMaskToUse & ~(DpdkDeviceList::getInstance().getDpdkMasterCore().Mask);
//    cout << "DpdkDeviceList::getInstance().getDpdkMasterCore().Mask:" << DpdkDeviceList::getInstance().getDpdkMasterCore().Mask << endl;


    //删除主核心后重新计算要使用的核心
    coresToUse.clear();
    createCoreVectorFromCoreMask(coreMaskToUse, coresToUse);

    cout <<"coreMaskToUse:" << coreMaskToUse << " coresToUse:" << coresToUse.size() << endl;

    //获取DPDK设备以向其发送数据包（如果不存在，则为NULL）
    DpdkDevice* sendPacketsTo = DpdkDeviceList::getInstance().getDeviceByPort(sendPacketsToPort);
    if (sendPacketsTo != nullptr && !sendPacketsTo->isOpened() &&  !sendPacketsTo->open())
        EXIT_WITH_ERROR("Could not open port#%d for sending matched packets", sendPacketsToPort);

    //初始化rte_ring 和 mempool
    for(int i = 0; i < readPcapCoreNum; ++i){
        //创建rte_ring
        string ring_tag = "rte_ring_" + to_string(i);
        if(rte_ring_create(ring_tag.c_str(),262144,(uint)rte_socket_id(),0) == nullptr){
            cout << "创建 " << ring_tag << " 失败!" << endl;
            exit(-1);
        }

        //创建mempool
        string mempool_tag = "mempool_" + to_string(i);
        if(rte_mempool_create(mempool_tag.c_str(), 65536, (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM), 32, sizeof(struct rte_pktmbuf_pool_private),
                              rte_pktmbuf_pool_init, nullptr, rte_pktmbuf_init, nullptr, (uint)rte_socket_id(),
                              0) == nullptr){
            cout << "创建 " << mempool_tag << " 失败!" << endl;
            exit(-1);
        }
    }

//    struct rte_ring *ring = rte_ring_create("message_ring",262144, (uint)rte_socket_id(), 0);
//    struct rte_mempool *message_pool = rte_mempool_create("message_pool", 65536,2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM, 32, 0,
//            NULL, NULL, NULL, NULL,rte_socket_id(), 0);
//
//    if(ring == nullptr || message_pool == nullptr){
//        cout << "ring 或 mempool 创建失败 " << endl;
//        exit(-1);
//    }

    //根据pcap所在文件夹读取pcap
//    vector<string> pcap_file_name_vector;
//    FindDirFile(pcapDirPath.c_str(), pcap_file_name_vector);


    //为每个核心创建工作线程
    vector<DpdkWorkerThread*> workerThreadVec;

    //发送工作线程配置
    SendWorkerConfig sendWorkerConfig(1,sendPacketsTo,sendPacketsToPort);
    sendWorkerConfig.ReadPcapCoreNum = readPcapCoreNum;
    auto* sendWorkerThread = new SendWorkerThread(sendWorkerConfig);
    workerThreadVec.push_back(sendWorkerThread);

    //读包工作线程配置
    for(int i = 0; i < readPcapCoreNum; ++i){
        ReadWorkConfig readWorkConfig(i,&pcapFileNameVecter);
        readWorkConfig.ReadPcapCoreNum = readPcapCoreNum;
        auto* readWorkerThread = new ReadWorkerThread(readWorkConfig);
        workerThreadVec.push_back(readWorkerThread);
    }
    cout << "workerThreadVec:" << workerThreadVec.size() << " coreMaskToUse:" << coreMaskToUse << endl;
    //启动所有工作线程
    if (!DpdkDeviceList::getInstance().startDpdkWorkerThreads(coreMaskToUse, workerThreadVec))
        EXIT_WITH_ERROR("Couldn't start worker threads:");

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

void onApplicationInterrupted(void* cookie)
{
    auto* args = (FiltetTrafficArgs*)cookie;
    //停止工作线程
    printf("\n\nApplication stopped\n");

    //DpdkDeviceList::getInstance().stopDpdkWorkerThreads();

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
        delete thread;
    }

    printer.printRow(aggregatedStats.getStatValuesAsString("|"), '|');

    args->shouldStop = true;
}


void printUsage()
{
    printf("\n帮助:\n"
           "------\n"
           "%s [-hl][-s PORT] [-a /root/pcap] [-b /data/send_pcap.list]\n"
           "\n命令:\n\n"
           "    -h                           : 使用说明\n"
           "    -l                           : DPDK端口列表\n"
           "    -s                           : 绑定dpdk发包端口\n"
           "    -a                           : pcap包所在目录\n"
           //"    -b                           : pcap包的list文件\n"
           "------\n"
           "\n流程:\n\n"
           "./DpdkSendPackets -h  查看使用说明\n"
           "./DpdkSendPackets -l  查看DPDK支持端口列表\n"
           "./DpdkSendPackets -s 0 -a /data/pcap            设置DPDK发包端口0读取目录/data/pcap包\n"
           //"./DpdkSendPackets -s 0 -b /data/send_pcap.list  设置DPDK发包端口0读取目录/data/send_pcap.list文件中包地址\n"
           , AppName::get().c_str());
}

CoreMask GenCoreNums(uint16_t start, uint16_t end){
    CoreMask result = 0;
    for (uint16_t i = start; i < end; i++) {
        result |= 1 << i;
    }
    return result;
}

