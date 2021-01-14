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
                {"useTxBuffer",  no_argument, 0, 'b'},
                {"speed",  required_argument, 0, 'p'},
                {"list", optional_argument, 0, 'l'},
                {"help", optional_argument, 0, 'h'},
                {0, 0, 0, 0}
        };

//过滤流量参数
struct FiltetTrafficArgs
{
    bool shouldStop;
    std::vector<DpdkWorkerThread*>* workerThreadsVector;
    int sendPacketsToPort = -1;
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

int main(int argc, char* argv[]) {
    //展示基本信息
    AppName::init(argc, argv);
    printAppVersion();

    //DPDK发送端口
    int sendPacketsToPort = -1;

    bool useTxBuffer = false;

    int optionIndex = 0;
    char opt = 0;
    string pcapDirPath,pcapListPath;

    //发送速度(Mbps)
    uint16_t send_speed = 34463;

    while((opt = getopt_long (argc, argv, "s:a:p:blh", FilterTrafficOptions, &optionIndex)) != -1)
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
                useTxBuffer = true;
                break;
            }
            case 'p':
            {
                send_speed = atoi(optarg);
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

    if(pcapDirPath.empty() && pcapListPath.empty()){
        printUsage();
        exit(0);
    }

    //为机器上可用的所有核心创建核心掩码
    CoreMask coreMaskToUse = getCoreMaskForAllMachineCores();

    //缓冲池大小
    uint32_t mBufPoolSize = DEFAULT_MBUF_POOL_SIZE;

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

    //获取DPDK设备以向其发送数据包（如果不存在，则为NULL）
    DpdkDevice* sendPacketsTo = DpdkDeviceList::getInstance().getDeviceByPort(sendPacketsToPort);
    if (sendPacketsTo != nullptr && !sendPacketsTo->isOpened() &&  !sendPacketsTo->open())
        EXIT_WITH_ERROR("Could not open port#%d for sending matched packets", sendPacketsToPort);

    //工作线程配置结构体数组 每个核心绑定一个工作线程配置结构体
    AppWorkerConfig workerConfigArr[coresToUse.size()];
    workerConfigArr[0].CoreId = coresToUse[0].Id;
    workerConfigArr[0].SendPacketsTo = sendPacketsTo;
    workerConfigArr[0].SendPacketsPort = sendPacketsToPort;
    workerConfigArr[0].PcapFileDirPath = pcapDirPath;
    workerConfigArr[0].PcapFileListPath = pcapListPath;
    workerConfigArr[0].send_speed = send_speed;
    workerConfigArr[0].useTxBuffer = useTxBuffer;

    rte_eth_dev_info dev_info{};
    rte_eth_dev_info_get(sendPacketsToPort,&dev_info);
    cout << "speed_capa:" << dev_info.speed_capa << endl;
    cout << "nb_tx_queues:" << dev_info.nb_tx_queues<< endl;
    cout << "nb_rx_queues:" << dev_info.nb_rx_queues<< endl;

    if(rte_eth_dev_start(sendPacketsToPort) == 0){
        cout << "rte_eth_dev_start success!" << endl;
    }else{
        cout << "rte_eth_dev_start error!" << endl;
    }

    if(rte_eth_dev_set_link_up(sendPacketsToPort) == 0){
        cout << "rte_eth_dev_set_link_up success!" << endl;
    }else{
        cout << "rte_eth_dev_set_link_up error!" << endl;
    }

    struct rte_eth_dev *dev;
    dev = &rte_eth_devices[sendPacketsToPort];
    if(dev->data->dev_link.link_speed == 0){
        dev->data->dev_link.link_speed = 10240;
        cout << "set link_speed = "<< dev->data->dev_link.link_speed << endl;
    }else{
        cout << "get link_speed = "<< dev->data->dev_link.link_speed << endl;
    }

    if(send_speed != 34463) {
        int limit_stat = rte_eth_set_queue_rate_limit(sendPacketsToPort, 0, send_speed);
        if (limit_stat != 0) {
            switch (limit_stat) {
                case -ENOTSUP:
                    cout << "硬件不支持此功能" << endl;
                    break;
                case -ENODEV:
                    cout << "port id 无效" << endl;
                    break;
                case -EIO:
                    cout << "设备已卸载" << endl;
                    break;
                case -EINVAL:
                    cout << "参数错误" << endl;
                    break;
                default:
                    cout << "限速失败:"<< limit_stat << endl;
                    break;
            }
            cout << "采用 usleep 模式,请手动调节限速大小" << endl;
            workerConfigArr[0].dev_speed_limit = false;
        }else{
            cout << "DPDK限速中:当前速度:" << send_speed << "Mbps" << endl;
        }
    }

    //为每个核心创建工作线程
    vector<DpdkWorkerThread*> workerThreadVec;
    int i = 0;
    for (auto iter = coresToUse.begin(); iter != coresToUse.end(); iter++)
    {
        auto* newWorker = new AppWorkerThread(workerConfigArr[i]);
        workerThreadVec.push_back(newWorker);
        i++;
    }

    //启动所有工作线程
    if (!DpdkDeviceList::getInstance().startDpdkWorkerThreads(coreMaskToUse, workerThreadVec))
        EXIT_WITH_ERROR("Couldn't start worker threads");

    //注册应用程序关闭事件，以在应用程序终止时打印摘要统计信息
    FiltetTrafficArgs args;
    args.workerThreadsVector = &workerThreadVec;
    args.sendPacketsToPort = sendPacketsToPort;
    ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &args);
    //无限循环（直到程序终止）
    while (!args.shouldStop) usleep(5);

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

    rte_eth_dev_set_link_down(args->sendPacketsToPort);


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
           "    -p                           : 发送速度(Mb/s)\n"
           "    -b                           : 发包使用TxBuffer(提速但可能丢包)\n"
           //"    -b                           : pcap包的list文件\n"
           "------\n"
           "\n流程:\n\n"
           "./DpdkSendPackets -h  查看使用说明\n"
           "./DpdkSendPackets -l  查看DPDK支持端口列表\n"
           "./DpdkSendPackets -s 0 -a /data/pcap            设置DPDK发包端口0读取目录/data/pcap包\n"
           //"./DpdkSendPackets -s 0 -b /data/send_pcap.list  设置DPDK发包端口0读取目录/data/send_pcap.list文件中包地址\n"
           "./DpdkSendPackets -s 0 -a /data/pcap -p 1000    设置DPDK发包端口0读取目录/data/pcap包,发送速度为1000Mb/s\n"
           , AppName::get().c_str());
}

