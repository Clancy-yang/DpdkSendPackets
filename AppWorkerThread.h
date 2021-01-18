#pragma once

#include "Common.h"
#include "PacketMatchingEngine.h"

#include "PacketUtils.h"
#include "DpdkDevice.h"
#include "DpdkDeviceList.h"
#include "PcapFileDevice.h"

#include "RawPacket.h"


#include "malloc.h"
#include "dirent.h"
#include "sys/stat.h"
#include <unistd.h>

#include <fstream>

#include <unordered_map>

#include <rte_ethdev.h>

// 已经被读取过的pcap数据包
static unordered_map<string, int> read_pcap_map_;

// 包负载结构体
//struct PacketStruct{
//    uint64_t data_len;
//    const uint8_t *data;
//    PacketStruct():data_len(0),data(nullptr){};
//    PacketStruct(uint64_t len,const uint8_t *data):data_len(len),data(data){};
//};

template<typename T>
static inline void FreeContainer(T& p_container){
    T empty;
    using std::swap;
    swap(p_container, empty);
}

int FindSecondDirFile(const char *dir_name, vector<string> &v) {
    DIR *dir;
    struct stat FileInfo{};
    struct dirent *dp;
    dir = opendir(dir_name);
    if (dir == nullptr)
        return 0;
    while((dp = readdir(dir)) != nullptr){
        if (dp->d_type == DT_UNKNOWN)
            continue;
        if (dp->d_type == DT_DIR){
            if (string(dp->d_name) != "." && string(dp->d_name) != ".."){
                string second_dir = string(dir_name) + "/" + string(dp->d_name);
                FindSecondDirFile(second_dir.c_str(), v);
            }
            continue;
        }
        string pcap_name = std::string(dir_name) + "/" + string(dp->d_name);
        if (read_pcap_map_.find(pcap_name) == read_pcap_map_.end()){
            // 抛弃空包
            stat(pcap_name.c_str(), &FileInfo);
            if (FileInfo.st_size > 24)
                v.emplace_back(pcap_name);
        }
    }
    return 0;
}

static bool SortPcapName(const string &the_first, const string &the_second) {
    pcpp::PcapFileReaderDevice first_reader(the_first.c_str());
    if (!first_reader.open())
        return false;
    pcpp::PcapFileReaderDevice second_reader(the_second.c_str());
    if (!second_reader.open())
        return false;
    bool result = true;
    auto firstPcapRawPacket = new pcpp::RawPacket();
    auto secondPcapRawPacket = new pcpp::RawPacket();
    if (!first_reader.getNextPacket(*firstPcapRawPacket) || !second_reader.getNextPacket(*secondPcapRawPacket))
        result = false;
    if (result && firstPcapRawPacket->getPacketTimeStamp().tv_sec > secondPcapRawPacket->getPacketTimeStamp().tv_sec) {
        result = false;
    } else if (result && firstPcapRawPacket->getPacketTimeStamp().tv_sec ==
                         secondPcapRawPacket->getPacketTimeStamp().tv_sec) {
        if (firstPcapRawPacket->getPacketTimeStamp().tv_nsec > secondPcapRawPacket->getPacketTimeStamp().tv_nsec) {
            result = false;
        }
    }
    first_reader.close();
    second_reader.close();
    delete firstPcapRawPacket;
    firstPcapRawPacket = nullptr;
    delete secondPcapRawPacket;
    secondPcapRawPacket = nullptr;
    return result;
}

int FindDirFile(const char *dir_name, vector<string> &v) {
    DIR *dir;
    struct stat FileInfo{};
    FreeContainer(v);
    struct dirent *dp;
    dir = opendir(dir_name);
    if (dir == nullptr){
        cout << "被监控文件夹:" << dir_name << " 不存在，请去config/config.ini修改" << endl;
    }
    while((dp = readdir(dir)) != nullptr){
        if (dp->d_type == DT_UNKNOWN)
            continue;
        if (dp->d_type == DT_DIR){
            if (string(dp->d_name) != "." && string(dp->d_name) != ".."){
                string second_dir = string(dir_name) + "/" + string(dp->d_name);
                FindSecondDirFile(second_dir.c_str(), v);
            }
            continue;
        }
        string pcap_name = string(dir_name) + "/" + string(dp->d_name);
        if (read_pcap_map_.find(pcap_name) == read_pcap_map_.end()){
            pcpp::PcapFileReaderDevice first_reader(pcap_name.c_str());
            if (first_reader.open()) {
                // 抛弃空包
                stat(pcap_name.c_str(), &FileInfo);
                if (FileInfo.st_size > 24)
                    v.emplace_back(pcap_name);
            }

        }
    }
    closedir(dir);
    sort(v.begin(), v.end(), SortPcapName);
    return 0;
}

int FindListFile(const char *dir_name, vector<string> &v){
    //开始读取列表文件名信息
    ifstream list(dir_name);
    if (!list.is_open())
    {
        cout << dir_name << " open fail!" << endl;
        return -1;
    }else {
        string filename;
        while(getline(list,filename)){
            v.push_back(filename);
        }

    }
    return 0;
}

/**
 * 完成所有工作的工作线程类：从相关的DPDK端口接收数据包，将其与数据包匹配引擎进行匹配，
 * 然后将其发送到TX端口和/或将它们保存到文件。此外，它还收集数据包统计信息。
 * 每个内核都分配了一个这样的工作线程，并且所有内核都使用DpdkDeviceList::startDpdkWorkerThreads激活（请参阅main.cpp）
 */
class AppWorkerThread : public pcpp::DpdkWorkerThread
{
private:
    bool m_Stop;
    PacketStats m_Stats;

    uint32_t m_CoreId;
	AppWorkerConfig& m_WorkerConfig;
public:
	explicit AppWorkerThread(AppWorkerConfig& workerConfig) :
	    m_Stop(true), m_CoreId(MAX_NUM_OF_CORES+1), m_WorkerConfig(workerConfig){}

	~AppWorkerThread() override = default;// do nothing

	PacketStats& getStats()
	{
		return m_Stats;
	}

	//实现抽象方法
	bool run(uint32_t coreId) override
	{
	    if(m_WorkerConfig.SendPacketsTo == nullptr) return false;

		m_CoreId = coreId;
		m_Stop = false;
		m_Stats.WorkerId = coreId;
		//pcpp::DpdkDevice* sendPacketsTo = m_WorkerConfig.SendPacketsTo;
        vector<string> v;
        struct timeval start{}, end{};
        struct stat FileInfo{};
		//主循环，运行直到被告知停止
		while (!m_Stop)
		{
            if(!m_WorkerConfig.PcapFileDirPath.empty()){
                //根据pcap所在文件夹读取pcap
                FindDirFile(m_WorkerConfig.PcapFileDirPath.c_str(), v);
                if (v.empty()){
                    malloc_trim(0); // 回收内存
                    cout << "当前所有文件读取完毕.. 正在监控文件夹: " << m_WorkerConfig.PcapFileDirPath  << endl;
                    sleep(2);
                }
            }else if(!m_WorkerConfig.PcapFileListPath.empty()){
                //根据list文件读取指定pcap
                FindListFile(m_WorkerConfig.PcapFileListPath.c_str(), v);
            }else{
                return false;
            }

            uint32_t file_size = v.size(); // 剩余待读文件数量
            uint32_t current_num = 0;
            pcpp::RawPacket raw_packet;
            for (const string &s :v){
                cout << "loading " << s << endl;
                pcpp::PcapFileReaderDevice reader(s.c_str());
                if(!reader.open()){
                    read_pcap_map_.insert(make_pair(s, 1));
                    cout << "文件 " << s << "打开失败"<<endl;
                    continue;
                }
                gettimeofday(&start, nullptr);
                stat(s.c_str(), &FileInfo);
                cout << "开始读取File: " << s << "(" << ++current_num << "/" << file_size << ")" << endl;
                while (true){
                    if (!m_Stop && !reader.getNextPacket(raw_packet)){
                        gettimeofday(&end, nullptr);
                        float useTime = (end.tv_sec - start.tv_sec) + (double)(end.tv_usec - start.tv_usec)/1000000.0;
                        cout << "耗费时间: " << useTime << "(s)" << " 文件大小: " << FileInfo.st_size /1024/1024 << "(MB)"
                                  << " 读取速度: " << FileInfo.st_size /1024/1024 / useTime << "(MB/s)" << endl;
                        read_pcap_map_.insert(make_pair(s, 1));
                        //m_Stats.total_number_ += FileInfo.st_size;

//                        struct rte_eth_stats ethStats{};
//                        if (0 == rte_eth_stats_get(m_WorkerConfig.SendPacketsPort, &ethStats)){
//                            cout << "传输包数:" << (ethStats.opackets - success_packets_num) << " 发送失败:" << (ethStats.oerrors - error_packets_num) << endl;
//                            cout << "成功率: " << ((double)(ethStats.obytes - m_Stats.send_success_number_) / (double)(FileInfo.st_size) ) * 100 << "% ";
//                            //cout << "丢包率: " << ((double)(ethStats.oerrors - error_packets_num) / (double)((ethStats.opackets - success_packets_num) + (ethStats.oerrors - error_packets_num)) ) * 100 << "% ";
//                            cout << "发送速度:" << (ethStats.obytes - m_Stats.send_success_number_)/1024/1024 / useTime << "MB/s" << endl;
//                            m_Stats.send_success_number_ = ethStats.obytes;
//                            success_packets_num = ethStats.opackets;
//                            error_packets_num = ethStats.oerrors;
//                        }
                        break; // 收尾完成，退出
                    }
                    //sendPacketsTo->sendPacket(raw_packet,0, true) ? m_Stats.sendSuccess_++ : m_Stats.sendError_++;
                    //m_Stats.PacketCount++;
                }
                if(m_Stop){
                    reader.close();
                    break;
                }
            }

            if(!m_WorkerConfig.PcapFileListPath.empty()) return true; //根据list读完pcap即结束
		}

		return true;
	}

	void stop() override
	{
		//分配停止标志，这将导致主循环结束
		m_Stop = true;
	}

	[[nodiscard]] uint32_t getCoreId() const override
	{
		return m_CoreId;
	}
};

class SendWorkerThread : public pcpp::DpdkWorkerThread
{
private:
    bool m_Stop;
    PacketStats m_Stats;

    uint32_t m_CoreId;
    SendWorkerConfig& m_WorkerConfig;
public:
    explicit SendWorkerThread(SendWorkerConfig& workerConfig) :
            m_Stop(true), m_CoreId(MAX_NUM_OF_CORES+1), m_WorkerConfig(workerConfig){
    }

    ~SendWorkerThread() override = default;// do nothing

    PacketStats& getStats()
    {
        //m_Stats.clear();
        cout << "sendAllPacketNum:" << m_Stats.sendAllPacketNum << endl;
        return m_Stats;
    }

    // 实现抽象方法
    bool run(uint32_t coreId) override
    {
        // 未初始化发包驱动
        if(m_WorkerConfig.SendPacketsTo == nullptr) return false;

        // 发包核心id
        m_CoreId = coreId;
        m_Stats.WorkerId = coreId;
        m_Stats.clear();

        // 停止标志位
        m_Stop = false;

        // 发包驱动
        pcpp::DpdkDevice* sendPacketsTo = m_WorkerConfig.SendPacketsTo;

        // 初始化ring和mempool
        rte_ring* ring_arr[m_WorkerConfig.ReadPcapCoreNum];
        rte_mempool* mempool_arr[m_WorkerConfig.ReadPcapCoreNum];

        for(int i = 0; i < m_WorkerConfig.ReadPcapCoreNum; ++i){
            //查找rte_ring
            string ring_tag = "rte_ring_" + to_string(i);
            ring_arr[i] = rte_ring_lookup(ring_tag.c_str());
            if(ring_arr[i] == nullptr){
                cout << "查找 " << ring_tag << " 失败!" << endl;
                exit(-1);
            }
            //查找mempool
            string mempool_tag = "mempool_" + to_string(i);
            mempool_arr[i] = rte_mempool_lookup(mempool_tag.c_str());
            if(mempool_arr[i] == nullptr){
                cout << "查找 " << mempool_tag << " 失败!" << endl;
                exit(-1);
            }
        }

        // 当前ring统计
        int ring_num = 0;

        // 统计信息
        struct timeval start{}, end{};
        struct rte_eth_stats ethStats{};

        cout << "==== 核心 " << m_CoreId << " ==== 开始发包 ==== " << endl;

        // 主循环，运行直到被告知停止
        while (!m_Stop)
        {
            uint64_t once_vector_num = 0; // 每次ring中携带的vector中包数
            uint64_t once_all_data_num = 0;// 每次ring中携带的总数据量
            uint64_t success_payload_num = 0;
            uint64_t error_payload_num = 0;

            void *msg = nullptr;
            while (!m_Stop && rte_ring_dequeue(ring_arr[ring_num], &msg) < 0){
                //cout << "rte_ring_" << ring_num << " 队列为空,等待中!" << endl;
                usleep(1);
            }
            // 开始计时
            gettimeofday(&start, nullptr);

            auto* packetStruct = (PacketStruct*)msg;
            //once_vector_num = packetStruct->rawPacketVector->size();
            for(auto *rawPacket : *(packetStruct->rawPacketVector)){
                int false_times = 0;

                while (!sendPacketsTo->sendPacket(*rawPacket,0, false)){
                    usleep(5);
                    if(++false_times == 3){
                        m_Stats.sendErrorPacketNum++;
                        error_payload_num += rawPacket->getRawDataLen();
                        break;
                    }
                }
                if(false_times != 3){
                    m_Stats.sendSuccessPacketNum++;
                    success_payload_num += rawPacket->getRawDataLen();
                }
                once_vector_num++;
                once_all_data_num += rawPacket->getRawDataLen();
                // 内存回收
                delete rawPacket;
                rawPacket = nullptr;
            }

            m_Stats.sendAllPacketNum += once_vector_num;
            m_Stats.sendAllDataNum += once_all_data_num;
            m_Stats.sendSuccessDataNum += success_payload_num;
            m_Stats.sendErrorDataNum += error_payload_num;

            delete packetStruct->rawPacketVector;
            packetStruct->rawPacketVector = nullptr;

            // 结束计时
            gettimeofday(&end, nullptr);
            float useTime = (end.tv_sec - start.tv_sec) + (double)(end.tv_usec - start.tv_usec)/1000000.0;
            if (0 == rte_eth_stats_get(m_WorkerConfig.SendPacketsPort, &ethStats)){
                cout << "* - - - 发包统计 RingId:" << ring_num << " PcapIndex:" << packetStruct->index << " - - - - - *" << endl;
                cout << "| 网卡信息:\t\t\t\t\t|" << endl;
                cout << "| 传输包数:" << (ethStats.opackets - m_Stats.sendPacketCount);
                cout << "\t传输数据:" << (double)(ethStats.obytes - m_Stats.sendDataCount)/1024/1024 << "(MB)\t|" << endl;

                cout << "| 统计信息:\t\t\t\t\t|" << endl;
                cout << "| 读取包数:" << once_vector_num;
                cout << "\t负载数据:" << (double)(once_all_data_num)/1024/1024 << "(MB)\t|" << endl;

                cout << "| 发送成功:" << (double)(success_payload_num)/1024/1024 << "(MB)\t发送失败:" << (double)(error_payload_num)/1024/1024 << "(MB)\t\t|" << endl;
                cout << "| 成功率: " << ((double)success_payload_num / (double)once_all_data_num ) * 100 << "%\t";
                cout << "\t发送速度:" << (ethStats.obytes - m_Stats.sendDataCount)/1024/128 / useTime << "Mb/s\t|" << endl;
                cout << "* - - - - - - - - - - - - - - - - - - - - - - - *" << endl;
                m_Stats.sendPacketCount = ethStats.opackets;
                m_Stats.sendDataCount = ethStats.obytes;
            }
            rte_mempool_put(mempool_arr[ring_num], msg);
            ++ring_num %= m_WorkerConfig.ReadPcapCoreNum;
            //usleep(10);
        }

        return true;
    }

    void stop() override
    {
        //分配停止标志，这将导致主循环结束
        m_Stop = true;
    }

    [[nodiscard]] uint32_t getCoreId() const override
    {
        return m_CoreId;
    }
};


class ReadWorkerThread : public pcpp::DpdkWorkerThread
{
private:
    bool m_Stop;
    uint32_t m_CoreId;
    ReadWorkConfig& m_WorkerConfig;
    PacketStats m_Stats;
public:
    explicit ReadWorkerThread(ReadWorkConfig& workerConfig):
    m_Stop(true),m_CoreId(MAX_NUM_OF_CORES+1),m_WorkerConfig(workerConfig)
    {}

    ~ReadWorkerThread() override = default;

    PacketStats& getStats()
    {
        return m_Stats;
    }

    // 实现抽象方法
    bool run(uint32_t coreId) override
    {
        m_Stats.clear();
        // 运行核心id
        m_CoreId = coreId;
        // 读包核心id = 运行核心 - 主核心 - 发包核心
        uint16_t ReadPcapCoreId = (coreId - 2);
        // 停止标志位
        m_Stop = false;
        // 状态信息:工作核心id
        m_Stats.WorkerId = ReadPcapCoreId;
        // 文件名集合
        vector<string> v = m_WorkerConfig.pcapFileNameVecter;
        //vector<string> v;
        // 剩余待读文件数量
        uint32_t file_size = v.size();
//        cout << "m_WorkerConfig.CoreId:" << m_WorkerConfig.CoreId << endl;
//        cout << "m_WorkerConfig.readPcapCoreNum:" << m_WorkerConfig.readPcapCoreNum << endl;
//        cout << "m_WorkerConfig.pcapFileNameVecter.size():" << m_WorkerConfig.pcapFileNameVecter.size() <<endl;
//        for(string str:m_WorkerConfig.pcapFileNameVecter){
//            cout << str << endl;
//        }

        // 查找rte_ring
        rte_ring* ring = nullptr;
        string ring_tag = "rte_ring_" + to_string(ReadPcapCoreId);
        ring = rte_ring_lookup(ring_tag.c_str());
        if(ring == nullptr){
            cout << "查找 " << ring_tag << " 失败!" << endl;
            exit(-1);
        }else{
            cout << "查找 " << ring_tag << " 成功!" << endl;
        }

        // 查找mempool
        rte_mempool* mempool = nullptr;
        string mempool_tag = "mempool_" + to_string(ReadPcapCoreId);
        mempool = rte_mempool_lookup(mempool_tag.c_str());
        if(mempool == nullptr){
            cout << "查找 " << mempool_tag << " 失败!" << endl;
            exit(-1);
        }else{
            cout << "查找 " << mempool_tag << " 成功!" << endl;
        }

        // 正在读取第几个文件
        int read_pcap_index = -1;

        // 统计信息
        struct timeval start{}, end{};
        struct stat FileInfo{};
        // 开始处理包
        usleep(coreId * 100);
        cout << "==== 核心 " << m_CoreId << " ==== 开始读包 ==== " << endl;
        //usleep(5);
        for (const string &s :v){
            if(m_Stop) return true;
            // 筛选当前核心需要读取的文件
            if((++read_pcap_index % m_WorkerConfig.readPcapCoreNum) == ReadPcapCoreId){
                auto *rawPacketVector = new vector<pcpp::RawPacket*>();
                gettimeofday(&start, nullptr);
                stat(s.c_str(), &FileInfo);
                //cout << "核心序号:" << m_CoreId << " 读取File: " << s << "(" << (read_pcap_index - 1) << "/" << file_size << ")" << endl;
                pcpp::PcapFileReaderDevice reader(s.c_str());
                if(!reader.open()){
                    read_pcap_map_.insert(make_pair(s, 1));
                    cout << "文件 " << s << "打开失败"<<endl;
                    continue;
                }
                while (true){
                    auto *rawPacketVector_ = new pcpp::RawPacketVector();

                    reader.getNextPackets(*rawPacketVector_);

                    auto *raw_packet = new pcpp::RawPacket();
                    if (!m_Stop && !reader.getNextPacket(*raw_packet)){
                        gettimeofday(&end, nullptr);
                        float useTime = (end.tv_sec - start.tv_sec) + (double)(end.tv_usec - start.tv_usec)/1000000.0;
                        read_pcap_map_.insert(make_pair(s, 1));

                        cout << "=====================================" << endl;
                        cout << "核心序号:" << m_CoreId << " 读取File: " << s << "(" << (read_pcap_index + 1) << "/" << file_size << ")" << endl;
                        cout << "读包队列:" << ReadPcapCoreId << " 本次读包:"<< rawPacketVector->size()<<endl;
                        cout << "耗费时间: " << useTime << "(s)" << " 文件大小: " << FileInfo.st_size /1024/1024 << "(MB)"
                             << " 读取速度: " << FileInfo.st_size /1024/1024 / useTime << "(MB/s)" << endl;
                        reader.close();
                        break; // 收尾完成，退出
                    }
                    rawPacketVector->push_back(raw_packet);
                }
                if(m_Stop){
                    reader.close();
                    break;
                }

                auto packetStruct = new PacketStruct;
                snprintf((char *)packetStruct->pcapName, s.size()+1, "%s", s.c_str());
                packetStruct->index = (read_pcap_index + 1);
                packetStruct->readCoreId = ReadPcapCoreId;
                packetStruct->rawPacketVector = rawPacketVector;
                cout << "Rte_ring_id:" << ring_tag << " rte_ring_count:" << rte_ring_count(ring) << endl;
                while(rte_ring_count(ring) > 2){
                    usleep(10);
                }
                // 将负载信息放入ring
                // rte_ring_rx_enqueue
                while (rte_ring_full(ring) == 1)
                    usleep(1);

                if (rte_ring_enqueue(ring, (void *)packetStruct) !=  0) {
                    //ring队列满,将申请的内存放回mempool
                    cout << "ring full" << endl;
                }

            }
        }
        sleep(2);
        cout << "核心" << coreId << "读包完成" << endl;

        //主循环，运行直到被告知停止
        while (!m_Stop){
            sleep(2);
        }

        return true;
    }

    void stop() override
    {
        //分配停止标志，这将导致主循环结束
        m_Stop = true;
    }

    [[nodiscard]] uint32_t getCoreId() const override
    {
        return m_CoreId;
    }
};


