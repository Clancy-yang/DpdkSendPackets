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
unordered_map<string, int> read_pcap_map_;

// 包负载结构体
struct PacketStruct{
    uint64_t data_len;
    const uint8_t *data;
    PacketStruct():data_len(0),data(nullptr){};
    PacketStruct(uint64_t len,const uint8_t *data):data_len(len),data(data){};
};

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
		pcpp::DpdkDevice* sendPacketsTo = m_WorkerConfig.SendPacketsTo;
        vector<string> v;
        struct timeval start{}, end{};
        struct stat FileInfo{};
        uint64_t success_packets_num = 0;
        uint64_t error_packets_num = 0;
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
                        m_Stats.total_number_ += FileInfo.st_size;

                        struct rte_eth_stats ethStats{};
                        if (0 == rte_eth_stats_get(m_WorkerConfig.SendPacketsPort, &ethStats)){
                            cout << "传输包数:" << (ethStats.opackets - success_packets_num) << " 发送失败:" << (ethStats.oerrors - error_packets_num) << endl;
                            cout << "成功率: " << ((double)(ethStats.obytes - m_Stats.send_success_number_) / (double)(FileInfo.st_size) ) * 100 << "% ";
                            //cout << "丢包率: " << ((double)(ethStats.oerrors - error_packets_num) / (double)((ethStats.opackets - success_packets_num) + (ethStats.oerrors - error_packets_num)) ) * 100 << "% ";
                            cout << "发送速度:" << (ethStats.obytes - m_Stats.send_success_number_)/1024/1024 / useTime << "MB/s" << endl;
                            m_Stats.send_success_number_ = ethStats.obytes;
                            success_packets_num = ethStats.opackets;
                            error_packets_num = ethStats.oerrors;
                        }
                        break; // 收尾完成，退出
                    }
                    sendPacketsTo->sendPacket(raw_packet,0, true) ? m_Stats.sendSuccess_++ : m_Stats.sendError_++;
                    m_Stats.PacketCount++;
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
            m_Stop(true), m_CoreId(MAX_NUM_OF_CORES+1), m_WorkerConfig(workerConfig){}

    ~SendWorkerThread() override = default;// do nothing

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
        pcpp::DpdkDevice* sendPacketsTo = m_WorkerConfig.SendPacketsTo;

        //主循环，运行直到被告知停止
        while (!m_Stop)
        {
            pcpp::RawPacket raw_packet;
            uint64_t rawDataLen = raw_packet.getRawDataLen();
            sendPacketsTo->sendPacket(raw_packet,0, true) ? m_Stats.sendSuccess_++ : m_Stats.sendError_++;
            m_Stats.PacketCount++;
            usleep(2);
            cout << "m_CoreId:" << m_CoreId << " SendPacketsPort:" << m_WorkerConfig.SendPacketsPort << endl;
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
    PacketStats m_Stats;

    uint32_t m_CoreId;
    ReadWorkConfig& m_WorkerConfig;
public:
    explicit ReadWorkerThread(ReadWorkConfig& workerConfig) :
            m_Stop(true), m_CoreId(MAX_NUM_OF_CORES+1), m_WorkerConfig(workerConfig){}

    ~ReadWorkerThread() override = default;// do nothing

    PacketStats& getStats()
    {
        return m_Stats;
    }

    //实现抽象方法
    bool run(uint32_t coreId) override
    {
        m_CoreId = coreId;
        m_Stop = false;
        m_Stats.WorkerId = coreId;
        vector<string> v = m_WorkerConfig.pcapFileNameVecter;

        rte_mempool* rteMempool = rte_mempool_lookup("mempool");
        if(rteMempool == nullptr){
            cout << "找不到 mempool " << endl;
            exit(-2);
        }

        struct timeval start{}, end{};
        struct stat FileInfo{};
        uint64_t success_packets_num = 0;
        uint64_t error_packets_num = 0;

        //主循环，运行直到被告知停止
        while (!m_Stop)
        {
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
                        m_Stats.total_number_ += FileInfo.st_size;

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
                    auto* packetStruct = new PacketStruct(raw_packet.getRawDataLen(),raw_packet.getRawData());


                    //sendPacketsTo->sendPacket(raw_packet,0, true) ? m_Stats.sendSuccess_++ : m_Stats.sendError_++;
                    m_Stats.PacketCount++;
                }
                if(m_Stop){
                    reader.close();
                    break;
                }
            }
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


