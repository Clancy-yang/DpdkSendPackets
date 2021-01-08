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

#include <unordered_map>

// 已经被读取过的pcap数据包
unordered_map<string, int> read_pcap_map_;

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
	    if(m_WorkerConfig.SendPacketsTo == nullptr) return true;

		m_CoreId = coreId;
		m_Stop = false;
		m_Stats.WorkerId = coreId;
		pcpp::DpdkDevice* sendPacketsTo = m_WorkerConfig.SendPacketsTo;
        string path = m_WorkerConfig.PcapFileDirPath;
        vector<string> v;
        struct timeval start{}, end{};
        struct stat FileInfo{};

		//主循环，运行直到被告知停止
		while (!m_Stop)
		{
            FindDirFile(path.c_str(), v);

            if (v.empty()){
                malloc_trim(0); // 回收内存
                cout << "当前所有文件读取完毕.. 正在监控文件夹: " << path  << endl;
                sleep(2);
            }

            uint32_t file_size = v.size(); // 剩余待读文件数量
            uint32_t current_num = 0;
            pcpp::RawPacket raw_packet;
            for (const string &s :v){
                pcpp::PcapFileReaderDevice reader(s.c_str());
                if(!reader.open()){
                    read_pcap_map_.insert(make_pair(s, 1));
                    cout << "文件" << s << "打开失败"<<endl;
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
                                  << " 速度: " << FileInfo.st_size /1024/1024 / useTime << "(MB/s)" << endl;
                        read_pcap_map_.insert(make_pair(s, 1));
                        break; // 收尾完成，退出
                    }
                    sendPacketsTo->sendPacket(raw_packet,0);
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
