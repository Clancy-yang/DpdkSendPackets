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
        //核心id
		m_CoreId = coreId;
		//工作线程id
		m_Stats.WorkerId = (coreId - 1);
		//是否停止
        m_Stop = false;

        //发包驱动
		pcpp::DpdkDevice* sendPacketsTo = m_WorkerConfig.SendPacketsTo;

		//统计信息
        vector<string> v;
        struct timeval read_start{}, read_end{};
        struct stat FileInfo{};
        usleep(m_Stats.WorkerId);
        cout << "核心:" << m_Stats.WorkerId << " 启动" << endl;

		//主循环，运行直到被告知停止
		while (!m_Stop)
		{
		    //判断数据来源
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

            //读取文件列表
            uint32_t file_size = v.size(); // 剩余待读文件数量
            uint32_t current_num = 0;

            //根据列表读指定pcap包
            for (const string &s :v){
                //判断当前包是否归属于当前线程处理
                if(current_num++ % m_WorkerConfig.readCoreNum != m_Stats.WorkerId) continue;
                //开始计时
                gettimeofday(&read_start, nullptr);
                //开始读取数据
                pcpp::PcapFileReaderDevice reader(s.c_str());
                if(!reader.open()){
                    read_pcap_map_.insert(make_pair(s, 1));
                    cout << "文件 " << s << "打开失败"<<endl;
                    continue;
                }
                stat(s.c_str(), &FileInfo);

                //包总数
                uint64_t total_packet_num = 0;

                //RawPacketVector的数组
                vector<pcpp::RawPacketVector*> raw_packet_vector_vector;

                //在未收到终止信号或未break时一直循环
                while (!m_Stop){
                    //新建RawPacketVector对象
                    auto *rawPacketVector = new pcpp::RawPacketVector();
                    //根据pcpp文档表示<64时直接发送>400时将有0.2秒的内置睡眠时间来清理TX描述符
                    uint64_t tmp = reader.getNextPackets(*rawPacketVector,400);
                    total_packet_num += tmp;

                    //当返回值小于0时读包结束
                    if(tmp <= 0){
                        //读取完毕：统计读包用时
                        gettimeofday(&read_end, nullptr);
                        //统计信息
                        *(m_WorkerConfig.io_delay) = (*(m_WorkerConfig.token) == m_Stats.WorkerId);
                        m_Stats.read_packet_num += total_packet_num;
                        m_Stats.read_data_num += FileInfo.st_size;
                        if(m_WorkerConfig.showReadInfo){
                            cout << "================ loading ================  "<<(*(m_WorkerConfig.token) == m_Stats.WorkerId ? "等待IO":" ") << endl;
                            cout << "核心:" << m_Stats.WorkerId << " 读取File: " << s << "(" << current_num << "/" << file_size << ")" << endl;
                            float read_pcap_use_time = (read_end.tv_sec - read_start.tv_sec) + (double)(read_end.tv_usec - read_start.tv_usec)/1000000.0;
                            cout << "耗费时间: " << read_pcap_use_time << "(s)\t";
                            cout << "读取包数: " << total_packet_num << '\t';
                            cout << "文件大小: " << FileInfo.st_size/1024/1024 << "(MB)\t";
                            cout << "读取速度: " << FileInfo.st_size/1024/1024 / read_pcap_use_time << "(MB/s)" << endl;
                        }
                        read_pcap_map_.insert(make_pair(s, 1));

                        //本线程读取完毕,等待其他线程交出令牌
                        while(!m_Stop && *(m_WorkerConfig.token) != m_Stats.WorkerId) {
                            usleep(1);
                        }

                        //本线程获取令牌,开始发包
                        for(auto it:raw_packet_vector_vector){
                            if(!m_Stop)
                                sendPacketsTo->sendPackets(*it);
                            it->clear();
                            delete it;
                            it = nullptr;
                        }
                        raw_packet_vector_vector.clear();
                        //发包结束,统计信息

                        //本线程发包结束,交出令牌
                        ++*(m_WorkerConfig.token) %= m_WorkerConfig.readCoreNum;
                        reader.close();
                        break;
                    }

                    //将rawPacketVector放入vector
                    raw_packet_vector_vector.push_back(rawPacketVector);
                }

                //收到终止信号
                if(m_Stop){
                    for(auto it:raw_packet_vector_vector){
                        it->clear();
                        delete it;
                        it = nullptr;
                    }
                    raw_packet_vector_vector.clear();
                    reader.close();
                    return true;
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
