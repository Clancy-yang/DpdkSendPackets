#pragma once

#include "Packet.h"
#include "DpdkDevice.h"

#include <SystemUtils.h>

#include <string>
#include <map>
#include <vector>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <cstdlib>

using namespace std;

/**
 * 错误退出应用程序的宏
 */

#define EXIT_WITH_ERROR(reason, ...) do { \
	printf("Application terminated in error: " reason "\n", ## __VA_ARGS__); \
	exit(1); \
	} while(0)

#define EXIT_WITH_ERROR_AND_PRINT_USAGE(reason, ...) do { \
	printf("\nError: " reason "\n\n", ## __VA_ARGS__); \
	listDpdkPorts(); \
	exit(1); \
	} while (0)

typedef map<pcpp::DpdkDevice*, vector<int> > InputDataConfig;

struct FileListStruct{
    char file_name[200]{};
    uint8_t * data = nullptr;
};

struct PacketStruct{
    uint64_t readCoreId = 0;
    uint64_t index = 0;
    char pcapName[128]{};
    vector<pcpp::RawPacket*> * rawPacketVector = nullptr;
    pcpp::RawPacketVector * rawPacketVector_ = nullptr;
};


/**
 * 包含工作线程所需的所有配置，包括：
 * - 哪些DPDK端口和哪些RX队列从中接收数据包
 * - 是否将匹配的数据包发送到TX DPDK端口和/或将其保存到pcap文件
 */
struct AppWorkerConfig
{
    //核心id
	uint32_t CoreId;
	//发送数据包的DPDK设备和端口
	pcpp::DpdkDevice* SendPacketsTo;
    uint16_t SendPacketsPort = 0;
	//读文件目录
	string PcapFileDirPath;
	//读文件列表
    string PcapFileListPath;

	AppWorkerConfig():
	CoreId(MAX_NUM_OF_CORES+1),
	SendPacketsTo(nullptr)
	{}
};

//发包配置
struct SendWorkerConfig{
    //核心id
    uint32_t CoreId;
    //发送数据包的DPDK设备和端口
    pcpp::DpdkDevice* SendPacketsTo;
    uint16_t SendPacketsPort;
    //读pcap包核心数
    uint16_t ReadPcapCoreNum = 0;
    //构造
    SendWorkerConfig():
    CoreId(MAX_NUM_OF_CORES+1),
    SendPacketsTo(nullptr),
    SendPacketsPort(0)
    {};
    SendWorkerConfig(uint32_t CoreId,pcpp::DpdkDevice* SendPacketsTo,uint16_t SendPacketsPort):
    CoreId(CoreId),SendPacketsTo(SendPacketsTo),SendPacketsPort(SendPacketsPort)
    {};
};

//读包配置
struct ReadWorkConfig{
//核心id
    uint32_t CoreId;
    //文件名称列表
    vector<string> pcapFileNameVecter;
    //读pcap包核心数
    uint16_t readPcapCoreNum = 0;
    //构造
    explicit ReadWorkConfig():
    CoreId(MAX_NUM_OF_CORES+1)
    {}
    ReadWorkConfig(const uint32_t CoreId,uint16_t readPcapCoreNum):
    CoreId(CoreId),
    readPcapCoreNum(readPcapCoreNum)
    {}
};


/**
 * 收集和分析数据包和流量统计
 */
struct PacketStats
{
public:
	uint8_t WorkerId;

	// 根据读取信息统计
	uint64_t sendAllPacketNum = 0;      // 发送总包数
	uint64_t sendAllDataNum = 0;        // 发送总数据量
	uint64_t sendSuccessPacketNum = 0;  // 发包成功数
	uint64_t sendErrorPacketNum = 0;    // 发包失败数
	uint64_t sendSuccessDataNum = 0;    // 发包成功数据量
	uint64_t sendErrorDataNum = 0;      // 发包失败数据量

	// 根据网卡信息统计
	uint64_t sendPacketCount = 0;       // 传输包数
	uint64_t sendDataCount = 0;         // 传输数据量

	// ring和mempool信息
	uint64_t ringSendPacketNum = 0;     // 通过ring发送的包数
	uint64_t ringSendDataNum = 0;       // 通过ring发送的数据量
	uint64_t ringReceivePacketNum = 0;  // 通过ring接收的包数
	uint64_t ringReceiveDataNum = 0;    // 通过ring接收的数据量
	uint64_t ringFullLosePacketNum = 0; // 因ring满导致丢包数
	uint64_t ringFullLoseDataNum = 0;   // 因ring满导致丢失数据量
	uint64_t mempoolFullLosePacketNum = 0;  // 因mempool满导致丢失包数
	uint64_t mempoolFullLoseDataNum = 0;    // 因mempool满导致丢失数据量

	PacketStats() : WorkerId(MAX_NUM_OF_CORES+1){}

	void collectStats(PacketStats& stats)
	{
        sendAllPacketNum += stats.sendAllPacketNum;
        sendAllDataNum += stats.sendAllDataNum;

        sendSuccessPacketNum += stats.sendSuccessPacketNum;
        sendErrorPacketNum += stats.sendErrorPacketNum;
        sendSuccessDataNum += stats.sendSuccessDataNum;
        sendErrorDataNum += stats.sendErrorDataNum;

        sendPacketCount += stats.sendPacketCount;
        sendDataCount += stats.sendDataCount;
	}

	void clear() {
	    WorkerId = MAX_NUM_OF_CORES+1;
        sendAllPacketNum = 0;
        sendAllDataNum = 0;
        sendSuccessPacketNum = 0;
        sendErrorPacketNum = 0;
        sendSuccessDataNum = 0;
        sendErrorDataNum = 0;
        sendPacketCount = 0;
        sendDataCount = 0;
	}

	[[nodiscard]] std::string getStatValuesAsString(const std::string& delimiter) const
	{
		std::stringstream values;
		values << sendAllPacketNum << delimiter;
        values << sendSuccessPacketNum << delimiter;
        values << sendErrorPacketNum << delimiter;
        values << (double)sendAllDataNum / 1024 / 1024 / 1024 << delimiter;
        values << (double)sendDataCount / 1024 / 1024 / 1024 << delimiter;
        values << ((double)sendDataCount / (double)sendAllDataNum) * 100 << delimiter;

		return values.str();
	}

	static void getStatsColumns(std::vector<std::string>& columnNames, std::vector<int>& columnWidths)
	{
		columnNames.clear();
		columnWidths.clear();

		columnNames.emplace_back("全部发送数据包数");
        columnNames.emplace_back("发送成功数据包数");
        columnNames.emplace_back("发送失败数据包数");
        columnNames.emplace_back("读取数据量(GB)");
        columnNames.emplace_back("传输数据量(GB)");
        columnNames.emplace_back("成功率(%)");

		columnWidths.push_back(16);
        columnWidths.push_back(16);
        columnWidths.push_back(16);
        columnWidths.push_back(14);
        columnWidths.push_back(14);
        columnWidths.push_back(9);
	}
};
