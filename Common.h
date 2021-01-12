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
    //构造
    ReadWorkConfig():
    CoreId(MAX_NUM_OF_CORES+1)
    {};
    ReadWorkConfig(uint32_t CoreId,const vector<string> &pcapFileNameVecter):
    CoreId(CoreId),
    pcapFileNameVecter(pcapFileNameVecter)
    {};
};


/**
 * 收集和分析数据包和流量统计
 */
struct PacketStats
{
public:
	uint8_t WorkerId;

    uint64_t PacketCount = 0;
    uint64_t sendSuccess_ = 0;//包数
	uint64_t sendError_ = 0;
	uint64_t send_success_number_ = 0;//数据量
	uint64_t total_number_ = 0;

	PacketStats() : WorkerId(MAX_NUM_OF_CORES+1), PacketCount(0){}



	void collectStats(PacketStats& stats)
	{
		PacketCount += stats.PacketCount;
        sendSuccess_ += stats.sendSuccess_;
        sendError_ += stats.sendError_;
        send_success_number_ += stats.send_success_number_;
        total_number_ += stats.total_number_;
	}

	//void clear() { WorkerId = MAX_NUM_OF_CORES+1; PacketCount = 0; EthCount = 0; ArpCount = 0; Ip4Count = 0; Ip6Count = 0; TcpCount = 0; UdpCount = 0; HttpCount = 0; MatchedTcpFlows = 0; MatchedUdpFlows = 0; MatchedPackets = 0; }

	[[nodiscard]] std::string getStatValuesAsString(const std::string& delimiter) const
	{
		std::stringstream values;
//		if (WorkerId == MAX_NUM_OF_CORES+1)
//			values << "Total" << delimiter;
//		else
//			values << (int)WorkerId << delimiter;
		values << PacketCount << delimiter;
        values << sendSuccess_ << delimiter;
        values << sendError_ << delimiter;
        values << (double)total_number_ / 1024 / 1024 / 1024 << delimiter;
        values << (double)send_success_number_ / 1024 / 1024 / 1024 << delimiter;
        values << ((double)send_success_number_ / (double)total_number_) * 100 << delimiter;

		return values.str();
	}

	static void getStatsColumns(std::vector<std::string>& columnNames, std::vector<int>& columnWidths)
	{
		columnNames.clear();
		columnWidths.clear();

		columnNames.emplace_back("  总发送数据包数  ");
        columnNames.emplace_back(" 发送成功数据包数 ");
        columnNames.emplace_back(" 发送失败数据包数 ");
        columnNames.emplace_back("全部数据量(GB)");
        columnNames.emplace_back("成功数据量(GB)");
        columnNames.emplace_back(" 成功率(%) ");

		columnWidths.push_back(18);
        columnWidths.push_back(18);
        columnWidths.push_back(18);
        columnWidths.push_back(14);
        columnWidths.push_back(14);
        columnWidths.push_back(11);
	}
};
