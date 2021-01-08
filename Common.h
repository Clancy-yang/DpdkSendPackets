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
	//接收数据包的DPDK设备列表
	InputDataConfig InDataCfg;
	//发送数据包的DPDK设备
	pcpp::DpdkDevice* SendPacketsTo;
	//是否将匹配到的包写入文件
	bool WriteMatchedPacketsToFile;
	//写文件路径
	string PathToWritePackets;

	AppWorkerConfig():
	CoreId(MAX_NUM_OF_CORES+1),
	SendPacketsTo(nullptr),
	WriteMatchedPacketsToFile(false)
	{}
};


/**
 * 收集和分析数据包和流量统计
 */
struct PacketStats
{
public:
	uint8_t WorkerId;

	int PacketCount;
	int EthCount;
	int ArpCount;
	int Ip4Count;
	int Ip6Count;
	int TcpCount;
	int UdpCount;
	int HttpCount;

	int MatchedTcpFlows;
	int MatchedUdpFlows;
	int MatchedPackets;

	PacketStats() : WorkerId(MAX_NUM_OF_CORES+1), PacketCount(0), EthCount(0), ArpCount(0), Ip4Count(0), Ip6Count(0), TcpCount(0), UdpCount(0), HttpCount(0), MatchedTcpFlows(0), MatchedUdpFlows(0), MatchedPackets(0) {}

	void collectStats(pcpp::Packet& packet)
	{
		PacketCount++;
		if (packet.isPacketOfType(pcpp::Ethernet))
			EthCount++;
		if (packet.isPacketOfType(pcpp::ARP))
			ArpCount++;
		if (packet.isPacketOfType(pcpp::IPv4))
			Ip4Count++;
		if (packet.isPacketOfType(pcpp::IPv6))
			Ip6Count++;
		if (packet.isPacketOfType(pcpp::TCP))
			TcpCount++;
		if (packet.isPacketOfType(pcpp::UDP))
			UdpCount++;
		if (packet.isPacketOfType(pcpp::HTTP))
			HttpCount++;
	}

	void collectStats(PacketStats& stats)
	{
		PacketCount += stats.PacketCount;
		EthCount += stats.EthCount;
		ArpCount += stats.ArpCount;
		Ip4Count += stats.Ip4Count;
		Ip6Count += stats.Ip6Count;
		TcpCount += stats.TcpCount;
		UdpCount += stats.UdpCount;
		HttpCount += stats.HttpCount;

		MatchedTcpFlows += stats.MatchedTcpFlows;
		MatchedUdpFlows += stats.MatchedUdpFlows;
		MatchedPackets += stats.MatchedPackets;
	}

	//void clear() { WorkerId = MAX_NUM_OF_CORES+1; PacketCount = 0; EthCount = 0; ArpCount = 0; Ip4Count = 0; Ip6Count = 0; TcpCount = 0; UdpCount = 0; HttpCount = 0; MatchedTcpFlows = 0; MatchedUdpFlows = 0; MatchedPackets = 0; }

	[[nodiscard]] std::string getStatValuesAsString(const std::string& delimiter) const
	{
		std::stringstream values;
		if (WorkerId == MAX_NUM_OF_CORES+1)
			values << "Total" << delimiter;
		else
			values << (int)WorkerId << delimiter;
		values << PacketCount << delimiter;
		values << EthCount << delimiter;
		values << ArpCount << delimiter;
		values << Ip4Count << delimiter;
		values << Ip6Count << delimiter;
		values << TcpCount << delimiter;
		values << UdpCount << delimiter;
		values << HttpCount << delimiter;
		values << MatchedTcpFlows << delimiter;
		values << MatchedUdpFlows << delimiter;
		values << MatchedPackets;

		return values.str();
	}

	static void getStatsColumns(std::vector<std::string>& columnNames, std::vector<int>& columnWidths)
	{
		columnNames.clear();
		columnWidths.clear();

	    static const int narrowColumnWidth = 11;
	    static const int wideColumnWidth = 18;

		columnNames.emplace_back("Core ID");
		columnNames.emplace_back("Packet Cnt");
		columnNames.emplace_back("Eth Cnt");
		columnNames.emplace_back("ARP Cnt");
		columnNames.emplace_back("IPv4 Cnt");
		columnNames.emplace_back("IPv6 Cnt");
		columnNames.emplace_back("TCP Cnt");
		columnNames.emplace_back("UDP Cnt");
		columnNames.emplace_back("HTTP Cnt");
		columnNames.emplace_back("Matched TCP Flows");
		columnNames.emplace_back("Matched UDP Flows");
		columnNames.emplace_back("Matched Packets");

		columnWidths.push_back(7);
		columnWidths.push_back(narrowColumnWidth);
		columnWidths.push_back(narrowColumnWidth);
		columnWidths.push_back(narrowColumnWidth);
		columnWidths.push_back(narrowColumnWidth);
		columnWidths.push_back(narrowColumnWidth);
		columnWidths.push_back(narrowColumnWidth);
		columnWidths.push_back(narrowColumnWidth);
		columnWidths.push_back(narrowColumnWidth);
		columnWidths.push_back(wideColumnWidth);
		columnWidths.push_back(wideColumnWidth);
		columnWidths.push_back(wideColumnWidth);

	}
};
