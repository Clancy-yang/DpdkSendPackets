#pragma once

#include "Common.h"
#include "PacketMatchingEngine.h"

#include "PacketUtils.h"
#include "DpdkDevice.h"
#include "DpdkDeviceList.h"
#include "PcapFileDevice.h"

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
    map<uint32_t, bool> m_FlowTable;

    uint32_t m_CoreId;
	AppWorkerConfig& m_WorkerConfig;
	PacketMatchingEngine& m_PacketMatchingEngine;
public:
	AppWorkerThread(AppWorkerConfig& workerConfig, PacketMatchingEngine& matchingEngine) :
	    m_Stop(true), m_CoreId(MAX_NUM_OF_CORES+1), m_WorkerConfig(workerConfig),
		m_PacketMatchingEngine(matchingEngine){}

	~AppWorkerThread() override = default;// do nothing

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
		pcpp::DpdkDevice* sendPacketsTo = m_WorkerConfig.SendPacketsTo;
		pcpp::PcapFileWriterDevice* pcapWriter = nullptr;

		//如果需要，创建pcap文件写入器，所有匹配的数据包都将写入其中
		if (m_WorkerConfig.WriteMatchedPacketsToFile)
		{
			pcapWriter = new pcpp::PcapFileWriterDevice(m_WorkerConfig.PathToWritePackets.c_str());
			if (!pcapWriter->open()) EXIT_WITH_ERROR("Couldn't open pcap writer device");
		}

		//如果未将DPDK设备分配给该工作线程/核心，请不要进入主循环并退出
		if (m_WorkerConfig.InDataCfg.empty()) return true;

		#define MAX_RECEIVE_BURST 64
		pcpp::MBufRawPacket* packetArr[MAX_RECEIVE_BURST] = {};

		//主循环，运行直到被告知停止
		while (!m_Stop)
		{
			//查看为此工作线程/核心配置的所有DPDK设备
			for (auto & iter : m_WorkerConfig.InDataCfg)
			{
				//对于每个DPDK设备，请遍历为此工作线程/核心配置的所有RX队列
				for (auto iter2 = iter.second.begin(); iter2 != iter.second.end(); iter2++)
				{
					pcpp::DpdkDevice* dev = iter.first;

					//从指定的DPDK设备和RX队列上的网络接收数据包
					uint16_t packetsReceived = dev->receivePackets(packetArr, MAX_RECEIVE_BURST, *iter2);

					for (int i = 0; i < packetsReceived; i++)
					{
						//解析数据包
						pcpp::Packet parsedPacket(packetArr[i]);

						//收集数据包统计信息
						m_Stats.collectStats(parsedPacket);

						//数据包是否匹配上
						bool packetMatched;

						//用五元组对数据包进行散列，然后在流表中查看该数据包是属于现有流还是新流
						uint32_t hash = pcpp::hash5Tuple(&parsedPacket);
						auto iter3 = m_FlowTable.find(hash);

						//如果数据包属于一个已经存在的流
						if (iter3 != m_FlowTable.end() && iter3->second)
						{
							packetMatched = true;
						}
						else //数据包属于新流
						{
						    //数据包根据条件进行匹配
							packetMatched = m_PacketMatchingEngine.isMatched(parsedPacket);
							if (packetMatched)
							{
								//将新流程放入流表
								m_FlowTable[hash] = true;

								//收集统计数据
								if (parsedPacket.isPacketOfType(pcpp::TCP))
								{
									m_Stats.MatchedTcpFlows++;
								}
								else if (parsedPacket.isPacketOfType(pcpp::UDP))
								{
									m_Stats.MatchedUdpFlows++;
								}

							}
						}

						if (packetMatched)
						{
							// 如果需要，将数据包发送到TX端口
							if (sendPacketsTo != nullptr)
							{
								sendPacketsTo->sendPacket(*packetArr[i], 0);
							}

							// 如果需要，将数据包保存到文件
							if (pcapWriter != nullptr)
							{
								pcapWriter->writePacket(*packetArr[i]);
							}

							m_Stats.MatchedPackets++;
						}
					}
				}
			}
		}

		// free packet array (frees all mbufs as well)
		for (auto & i : packetArr)
		{
		    delete i;
		    i = nullptr;
		}

		//关闭并删除pcap文件编写器
		delete pcapWriter;
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
