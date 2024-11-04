package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"sync"
)

// PacketInfo 用于存储捕获到的数据包信息
type PacketInfo struct {
	SrcIP    string
	DstIP    string
	SrcPort  string
	DstPort  string
	Protocol string
	Data     string
}

// PacketCapture 用于抓取和处理网络流量
type PacketCapture struct {
	handle *pcap.Handle
	stop   chan struct{}
	wg     sync.WaitGroup
}

func NewPacketCapture(interfaceName string) (*PacketCapture, error) {
	handle, err := pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	return &PacketCapture{
		handle: handle,
		stop:   make(chan struct{}),
	}, nil
}

// Start 启动抓包
func (pc *PacketCapture) Start() {
	packetSource := gopacket.NewPacketSource(pc.handle, pc.handle.LinkType())
	for i := 0; i < threadcount; i++ {
		pc.wg.Add(1)
		go pc.packetWorker(packetSource)
	}
}

func (pc *PacketCapture) packetWorker(packetSource *gopacket.PacketSource) {
	defer pc.wg.Done()
	for {
		select {
		case packet := <-packetSource.Packets():
			pc.processPacket(packet)
		case <-pc.stop:
			return
		}
	}
}

// processPacket 处理捕获到的数据包
func (pc *PacketCapture) processPacket(packet gopacket.Packet) {
	var packetInfo PacketInfo

	// 解析网络层信息
	networkLayer := packet.NetworkLayer()
	if networkLayer != nil {
		srcIP := networkLayer.NetworkFlow().Src().String()
		dstIP := networkLayer.NetworkFlow().Dst().String()

		// 解析传输层信息
		transportLayer := packet.TransportLayer()
		if transportLayer != nil {
			protocol := transportLayer.LayerType().String() // 转换为字符串

			if tcpLayer, ok := transportLayer.(*layers.TCP); ok {
				packetInfo = PacketInfo{
					SrcIP:    srcIP,
					DstIP:    dstIP,
					SrcPort:  fmt.Sprintf("%d", tcpLayer.SrcPort), // 转换为字符串
					DstPort:  fmt.Sprintf("%d", tcpLayer.DstPort), // 转换为字符串
					Protocol: protocol,
				}

				// 检查 SYN 标志位
				if tcpLayer.SYN {
					synCheck(packetInfo) // 调用 SYN 检测引擎
				}
			}
		}

		// 获取应用层数据
		if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {
			packetInfo.Data = string(applicationLayer.Payload())
		}

		CheckPackets(packetInfo) // 调用其他检测引擎
	}
}

// Close 关闭抓包句柄
func (pc *PacketCapture) Close() {
	close(pc.stop) // 发送停止信号
	pc.wg.Wait()   // 等待所有 goroutine 完成
	pc.handle.Close()
}
