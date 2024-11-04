package main

import "fmt"

func init() {

}

var sidCounter = 10000

// CreateSnortRule 创建Snort规则
func CreateSnortRule(srcIP, srcPort, destIP, destPort, protocolType, logType, attackType string) string {
	if srcIP == "" {
		srcIP = "any"
	}
	if srcPort == "" {
		srcPort = "any"
	}
	if destIP == "" {
		destIP = "any"
	}
	if destPort == "" {
		destPort = "any"
	}
	if protocolType == "" {
		protocolType = "TCP"
	}
	if logType == "" {
		logType = "log"
	}
	sidCounter++
	return fmt.Sprintf("%s %s %s %s -> %s %s (msg:\"%s detected\"; sid:%d;)", logType, protocolType, srcIP, srcPort, destIP, destPort, attackType, sidCounter)
}
