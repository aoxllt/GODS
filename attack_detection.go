package main

import (
	"fmt"
	"fyne.io/fyne/v2/dialog"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	portScanThreshold    = 1300
	timeWindow           = 10 * time.Second // 时间窗口
	ipPortFlag           = make(map[string]bool)
	ipPortAttempts       = make(map[string]int)
	ipPortTimestamp      = make(map[string]time.Time)
	mu                   sync.Mutex
	synFloodThreshold    = 500
	synFloodAttempts     = make(map[string]int)
	synFloodTimestamp    = make(map[string]time.Time)
	synFloodFlag         = make(map[string]bool)
	bruteForceThreshold  = 30                         // 设定的阈值
	bruteForceAttempts   = make(map[string]int)       // 存储尝试次数
	bruteForceTimestamp  = make(map[string]time.Time) // 存储时间戳
	bruteForceFlag       = make(map[string]bool)
	bruteForceTimeWindow = 10 * time.Second // 时间窗口
	doSThreshold         = 2000             // 设定的阈值
	doSAttempts          = make(map[string]int)
	doSTimestamp         = make(map[string]time.Time)
	doSTimeWindow        = 10 * time.Second // 时间窗口
	doSFlag              = make(map[string]bool)
	injectionPatterns    = []string{
		`(?i);`,                 // 分号
		`(?i)&&`,                // 逻辑与
		`(?i)\|\|`,              // 逻辑或，修正了这里
		`(?i)\|`,                // 管道符
		`(?i)<`,                 // 输入重定向
		`(?i)>`,                 // 输出重定向
		`(?i)\$`,                // 变量
		`(?i)` + `[^a-zA-Z0-9]`, // 其他可疑字符，添加了匹配非字母和数字的部分
	}
	alerts []string
)

// Rule 结构体表示一个 Snort 规则
type Rule struct {
	Description string
	SrcIP       string
	DstIP       string
	SrcPort     string
	DstPort     string
	Protocol    string
	AttackType  string
	Priority    int
}

var matchrules []Rule

// RuleManager 用于管理规则的加载和更新
type RuleManager struct {
	mu       sync.RWMutex
	stopChan chan struct{}
}

func LogAlert(message string) {
	alerts = append(alerts, message)
	alertList.Refresh()
	if err := writeLog(message); err != nil {
		return
	}
	if strings.Contains(message, "Alert") {
		dialog.NewInformation("警报", message, w).Show()
		fmt.Print("\a")
	}
}

func writeLog(message string) error {
	file, err := os.OpenFile("日志.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	// 写入日志内容
	_, err = file.WriteString(fmt.Sprintf("%s\n", message))
	return err
}

// NewRuleManager 创建一个新的规则管理器
func NewRuleManager() *RuleManager {
	return &RuleManager{
		stopChan: make(chan struct{}),
	}
}

// LoadRules 从文件中加载规则
func (rm *RuleManager) LoadRules(globalRules *[]string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	matchrules = nil // 清空现有规则
	for _, line := range *globalRules {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r, err := parseRules(line)
		if err != nil {
			log.Fatal(err)
		}
		matchrules = append(matchrules, r)
	}

	sort.Slice(matchrules, func(i, j int) bool {
		return matchrules[i].Priority > matchrules[j].Priority
	})

}

// parseRules 解析 Snort 规则行
func parseRules(line string) (Rule, error) {
	var r Rule
	// 使用 Sscanf 解析行，并确保字段传入地址
	_, _ = fmt.Sscanf(line, "%s %s %s %s -> %s %s (msg:\"%s \";)",
		&r.Description, &r.Protocol, &r.SrcIP, &r.SrcPort, &r.DstIP, &r.DstPort, &r.AttackType)

	anyCount := 0
	if r.SrcIP == "any" {
		anyCount++
	}
	if r.DstIP == "any" {
		anyCount++
	}
	if r.SrcPort == "any" {
		anyCount++
	}
	if r.DstPort == "any" {
		anyCount++
	}
	if strings.Contains(r.Description, "alert") {
		r.Priority = 2
	} else if strings.Contains(r.Description, "log") {
		r.Priority = 1 // 较低优先级
	}
	r.Priority += anyCount
	return r, nil
}

// Start 运行协程定期加载规则
func (rm *RuleManager) Start(r *[]string, interval time.Duration) {
	go func() {
		for {
			select {
			case <-time.After(interval):
				rm.LoadRules(r)
			case <-rm.stopChan:
				return
			}
		}
	}()
}

// Stop 停止规则加载
func (rm *RuleManager) Stop() {
	select {
	case <-rm.stopChan:
		return
	default:
		close(rm.stopChan)
	}
}

func Match(rule Rule, packet PacketInfo) (bool, string) {
	res := (rule.SrcIP == packet.SrcIP || rule.SrcIP == "any") &&
		(rule.DstIP == packet.DstIP || rule.DstIP == "any") &&
		(rule.SrcPort == packet.SrcPort || rule.SrcPort == "any") &&
		(rule.DstPort == packet.DstPort || rule.DstPort == "any") &&
		(rule.Protocol == packet.Protocol || rule.Protocol == "any")

	attacktype := rule.AttackType
	return res, attacktype
}

func CheckPackets(packet PacketInfo) {
	for _, rule := range matchrules {
		res, attacktype := Match(rule, packet)
		if res {
			//todo 匹配规则
			switch attacktype {
			case "端口扫描":
				detectPortScan(packet, rule.Description)
			case "拒绝服务攻击":
				DoSCheck(packet, rule.Description)
			case "命令注入":
				CommandInjectionCheck(packet, rule.Description)
			case "口令爆破":
				BruteForceCheck(packet, rule.Description)
			}
		}
	}
}

// 端口扫描检测
func detectPortScan(packet PacketInfo, description string) {
	mu.Lock()
	defer mu.Unlock()

	key := fmt.Sprintf("%s:%s", packet.SrcIP, packet.DstIP)
	currentTime := time.Now()

	if lastTime, exists := ipPortTimestamp[key]; exists && currentTime.Sub(lastTime) <= timeWindow {
		if !ipPortFlag[key] { // 如果在时间窗口内没有记录过
			ipPortAttempts[key]++
		}
	} else {
		//重置
		ipPortFlag[key] = false
		ipPortAttempts[key] = 1
		ipPortTimestamp[key] = currentTime
	}

	if ipPortAttempts[key] > portScanThreshold && ipPortFlag[key] == false {
		ipPortFlag[key] = true
		if description == "alert" {
			LogAlert(fmt.Sprintf("Alert: 可能存在端口扫描，源IP: %s, 目标IP: %s;数据内容: %s\n", packet.SrcIP, packet.DstIP, packet.Data))
		} else {
			LogAlert(fmt.Sprintf("Log: 可能存在端口扫描，源IP: %s, 目标IP: %s;数据内容: %s\n", packet.SrcIP, packet.DstIP, packet.Data))
		}

	}
}

// syn洪泛检测
func synCheck(packet PacketInfo) {
	mu.Lock()
	defer mu.Unlock()

	for _, rule := range matchrules {
		if rule.AttackType == "SYN洪泛" {
			if rule.DstIP != packet.DstIP && rule.DstIP != "any" {
				continue
			}
			key := packet.SrcIP
			currentTime := time.Now()

			if lastTime, exists := synFloodTimestamp[key]; exists && currentTime.Sub(lastTime) <= timeWindow {
				if !synFloodFlag[key] {
					synFloodAttempts[key]++
				}
			} else {
				synFloodFlag[key] = false
				synFloodAttempts[key] = 1
				synFloodTimestamp[key] = currentTime
			}

			if synFloodAttempts[key] > synFloodThreshold && synFloodFlag[key] == false {
				synFloodFlag[key] = true
				if rule.Description == "log" {
					LogAlert(fmt.Sprintf("Log: 可能存在 SYN 洪泛攻击，源IP: %s;数据内容: %s\n", packet.SrcIP, packet.Data))
				} else {
					LogAlert(fmt.Sprintf("Alert: 可能存在 SYN 洪泛攻击，源IP: %s;数据内容: %s\n", packet.SrcIP, packet.Data))
				}
			}
			break
		}
	}
}

// DoSCheck Dos攻击检测
func DoSCheck(packet PacketInfo, description string) {
	mu.Lock()
	defer mu.Unlock()

	key := packet.SrcIP
	currentTime := time.Now()

	if lastTime, exists := doSTimestamp[key]; exists && currentTime.Sub(lastTime) <= doSTimeWindow {
		if !doSFlag[key] {
			doSAttempts[key]++
		}
	} else {
		doSFlag[key] = false
		doSAttempts[key] = 1
		doSTimestamp[key] = currentTime
	}

	if doSAttempts[key] > doSThreshold && doSFlag[key] == false {
		doSFlag[key] = true
		if description == "log" {
			LogAlert(fmt.Sprintf("Log: 可能存在拒绝服务攻击，源IP: %s;数据内容: %s\n", packet.SrcIP, packet.Data))
		} else {
			LogAlert(fmt.Sprintf("Alert: 可能存在拒绝服务攻击，源IP: %s;数据内容: %s\n", packet.SrcIP, packet.Data))
		}

	}
}

// CommandInjectionCheck 命令注入检测
func CommandInjectionCheck(packet PacketInfo, description string) {
	for _, pattern := range injectionPatterns {
		re := regexp.MustCompile(pattern)
		if re.FindString(packet.Data) != "" {
			if description == "log" {
				LogAlert(fmt.Sprintf("Log: 可能存在命令注入攻击，源IP: %s, 数据: %s\n", packet.SrcIP, packet.Data))
			} else {
				LogAlert(fmt.Sprintf("Alert: 可能存在命令注入攻击，源IP: %s, 数据: %s\n", packet.SrcIP, packet.Data))
			}
			return
		}
	}
}

// BruteForceCheck 口令爆破攻击检测
func BruteForceCheck(packet PacketInfo, description string) {
	mu.Lock()
	defer mu.Unlock()

	username := parseUsernameFromPayload(packet.Data)
	if username == "" {
		return
	}
	key := fmt.Sprintf("%s_%s", username, packet.SrcIP)
	currentTime := time.Now()

	if lastTime, exists := bruteForceTimestamp[key]; exists && currentTime.Sub(lastTime) <= bruteForceTimeWindow {
		if !bruteForceFlag[key] {
			bruteForceAttempts[key]++
		}
	} else {
		bruteForceFlag[key] = false
		bruteForceAttempts[key] = 1
		bruteForceTimestamp[key] = currentTime
	}

	if bruteForceAttempts[key] > bruteForceThreshold && bruteForceFlag[key] == false {
		bruteForceFlag[key] = true
		if description == "log" {
			LogAlert(fmt.Sprintf("Log: 可能存在口令爆破攻击，用户: %s, 源IP: %s;数据内容: %s\n", packet.SrcIP, packet.DstIP, packet.Data))
		} else {
			LogAlert(fmt.Sprintf("Alert: 可能存在口令爆破攻击，用户: %s, 源IP: %s;数据内容: %s\n", packet.SrcIP, packet.DstIP, packet.Data))
		}
	}
}

// parseUsernameFromPayload 从数据包负载中解析用户名
func parseUsernameFromPayload(data string) string {
	payload := data
	// 查找用户名字段
	startIndex := strings.Index(payload, "username=")
	if startIndex == -1 {
		return "" // 如果没有找到，则返回空字符串
	}

	// 提取用户名
	startIndex += len("username=")
	endIndex := strings.IndexByte(payload[startIndex:], '&')
	if endIndex == -1 {
		endIndex = len(payload) // 如果没有找到下一个 '&'，取到结尾
	} else {
		endIndex += startIndex // 修正索引
	}

	username := payload[startIndex:endIndex]
	return username
}
