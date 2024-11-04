package main

import (
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"image/color"
	"log"
	"strings"
	"time"
)

// 攻击类型选项
var attackTypes = []string{"端口扫描", "口令爆破", "SYN洪泛", "拒绝服务攻击", "命令注入"}

var selectedIndex = -1
var threadcount = 1
var (
	pc, _       = NewPacketCapture("\\Device\\NPF_{2FC7F6EA-3C95-4161-8111-B19A26C1F6BD}")
	rm          = NewRuleManager()
	isRunning   bool // 记录当前状态
	startButton *widget.Button
	endButton   *widget.Button
)

type ParsedRule struct {
	srcIP      string
	srcPort    string
	destIP     string
	destPort   string
	protocol   string
	logType    string
	attackType string
}

// 全局变量，用于输入框
var (
	srcIPEntry, srcPortEntry, destIPEntry, destPortEntry *widget.Entry
	protocolType                                         *widget.Select
	logTypeEntry                                         *widget.Select
	rules                                                []string
)

var alertList = widget.NewList(
	func() int {
		return len(alerts)
	},
	func() fyne.CanvasObject {
		return canvas.NewText("", color.NRGBA{A: 0xff}) // 默认文本颜色
	},
	func(i int, o fyne.CanvasObject) {
		msg := alerts[i]
		text := o.(*canvas.Text)

		// 检查消息是否包含 "Alert"，如果是，则设置为红色
		if strings.Contains(msg, "Alert") {
			text.Text = msg
			text.Color = color.NRGBA{R: 0xff, A: 0xff} // 红色
			text.TextSize = 14
		} else {
			text.Text = msg
			text.Color = color.NRGBA{R: 0xff, G: 0xff, B: 0xff, A: 0xff}
			text.TextSize = 14
		}

		text.Refresh() // 刷新以应用颜色更改
	},
)

var (
	a = app.New()
	w = a.NewWindow("IDS入侵检测系统")
)

// 启动 GUI
func startGUI() fyne.Window {
	iconData, err := idsPng()
	if err != nil {
		log.Fatal(err)
	}
	var icon = &fyne.StaticResource{
		StaticName:    "icon.png",
		StaticContent: iconData.bytes,
	}
	w.SetIcon(icon)

	// 规则区
	ruleList := widget.NewList(
		func() int {
			return len(rules)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(i int, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(rules[i])
		},
	)

	ruleList.OnSelected = func(id int) {
		selectedIndex = id

	}

	alertContainer := container.NewScroll(alertList)
	alertContainer.SetMinSize(fyne.NewSize(400, 200))
	// 使用容器来控制规则区域的大小
	scrollContainer := container.NewScroll(ruleList)
	scrollContainer.SetMinSize(fyne.NewSize(400, 200))

	// 创建选择框用于选择攻击类型
	attackSelect := widget.NewSelect(attackTypes, func(selected string) {
		selectOption(selected, w, a)
	})

	attackSelect.PlaceHolder = "检测攻击选择"

	delButton := widget.NewButton("删除规则", func() {
		delRules(ruleList)
	})

	changeButton := widget.NewButton("修改规则", func() {
		if selectedIndex >= 0 {
			changeRules(selectedIndex, a)
		} else {
			dialog.NewInformation("提示", "请先选择要修改的规则", w).Show()
		}
	})
	startButton = widget.NewButton("   开始   ", func() {
		startIDS()
	})
	endButton = widget.NewButton("   结束   ", func() {
		endIDS()
	})
	endButton.Disable()

	clearButton := widget.NewButton("清空日志", func() {
		alerts = []string{}
		alertList.Refresh()
	})

	threadswtich := widget.NewCheck("使用多线程", func(b bool) {
		if b {
			threadcount = 10
		} else {
			threadcount = 1
		}
	})
	// 布局
	content := container.New(layout.NewVBoxLayout(),
		alertContainer,
		attackSelect,
		scrollContainer,
		container.NewHBox(
			endButton,
			changeButton,
			delButton,
			startButton,
			clearButton,
			threadswtich,
		),
	)
	w.SetContent(content)
	// 设置退出按钮
	w.SetCloseIntercept(func() {
		dialog.NewConfirm("退出", "您确定要退出吗？", func(b bool) {
			if b {
				a.Quit()
			}
		}, w).Show()
	})

	// 启动协程定时更新规则显示
	go func() {
		ticker := time.NewTicker(1 * time.Second) // 每秒更新一次
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ruleList.Refresh() // 更新规则显示区
			}
		}
	}()

	w.Resize(fyne.NewSize(400, 400))
	return w
}

func delRules(ruleList *widget.List) {
	if selectedIndex >= 0 && selectedIndex < len(rules) {
		rules = append(rules[:selectedIndex], rules[selectedIndex+1:]...)
		selectedIndex = -1 // 重置选中索引
		ruleList.Refresh() // 刷新列表以显示更新后的规则
	}
}

func changeRules(index int, a fyne.App) {
	nw := a.NewWindow("修改规则")

	// 创建输入字段
	srcIPEntry = widget.NewEntry()
	srcPortEntry = widget.NewEntry()
	destIPEntry = widget.NewEntry()
	destPortEntry = widget.NewEntry()
	protocolType = widget.NewSelect([]string{"TCP", "UDP"}, func(s string) {})
	logTypeEntry = widget.NewSelect([]string{"log", "alert"}, func(selected string) {})

	// 填充输入框
	parsed := parseRule(rules[index])
	srcIPEntry.SetText(parsed.srcIP)
	srcPortEntry.SetText(parsed.srcPort)
	destIPEntry.SetText(parsed.destIP)
	destPortEntry.SetText(parsed.destPort)
	protocolType.SetSelected(parsed.protocol)
	logTypeEntry.SetSelected(parsed.logType)
	attackType := parsed.attackType

	updatePlaceholders(attackType, srcIPEntry, srcPortEntry, destIPEntry, destPortEntry)

	// 确认按钮
	confirmButton := widget.NewButton("确认", func() {
		// 获取输入值
		srcIP := srcIPEntry.Text
		srcPort := srcPortEntry.Text
		destIP := destIPEntry.Text
		destPort := destPortEntry.Text
		protocol := protocolType.Selected
		logType := logTypeEntry.Selected

		// 创建Snort规则
		rule := CreateSnortRule(srcIP, srcPort, destIP, destPort, protocol, logType, attackType)

		// 检查规则是否已存在（排除当前规则）
		if containsRule(rule) && rules[index] != rule {
			dialog.NewInformation("提示", "规则已存在，请勿重复输入", nw).Show()
			return
		}

		// 更新规则列表中的选中规则
		rules[index] = rule

		dialog.NewInformation("更新成功", "规则已更新", nw).Show()
		nw.Close() // 关闭新窗口
	})

	nw.SetContent(container.New(layout.NewVBoxLayout(),
		srcIPEntry,
		srcPortEntry,
		destIPEntry,
		destPortEntry,
		protocolType,
		logTypeEntry,
		confirmButton, // 添加确认按钮
	))

	nw.Resize(fyne.NewSize(300, 250)) // 设置新窗口大小
	nw.Show()                         // 显示新窗口
}

func parseRule(rule string) ParsedRule {
	var parsed ParsedRule
	var msg string // 用于接收消息部分

	// 示例解析：根据你的规则格式解析
	_, _ = fmt.Sscanf(rule, "%s %s %s %s -> %s %s (msg:\"%s detected\"; sid:%d;)",
		&parsed.logType, &parsed.protocol, &parsed.srcIP, &parsed.srcPort, &parsed.destIP, &parsed.destPort, &msg)

	// 提取攻击类型
	if len(msg) > 0 {
		parsed.attackType = strings.TrimSpace(strings.Split(msg, " ")[0]) // 根据你的规则格式修改
	}

	return parsed
}
func startIDS() {
	if isRunning {
		return
	}
	isRunning = true
	startButton.Disable()
	endButton.Enable()
	var err error
	pc, err = NewPacketCapture("\\Device\\NPF_{2FC7F6EA-3C95-4161-8111-B19A26C1F6BD}")
	if err != nil {
		log.Fatalf("Error creating PacketCapture: %v", err)
	}
	go pc.Start()
	go rm.Start(&rules, 1*time.Second)
}

func endIDS() {
	if !isRunning {
		return // 如果没有在运行，直接返回
	}
	isRunning = false    // 设置为结束状态
	startButton.Enable() // 启用开始按钮
	endButton.Disable()  // 禁用结束按钮
	if pc != nil {
		pc.Close() // 关闭数据包捕获
	}
	rm.Stop() // 停止规则管理
}

func selectOption(selected string, w fyne.Window, a fyne.App) {
	nw := a.NewWindow("选项")

	// 创建输入字段
	srcIPEntry = widget.NewEntry()
	srcPortEntry = widget.NewEntry()
	destIPEntry = widget.NewEntry()
	destPortEntry = widget.NewEntry()
	protocolType = widget.NewSelect([]string{"TCP", "UDP"}, func(s string) {})
	logTypeEntry = widget.NewSelect([]string{"log", "alert"}, func(selected string) {})

	// 根据选择的攻击类型设置输入框的占位符
	updatePlaceholders(selected, srcIPEntry, srcPortEntry, destIPEntry, destPortEntry)

	// 确认按钮
	confirmButton := widget.NewButton("确认", func() {
		// 获取输入值
		srcIP := srcIPEntry.Text
		srcPort := srcPortEntry.Text
		destIP := destIPEntry.Text
		destPort := destPortEntry.Text
		protocol := protocolType.Selected
		logType := logTypeEntry.Selected

		// 创建Snort规则
		rule := CreateSnortRule(srcIP, srcPort, destIP, destPort, protocol, logType, selected)

		// 检查规则是否已存在
		if containsRule(rule) {
			dialog.NewInformation("提示", "规则已存在，请勿重复输入", nw).Show()
			return
		}

		dialog.NewInformation("生成的规则", rule, w).Show()

		// 将规则添加到规则列表中并更新显示
		rules = append(rules, rule)
		nw.Close() // 关闭新窗口
	})

	protocolType.PlaceHolder = "协议类型选择"
	logTypeEntry.PlaceHolder = "输出选择"

	nw.SetContent(container.New(layout.NewVBoxLayout(),
		srcIPEntry,
		srcPortEntry,
		destIPEntry,
		destPortEntry,
		protocolType,
		logTypeEntry,
		confirmButton, // 添加确认按钮
	))

	nw.Resize(fyne.NewSize(300, 250)) // 设置新窗口大小
	nw.Show()                         // 显示新窗口
}

// 检查规则列表中是否已存在指定的规则
func containsRule(rule string) bool {
	// 获取当前规则的SID前的部分
	rulePrefix := strings.Split(rule, "; sid:")[0] + ";"

	for _, r := range rules {
		// 获取已有规则的SID前的部分
		existingRulePrefix := strings.Split(r, "; sid:")[0] + ";"

		if existingRulePrefix == rulePrefix {
			return true
		}
	}
	return false
}

// 更新输入字段的占位符
func updatePlaceholders(selected string, srcIPEntry, srcPortEntry, destIPEntry, destPortEntry *widget.Entry) {
	switch selected {
	case "端口扫描":
		srcIPEntry.SetPlaceHolder("源 IP")
		destIPEntry.SetPlaceHolder("目标 IP")
		destPortEntry.SetPlaceHolder("目标端口")
		srcPortEntry.Hide() // 隐藏源端口字段

	case "口令爆破":
		srcIPEntry.SetPlaceHolder("源 IP")
		srcPortEntry.SetPlaceHolder("源端口")
		destIPEntry.SetPlaceHolder("目标 IP")
		destPortEntry.SetPlaceHolder("目标端口")

	case "SYN洪泛":
		srcIPEntry.Hide()
		destIPEntry.SetPlaceHolder("目标 IP")
		destPortEntry.SetPlaceHolder("目标端口")
		srcPortEntry.Hide() // 隐藏源端口字段

	case "拒绝服务攻击":
		srcIPEntry.SetPlaceHolder("源 IP")
		destIPEntry.SetPlaceHolder("目标 IP")
		destPortEntry.SetPlaceHolder("目标端口")
		srcPortEntry.Hide() // 隐藏源端口字段

	case "命令注入":
		srcIPEntry.SetPlaceHolder("源 IP")
		srcPortEntry.SetPlaceHolder("源端口")
		destIPEntry.SetPlaceHolder("目标 IP")
		destPortEntry.SetPlaceHolder("目标端口")

	default:
		srcIPEntry.SetPlaceHolder("源 IP")
		srcPortEntry.SetPlaceHolder("源端口")
		destIPEntry.SetPlaceHolder("目标 IP")
		destPortEntry.SetPlaceHolder("目标端口")
	}
}

func main() {
	w := startGUI()
	w.ShowAndRun()
}
