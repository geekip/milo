package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
)

// 配置信息结构体
type ConfigInfo struct {
	Server   string `json:"server"`   //服务地址
	Token    string `json:"token"`    //认证Token
	Interval int    `json:"interval"` //上报频率
}

// CPU信息结构体
type CpuInfo struct {
	Name          string `json:"name"`
	PhysicalCount int    `json:"physical_count"` //物理核心数
	LogicalCount  int    `json:"logical_count"`  //逻辑核心数
	Use           int    `json:"use"`
}

// 系统盘信息结构体
type DiskInfo struct {
	Total int `json:"total"`
	Free  int `json:"free"`
}

// 系统信息结构体
type HostInfo struct {
	Name            string `json:"name"`
	Os              string `json:"os"`
	Platform        string `json:"platform"`
	Uptime          int    `json:"up_time"`
	BootTime        int    `json:"boot_time"`
	Arch            string `json:"arch"`
	PlatformVersion string `json:"platform_version"`
	KernelVersion   string `json:"kernel_version"`
	Process         int    `json:"process"`
}

// 内存信息结构体
type MemInfo struct {
	Total int `json:"total"`
	Free  int `json:"free"`
}

// IP信息结构体
type IpInfo struct {
	IP       string   `json:"ip"`
	Location Location `json:"location"`
}

// 位置信息结构体
type Location struct {
	City        string `json:"city"`
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	Latitude    string `json:"latitude"`
	Longitude   string `json:"longitude"`
	Province    string `json:"province"`
}

// 上报数据信息结构体
type SysInfo struct {
	Host    HostInfo `json:"host"`
	Cpu     CpuInfo  `json:"cpu"`
	Disk    DiskInfo `json:"disk"`
	Mem     MemInfo  `json:"mem"`
	Ip      IpInfo   `json:"ip"`
	Token   string   `json:"token"`
	Version string   `json:"version"`
	Time    int      `json:"time"`
}

// 定义服务器响应结构体
type ServerResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

const (
	ipServer = "http://api.myip.la/cn?json"
	version  = "1.0.0"
)

var ipInfo IpInfo

func getConfig() ConfigInfo {
	server := flag.String("server", "", "Server address")
	interval := flag.Int("interval", 600, "Interval in seconds")
	token := flag.String("token", "", "Authentication token")
	flag.Parse()

	if *server == "" || *token == "" {
		flag.PrintDefaults()
		os.Exit(0)
	}

	return ConfigInfo{
		Server:   *server,
		Token:    *token,
		Interval: *interval,
	}
}

func getIp(url string) (IpInfo, error) {

	if ipInfo.IP != "" {
		// fmt.Println("cached")
		return ipInfo, nil
	}

	// 发送GET请求
	resp, err := http.Get(url)
	if err != nil {
		return ipInfo, fmt.Errorf("failed to send GET request: %w", err)
	}
	defer resp.Body.Close() // 确保关闭响应体

	// 检查HTTP响应状态码
	if resp.StatusCode != http.StatusOK {
		return ipInfo, fmt.Errorf("failed to get IP info: HTTP status code %d", resp.StatusCode)
	}

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ipInfo, fmt.Errorf("failed to read response body: %w", err)
	}

	// 解析JSON数据
	err = json.Unmarshal(body, &ipInfo)
	if err != nil {
		return ipInfo, fmt.Errorf("failed to unmarshal JSON response: %w", err)
	}

	return ipInfo, nil
}

func postData(Server string, data []byte) {
	jsonData := bytes.NewBuffer(data)

	// 创建POST请求
	req, err := http.NewRequest("POST", Server, jsonData)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	// 发送HTTP POST请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending POST request:", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	// 打印服务器返回的响应状态码
	fmt.Println("Response Status:", resp.Status)

	// 解析服务器返回的JSON数据
	var serverResp ServerResponse
	err = json.Unmarshal(body, &serverResp)
	if err != nil {
		fmt.Println("Error parsing response body:", err)
		return
	}

	// 检查code是否为0并打印响应信息
	if serverResp.Code == 0 {
		fmt.Println("Server Response:", serverResp.Msg)
	} else {
		fmt.Println("Server returned error code:", serverResp.Code)
	}
}

// 获取CPU信息
func getCpuInfo() CpuInfo {
	// 物理核心
	physicalCount, _ := cpu.Counts(false)
	// 逻辑数量
	logicalCount, _ := cpu.Counts(true)

	cpuInfo, _ := cpu.Info()
	cpuPercent, _ := cpu.Percent(time.Second, false)

	return CpuInfo{
		Name:          cpuInfo[0].ModelName,
		PhysicalCount: physicalCount,
		LogicalCount:  logicalCount,
		Use:           int(cpuPercent[0]),
	}
}

func getDiskInfo() DiskInfo {
	diskInfo, _ := disk.Usage("/")
	return DiskInfo{
		Total: int(diskInfo.Total),
		Free:  int(diskInfo.Free),
	}
}

func getHostInfo() HostInfo {
	hostInfo, _ := host.Info()
	return HostInfo{
		Name:            hostInfo.Hostname,
		Os:              hostInfo.OS,
		Platform:        hostInfo.Platform,
		Uptime:          int(hostInfo.Uptime),
		BootTime:        int(hostInfo.BootTime),
		Arch:            hostInfo.KernelArch,
		PlatformVersion: hostInfo.PlatformVersion,
		KernelVersion:   hostInfo.KernelVersion,
		Process:         int(hostInfo.Procs),
	}
}

func getMemInfo() MemInfo {
	memStat, _ := mem.VirtualMemory()
	return MemInfo{
		Total: int(memStat.Total),
		Free:  int(memStat.Free),
	}
}

func getSysInfo(token string) SysInfo {

	// 多线程
	var wg sync.WaitGroup
	wg.Add(5)

	var ip IpInfo
	var host HostInfo
	var cpu CpuInfo
	var disk DiskInfo
	var mem MemInfo

	go func() {
		defer wg.Done()
		ip, _ = getIp(ipServer)
	}()

	go func() {
		defer wg.Done()
		host = getHostInfo()
	}()

	go func() {
		defer wg.Done()
		cpu = getCpuInfo()
	}()

	go func() {
		defer wg.Done()
		disk = getDiskInfo()
	}()

	go func() {
		defer wg.Done()
		mem = getMemInfo()
	}()

	wg.Wait()

	timestamp := time.Now().Unix()
	return SysInfo{
		Host:    host,
		Cpu:     cpu,
		Disk:    disk,
		Mem:     mem,
		Ip:      ip,
		Token:   token,
		Version: version,
		Time:    int(timestamp),
	}
}

func main() {
	config := getConfig()
	sendData := func() {
		sysInfo := getSysInfo(config.Token)
		data, err := json.Marshal(sysInfo)
		if err == nil {
			postData(config.Server, data)
		} else {
			fmt.Println("Error marshaling sysInfo:", err)
		}
	}
	sendData()
	interval := time.Tick(time.Duration(config.Interval) * time.Second)
	for range interval {
		sendData()
	}
}
