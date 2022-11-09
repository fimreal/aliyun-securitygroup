package net

import (
	"net"
)

// 返回网卡获取到的第一个非回环 ip 地址
func GetFirstIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, address := range addrs {
			// 检查ip地址判断是否回环地址
			if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					// fmt.Println(ipnet.IP.String())
					return ipnet.IP.String(), nil
				}
			}
		}
	}

	return "", err
}

func GetAllMacAddr() ([]string, error) {
	var macAddrs []string
	netInterfaces, err := net.Interfaces()
	if err != nil {
		// fmt.Printf("fail to get net interfaces: %v", err)
		return macAddrs, err
	}

	for _, netInterface := range netInterfaces {
		macAddr := netInterface.HardwareAddr.String()
		if len(macAddr) == 0 {
			continue
		}
		macAddrs = append(macAddrs, macAddr)
	}
	return macAddrs, err
}

func GetAllIP() ([]string, error) {
	var ips []string

	interfaceAddr, err := net.InterfaceAddrs()
	if err != nil {
		// fmt.Printf("fail to get net interface addrs: %v", err)
		return ips, err
	}

	for _, address := range interfaceAddr {
		ipNet, isValidIPNet := address.(*net.IPNet)
		if isValidIPNet && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				ips = append(ips, ipNet.IP.String())
			}
		}
	}
	return ips, err
}
