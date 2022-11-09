package net

import "net"

func Host(host string) ([]string, error) {
	res, err := net.LookupHost(host)
	return res, err

}
