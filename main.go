package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/fimreal/goutils/ezap"
	iptools "github.com/fimreal/goutils/net"
)

var (
	port              = ":5000"
	REGION_ID         = os.Getenv("REGION_ID")
	ACCESS_KEY_ID     = os.Getenv("ACCESS_KEY_ID")
	ACCESS_KEY_SECRET = os.Getenv("ACCESS_KEY_SECRET")
)

func main() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "OK") })
	http.HandleFunc("/add", addIP)

	ezap.Info("Running at ", port)
	ezap.Info("健康检查 => /health")
	ezap.Info("写入安全组规则 => /add")
	ezap.Fatal(http.ListenAndServe(port, nil))
}

func addIP(w http.ResponseWriter, r *http.Request) {
	// 解析url传递的参数，对于POST则解析响应包的主体（request body）
	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm() err: %v", err)
		ezap.Println("ParseForm() err: ", err)
		return
	}
	s := &staff{
		ip:   r.FormValue("ip"),
		name: r.FormValue("name"),
		sgid: r.FormValue("sgid"),
	}
	if !s.verify() {
		fmt.Fprintf(w, "输入 信息[%v] 有误，请检查", s)
		ezap.Errorf("输入 信息[%v] 有误，请检查", s)
		return
	}
	err := s.authorize()
	if err != nil {
		fmt.Fprintf(w, "系统异常，请稍后重试")
		ezap.Error("添加安全组规则时遇到错误，", err)
		return
	}
	// // 返回成功信息
	fmt.Fprintln(w, "添加成功")
}

type staff struct {
	name string
	ip   string
	sgid string
}

func newClient() *ecs.Client {

	client, err := ecs.NewClientWithAccessKey(REGION_ID, ACCESS_KEY_ID, ACCESS_KEY_SECRET)
	if err != nil {
		// Handle exceptions
		panic(err)
	}
	return client
}

func (s *staff) authorize() error {
	c := newClient()

	r := ecs.CreateAuthorizeSecurityGroupRequest()
	r.Scheme = "https"
	r.IpProtocol = "tcp"
	r.Priority = "1"
	r.Policy = "accept"
	r.NicType = "internet"
	r.PortRange = "1/65535"

	r.SecurityGroupId = s.sgid
	r.SourceCidrIp = s.ip
	r.Description = s.name

	res, err := c.AuthorizeSecurityGroup(r)
	if err != nil {
		return err
	}
	ezap.Infof("Response: %#v, Client IP: %s  was successfully added to the Security Group.", res, s.ip)

	return nil
}

func (s *staff) verify() bool {
	ezap.Info("request details: ", s)

	if iptools.IsLanIPv4(s.ip) {
		return false
	}

	c := newClient()
	r := ecs.CreateDescribeSecurityGroupsRequest()
	r.Scheme = "https"
	r.RegionId = REGION_ID
	r.SecurityGroupId = s.sgid

	resJSON, err := c.DescribeSecurityGroups(r)
	if err != nil {
		ezap.Error(err)
		return false
	}
	res := &ecs.DescribeSecurityGroupsResponse{}
	err = json.Unmarshal(resJSON.GetHttpContentBytes(), res)
	if err != nil {
		ezap.Error(err)
		return false
	}
	if len(res.SecurityGroups.SecurityGroup) == 0 {
		ezap.Error(s.sgid, " is not exists ", res)
		return false
	}
	ezap.Info("检查安全组是否存在，", res)

	return true
}
