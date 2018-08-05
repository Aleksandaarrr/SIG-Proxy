package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hpcloud/tail"
	"github.com/scionproto/scion/go/lib/snet"
)

var (
	sigListener  net.Listener
	config       Config
	measuringMap map[string]Info
	validSIGInfo *regexp.Regexp
	extractIP    *regexp.Regexp
	runningSIG   *exec.Cmd
	count        = 1
	username     = ""
	thisIP       = ""

	//////////////////////////////////////////////
	// THINGS BELOW ARE ADJUSTABLE BY THE USER //
	////////////////////////////////////////////

	// Specify the SIG details, e.g. "17-ffaa:1:1d,[127.0.0.1]:10080@10.0.2.0/24,192.168.178.0/24,10.0.8.0/24"
	sigInfo = ""
	// Specify oort number of the application (listening port)
	port = 30303
	// Specify own SIG discovery port
	sigDiscoveryPort = "10001"
	// Specify the command for the running application e.g. "./geth -datadir="<>" -bootnodes=enode//... -port 30303 -networkID 8014 console"
	application = ""
)

// Info stores data for measurements
type Info struct {
	ping  float64
	ttl   int
	time  time.Time
	count int
}

type Remote struct {
	Addr      string
	CtrlPort  int
	EncapPort int
}

type AS struct {
	Name string
	Nets []string `json:"Nets"`
	Sigs map[string]Remote
}

type Config struct {
	ASes          map[string]AS
	ConfigVersion int
}

// Start SIG
func startSIG() {
	runningSIG = exec.Command("/home/ubuntu/go/src/github.com/scionproto/scion/bin/sig", "-config", "/home/ubuntu/go/src/github.com/scionproto/scion/bin/sig.config.json", "-sciond", "/run/shm/sciond/sd1-1029.sock", "-dispatcher", "/run/shm/dispatcher/default.sock", "-ia", "1-1029", "-ip", "127.0.0.1", "-encapport", "10080", "-ctrlport", "10081", "-id", "sig")
	if err := runningSIG.Start(); err != nil {
		fmt.Println("Failed to start process", err)
	}
	fmt.Println("SIG is running...")
}

// Restart SIG
func restartSIG() {
	if runningSIG != nil {
		if err := runningSIG.Process.Signal(syscall.SIGHUP); err != nil {
			fmt.Println("Failed to reload config", err)
		} else {
			fmt.Println("Config was succesfully reloaded")
		}
	}
}

func createConfigFile(sig string) bool {
	splitSIG := strings.Split(sig, "@")

	remote, err := snet.AddrFromString(splitSIG[0])
	if err != nil {
		fmt.Println("ERROR:", err)
		return false
	}

	a := AS{}
	a.Name = "AS " + strconv.Itoa(count)
	count++
	a.Sigs = make(map[string]Remote)

	array := strings.Split(splitSIG[1], ",")
	a.Nets = make([]string, len(array))
	for i, v := range array {
		a.Nets[i] = v
	}
	r := Remote{}
	r.Addr = remote.Host.String()
	r.EncapPort = int(remote.L4Port)
	r.CtrlPort = int(remote.L4Port) + 1

	a.Sigs["remote-1"] = r
	config.ASes[remote.IA.String()] = a

	jsonString, _ := json.Marshal(config)
	fmt.Println(string(jsonString))
	err = ioutil.WriteFile("/home/ubuntu/go/src/github.com/scionproto/scion/bin/sig.config.json", jsonString, 0644)
	if err != nil {
		fmt.Println("ERROR:", err)
		return false
	}
	return true
}

func runSIGDiscoveryServer() {
	fmt.Println("Launching server...")

	// listen on all interfaces
	sigListener, err := net.Listen("tcp", "0.0.0.0:"+sigDiscoveryPort)
	if err != nil {
		panic(err)
	}

	for {
		// accept connection on port 10001
		conn, err := sigListener.Accept()
		fmt.Println("Accepted connection from", conn.RemoteAddr().String())

		if err == nil {
			go handleRequest(conn)
		}
	}
}

// Handles incoming requests.
func handleRequest(conn net.Conn) {
	// Close the connection when you're done with it.
	defer conn.Close()
	// Make a buffer to hold incoming data.
	buf := make([]byte, 1024)
	// Read the incoming connection into the buffer.
	n, err := conn.Read(buf)
	if err != nil {
		if err != io.EOF {
			fmt.Println("Error reading:", err)
		}
		return
	}
	if validSIGInfo.MatchString(string(buf[:n])) {
		conn.Write([]byte(sigInfo))
		if createConfigFile(string(buf[:n])) {
			info := Info{}
			info.time = time.Now()
			info.ping = math.MaxFloat64
			info.ttl = math.MaxInt64
			info.count = 0
			tmpSplit := strings.Split(conn.RemoteAddr().String(), ":")
			measuringMap[tmpSplit[0]] = info
			fmt.Println("Succesfully created sig.config.json")
			if runningSIG != nil {
				restartSIG()
			} else {
				startSIG()
			}
		}
	} else {
		fmt.Println("Incorrect SIG information")
	}
}

func startApplication() {
	cmd := exec.Command("sudo", "-s", "-u", username, application)
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Println("Failed to start process", err)
	} else {
		fmt.Println("Application is running...")
	}
}

func getSIGInfo(remoteIP string) {
	// connect to this socket
	conn, err := net.Dial("tcp", remoteIP+":"+sigDiscoveryPort)
	if err == nil {
		defer conn.Close()
		buf := make([]byte, 1024)
		_, err = conn.Write([]byte(sigInfo))
		if err != nil {
			fmt.Println("Error reading:", err.Error())
		}
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Println("Error reading:", err.Error())
		}
		if validSIGInfo.MatchString(string(buf[:n])) {
			if createConfigFile(string(buf[:n])) {
				info := Info{}
				info.time = time.Now()
				info.ping = math.MaxFloat64
				info.ttl = math.MaxInt64
				info.count = 0
				tmpSplit := strings.Split(conn.RemoteAddr().String(), ":")
				measuringMap[tmpSplit[0]] = info
				fmt.Println("Succesfully created sig.config.json")
				if runningSIG != nil {
					restartSIG()
				} else {
					startSIG()
				}
			}
		} else {
			fmt.Println("Incorrect SIG information")
		}
	}
}

func createNewUser(uname string) {
	cmd := exec.Command("sudo", "useradd", uname)
	err := cmd.Run()
	if err != nil {
		fmt.Println("Failed to create a new user", err)
	} else {
		username = uname
		fmt.Println("Created new user")
	}
}

func deleteUser(uname string) {
	cmd := exec.Command("sudo", "userdel", uname)
	err := cmd.Run()
	if err != nil {
		fmt.Println("Failed to delete", uname, err)
	} else {
		username = ""
		fmt.Println("User", uname, "was deleted!")
	}
}

func addRules() {
	cmd := exec.Command("sudo", "iptables", "-A", "OUTPUT", "-p", "tcp", "-m", "owner", "--uid-owner", username, "-m", "state", "--state", "NEW", "-j", "LOG", "--log-prefix", "poc")
	err := cmd.Run()
	if err != nil {
		fmt.Println("Failed to add rule 1", err)
	} else {
		fmt.Println("Added rule 1")
	}

	cmd = exec.Command("sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", strconv.Itoa(port), "-m", "state", "--state", "NEW", "-j", "LOG", "--log-prefix", "poc")
	err = cmd.Run()
	if err != nil {
		fmt.Println("Failed to add rule 2", err)
	} else {
		fmt.Println("Added rule 2")
	}

	cmd = exec.Command("sudo", "ip", "rule", "add", "fwmark", "1", "table", "11")
	err = cmd.Run()
	if err != nil {
		fmt.Println("Failed to add rule 3", err)
	} else {
		fmt.Println("Added rule 3")
	}

}

func deleteRules() {
	cmd := exec.Command("sudo", "iptables", "-D", "OUTPUT", "-p", "tcp", "-m", "owner", "--uid-owner", username, "-m", "state", "--state", "NEW", "-j", "LOG", "--log-prefix", "poc")
	err := cmd.Run()
	if err != nil {
		fmt.Println("Failed to delete rule 1", err)
	} else {
		fmt.Println("Deleted rule 1")
	}

	cmd = exec.Command("sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", strconv.Itoa(port), "-m", "state", "--state", "NEW", "-j", "LOG", "--log-prefix", "poc")
	err = cmd.Run()
	if err != nil {
		fmt.Println("Failed to delete rule 2", err)
	} else {
		fmt.Println("Deleted rule 2")
	}

	cmd = exec.Command("sudo", "ip", "rule", "delete", "fwmark", "1", "table", "11")
	err = cmd.Run()
	if err != nil {
		fmt.Println("Failed to delete rule 3", err)
	} else {
		fmt.Println("Deleted rule 3")
	}

}

func tailLog() {
	t, _ := tail.TailFile("/var/log/kern.log", tail.Config{Follow: true})
	for line := range t.Lines {
		if strings.Contains(line.Text, "poc") {
			addToMap(line.Text)
		}
	}
}

func addToMap(line string) {
	// fmt.Println(line)
	var sList []string
	matches := extractIP.FindAllString(line, -1)
	if strings.Contains(matches[0], thisIP) {
		sList = strings.Split(matches[1], "=")
	} else {
		sList = strings.Split(matches[0], "=")
	}

	// if new IP, call getSIGInfo() to update SIG config
	if _, ok := measuringMap[sList[1]]; !ok {
		getSIGInfo(sList[1])
	}
}

func clearLog() {
	cmd := exec.Command("bash", "-c", "echo > /dev/null | sudo tee /var/log/kern.log")
	err := cmd.Run()
	if err != nil {
		fmt.Println("Failed to clear kern.log", err)
	} else {
		fmt.Println("Cleared kern.log")
	}
}

func getThisIP() {
	output, err := exec.Command("hostname", "-I").Output()
	if err != nil {
		fmt.Println("Failed to get IP", err)
	} else {
		sList := strings.Split(string(output), " ")
		thisIP = sList[1]
		fmt.Println("IP of this machine is:", thisIP)
	}
}

// Ping TODO
func Ping(remoteIP string, count int) string {
	cmd := "ping " + remoteIP + " -c " + strconv.Itoa(count) + " | tail -2"
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		fmt.Println("Error in ping for", remoteIP, err)
	}
	return string(out)
}

// Traceroute TODO
func Traceroute(remoteIP string) string {
	cmd := "traceroute -n " + remoteIP + " | tail -1"
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		fmt.Println("Error in traceroute for", remoteIP, err)
	}
	return string(out)
}

func markPackets(remoteIP string) {
	cmd := exec.Command("sudo", "iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "tcp", "-d", remoteIP, "-j", "MARK", "--set-mark", "1")
	err := cmd.Run()
	if err != nil {
		fmt.Println("Failed to add rule for", remoteIP, err)
	} else {
		fmt.Println("Added rule for", remoteIP)
	}
}

func unmarkPackets(remoteIP string) {
	cmd := exec.Command("sudo", "iptables", "-t", "mangle", "-D", "OUTPUT", "-p", "tcp", "-d", remoteIP, "-j", "MARK", "--set-mark", "1")
	err := cmd.Run()
	if err != nil {
		fmt.Println("Failed to delete rule for", remoteIP, err)
	} else {
		fmt.Println("Deleted rule for", remoteIP)
	}
}

// TODO
func initLinuxCmds() {
	cmd := exec.Command("bash", "-c", "sudo setcap cap_net_admin+eip /home/ubuntu/go/src/github.com/scionproto/scion/bin/sig")
	err := cmd.Run()
	if err != nil {
		fmt.Println("Failed to enable CAP_NET_ADMIN", err)
	} else {
		fmt.Println("Enabled CAP_NET_ADMIN")
	}

	cmd = exec.Command("bash", "-c", "sudo sysctl -w net.ipv4.ip_forward=1")
	err = cmd.Run()
	if err != nil {
		fmt.Println("Failed enable IP forwarding", err)
	} else {
		fmt.Println("Enabled IP forwarding")
	}

	cmd = exec.Command("bash", "-c", "sudo sysctl -w net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0")
	err = cmd.Run()
	if err != nil {
		fmt.Println("Failed to disable reverse path filtering", err)
	} else {
		fmt.Println("Disabled reverse path filtering")
	}

	// - sudo setcap cap_net_admin+eip /home/ubuntu/go/src/github.com/scionproto/scion/bin/sig
	// - sudo sysctl -w net.ipv4.ip_forward=1
	// - sudo sysctl -w net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
}

func init() {
	config = Config{}
	config.ConfigVersion = 9001 // TODO change by the user
	config.ASes = make(map[string]AS)

	measuringMap = make(map[string]Info)

	validSIGInfo = regexp.MustCompile(`^\d+-[\d:A-Fa-f]+,\[(\d+.){3}\d+\]:\d+@((\d+.){3}\d+\/\d+,?)*$`)
	extractIP = regexp.MustCompile(`(SRC|DST)=(\d+.){3}\d+`)
}

func main() {
	initLinuxCmds()
	deleteUser("test")
	createNewUser("test")
	getThisIP()
	if username == "" {
		fmt.Println("New temp user was not created")
		return
	}
	if thisIP == "" {
		fmt.Println("No IP was obtained for this machine")
		return
	}

	deleteRules()
	addRules()
	clearLog()
	go tailLog()
	go runSIGDiscoveryServer()
	go startApplication()

	fmt.Println("Measuring...")

	for {
		for k, v := range measuringMap {
			avgPing := v.ping
			avgTTL := v.ttl
			count := v.count
			fmt.Println("Measuring", k)

			// Packet loss
			ping := Ping(k, 3)
			fmt.Println(ping)
			if strings.Contains(ping, "errors") { // unreachable
				fmt.Println("Error with measuring ping")
				markPackets(k)
				continue
			}
			splitPing := strings.Split(ping, " ")
			loss := strings.Split(splitPing[6], "%")
			tmpLoss, _ := strconv.ParseFloat(loss[0], 64)
			fmt.Println(loss[0])
			fmt.Println(tmpLoss)
			if tmpLoss > 0.0 { // or unreachable, etc.
				fmt.Println("PACKET LOSS !", tmpLoss, "%")
				markPackets(k)
				continue
			}

			// Ping
			avg := strings.Split(splitPing[12], "/")
			tmpAvg, _ := strconv.ParseFloat(avg[1], 64)
			if count == 0 || tmpAvg <= avgPing {
				v.ping = tmpAvg
			} else {
				fmt.Println("HIGHER AVG PING !", tmpAvg, "ms", "(", avgPing, ")")
				markPackets(k)
				continue
			}

			// Traceroute
			traceroute := Traceroute(k)
			fmt.Println(traceroute)
			splitTTL := strings.Split(traceroute, " ")
			tmpTTL, _ := strconv.Atoi(splitTTL[0])
			if count == 0 || tmpTTL <= avgTTL {
				v.ttl = tmpTTL
			} else {
				fmt.Println("HIGHER TTL !", tmpTTL, "(", avgTTL, ")")
				markPackets(k)
				continue
			}

			if count == 0 {
				fmt.Println("Initialization done with ", tmpLoss, "% packet loss,", v.ping, "ms average ping,", v.ttl, "TTL")
			}
			// Update values
			v.count++
			v.time = time.Now()
			measuringMap[k] = v
			unmarkPackets(k)
		}
		time.Sleep(10 * time.Second)
	}
}
