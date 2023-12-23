package agent

/*
#cgo CFLAGS: -I../c-libs
#define GO_ENV
#include "cJSON/cJSON.c"
#include "monitor/linux/monitor.c"
*/
import "C"

import (
	"fmt"
	"log"
	"net"
	"os"

	"encoding/json"
)

// monitorStart
//
//	@param ip string
//	@param port int
func monitorStart(ip string, port int) {
	// ip := "127.0.0.1"
	// port := 65530

	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		log.Println("error ResolveUDPAddr")
		os.Exit(1)
	}

	serverConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Println("ListenUDP error: ", err)
		return
	}
	defer serverConn.Close()

	go C.startMonitor(C.CString(ip), C.int(port))

	buf := make([]byte, 1024)
	var data map[string]interface{}
	for {
		n, _, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			log.Println("error during read: ", err)
		}

		err = json.Unmarshal(buf[:n], &data)
		if err != nil {
			log.Println("json.Unmarshal error: ", err)
		}
		log.Println("data: ", data)
	}
}
