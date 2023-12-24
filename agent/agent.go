package agent

func Run(ip string, port int) {
	go processMonitorStart(ip, port)
	go networkMonitorStart(ip, port)

	for {
		// TODO
	}
}
