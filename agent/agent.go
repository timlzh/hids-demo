package agent

func Run(ip string, port int) {
	go processMonitorStart(ip, port)
	networkMonitorStart()
}
