package model

type Process struct {
	Pid     int    `json:"pid"`
	PPid    int    `json:"ppid"`
	Tgid    int    `json:"tgid"`
	Ptgid   int    `json:"ptgid"`
	Name    string `json:"name"`
	CWD     string `json:"cwd"`
	Cmdline string `json:"cmdline"`
	Env     string `json:"env"`
}

type Packet struct {
	SourceIP   string `json:"source_ip"`
	SourcePort string `json:"source_port"`
	DestIP     string `json:"dest_ip"`
	DestPort   string `json:"dest_port"`
	Protocol   string `json:"protocol"`
	Direction  string `json:"direction"` // in or out
	Payload    string `json:"payload"`
}

type Behavior struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

type Warning struct {
	Severity  uint       `json:"severity"`
	Type      string     `json:"type"`
	Process   Process    `json:"process"`
	Network   Packet     `json:"network"`
	Rule      Rule       `json:"rule"`
	Behaviors []Behavior `json:"behaviors"`
}

type UdpResponse struct {
	Type string  `json:"type"`
	Data Process `json:"data"`
}
