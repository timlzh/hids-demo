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

type Behavior struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

type Warning struct {
	Severity  uint       `json:"severity"`
	Process   Process    `json:"process"`
	Rule      Rule       `json:"rule"`
	Behaviors []Behavior `json:"behaviors"`
}

type UdpResponse struct {
	Type string  `json:"type"`
	Data Process `json:"data"`
}
