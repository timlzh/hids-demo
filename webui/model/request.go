package model

type Expression struct {
	Field      string `json:"field"`
	Expression string `json:"expression"`
	IsRegex    bool   `json:"is_regex"`
}

type Rule struct {
	Type        string       `json:"type"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Severity    uint         `json:"severity"`
	IsEnable    bool         `json:"is_enable"`
	Expressions []Expression `json:"expressions"`
}
