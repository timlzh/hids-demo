package model

type Expression struct {
	ID         uint   `gorm:"primaryKey" json:"id"`
	Field      string `gorm:"column:field;type:varchar(255);not null" json:"field"`
	Expression string `gorm:"column:expression;type:text;not null" json:"expression"`
	IsRegex    bool   `gorm:"column:is_regex;type:tinyint(1);not null" json:"is_regex"`

	RuleId uint `gorm:"column:rule_id;type:bigint;not null" json:"rule_id"`
}

type Rule struct {
	ID          uint   `gorm:"primaryKey" json:"id"`
	Type        string `gorm:"column:type;type:vachar(255);not null" json:"type"`
	Name        string `gorm:"column:name;type:varchar(255);not null" json:"name"`
	Description string `gorm:"column:description;type:varchar(255);not null" json:"description"`
	Severity    uint   `gorm:"column:severity;type:bigint;not null" json:"severity"`
	IsEnable    bool   `gorm:"column:is_enable;type:tinyint(1);not null" json:"is_enable"`

	Expressions []Expression `json:"expressions"`
}

func (Expression) TableName() string {
	return "expression"
}

func (Rule) TableName() string {
	return "rule"
}
