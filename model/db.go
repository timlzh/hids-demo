package model

type Expression struct {
	ID         uint   `gorm:"primaryKey" json:"id"`
	Expression string `gorm:"column:expression;type:varchar(255);not null" json:"expression"` // 表达式
	IsRegex    bool   `gorm:"column:is_regex;type:tinyint(1);not null" json:"is_regex"`

	RuleId uint `gorm:"column:rule_id;type:bigint;not null" json:"rule_id"`
}

type Rule struct {
	ID          uint   `gorm:"primaryKey" json:"id"`
	Name        string `gorm:"column:name;type:varchar(255);not null" json:"name"`
	Description string `gorm:"column:description;type:varchar(255);not null" json:"description"`
	Level       uint   `gorm:"column:level;type:bigint;not null" json:"level"`
	IsEnable    bool   `gorm:"column:is_enable;type:tinyint(1);not null" json:"is_enable"`

	Expressions []Expression `json:"expressions"`
}

func (Expression) TableName() string {
	return "expression"
}

func (Rule) TableName() string {
	return "rule"
}
