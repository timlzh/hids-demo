package api

import (
	"hids/db"
	"hids/model"
)

func CreateRule(rule model.Rule) (err error) {
	err = db.DB.Create(&rule).Error
	return
}

func UpdateRule(rule model.Rule) (err error) {
	err = db.DB.Save(&rule).Error
	return
}

func DeleteRule(rule model.Rule) (err error) {
	err = db.DB.Delete(&rule).Error
	return
}

func CreateExpression(expression model.Expression) (err error) {
	err = db.DB.Create(&expression).Error
	return
}

func UpdateExpression(expression model.Expression) (err error) {
	err = db.DB.Save(&expression).Error
	return
}

func DeleteExpression(expression model.Expression) (err error) {
	err = db.DB.Delete(&expression).Error
	return
}

func GetRuleByField(field string, value ...interface{}) (rule model.Rule, err error) {
	err = db.DB.Where(field+" = ?", value).First(&rule).Error
	if err != nil {
		return
	}

	expressions := []model.Expression{}
	err = db.DB.Where("rule_id = ?", rule.ID).Find(&expressions).Error
	if err != nil {
		return
	}

	rule.Expressions = expressions
	return
}
