package api

import (
	"hids/db"
	"hids/model"
)

func CreateRule(rule *model.Rule) (err error) {
	err = db.DB.Create(rule).Error
	return
}

func UpdateRule(rule *model.Rule) (err error) {
	err = db.DB.Save(rule).Error
	return
}

func DeleteRule(rule *model.Rule) (err error) {
	err = db.DB.Delete(rule).Error
	return
}

func CreateExpression(expression *model.Expression) (err error) {
	err = db.DB.Create(expression).Error
	return
}

func UpdateExpression(expression *model.Expression) (err error) {
	err = db.DB.Save(expression).Error
	return
}

func DeleteExpression(expression *model.Expression) (err error) {
	err = db.DB.Delete(expression).Error
	return
}

func DeleteExpressionByRuleId(ruleId uint) (err error) {
	err = db.DB.Where("rule_id = ?", ruleId).Delete(&model.Expression{}).Error
	return
}

func GetRules() (rules []model.Rule, err error) {
	err = db.DB.Find(&rules).Error
	if err != nil {
		return
	}

	for i, rule := range rules {
		expressions := []model.Expression{}
		err = db.DB.Where("rule_id = ?", rule.ID).Find(&expressions).Error
		if err != nil {
			return
		}

		rules[i].Expressions = expressions
	}
	return
}

func GetRulesByField(field string, value ...interface{}) (rules []model.Rule, err error) {
	err = db.DB.Where(field+" = ?", value).Find(&rules).Error
	if err != nil {
		return
	}

	for i, rule := range rules {
		expressions := []model.Expression{}
		err = db.DB.Where("rule_id = ?", rule.ID).Find(&expressions).Error
		if err != nil {
			return
		}

		rules[i].Expressions = expressions
	}
	return
}
