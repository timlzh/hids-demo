package controller

import (
	"log"
	"strconv"

	"hids/api"
	"hids/model"
	webuiModel "hids/webui/model"

	"github.com/gin-gonic/gin"
)

// GetRules
//
//		@Summary Get rules
//		@Description Get rules
//		@Tags rule
//		@Accept  json
//		@Produce  json
//	 @Success 200 {object} []model.Rule
//		@Router /rules [get]
func GetRules(c *gin.Context) {
	rules, err := api.GetRules()
	if err != nil {
		log.Println("error GetRules: ", err)
		c.JSON(500, gin.H{"message": "error GetRules"})
		return
	}

	c.JSON(200, rules)
}

// CreateRule
//
//		@Summary Create rule
//		@Description Create rule
//		@Tags rule
//		@Accept  json
//		@Produce  json
//	 @Param rule body webuiModel.Rule true "Rule"
//	 @Success 200 {object} Rule
//		@Router /rules [post]
func CreateRule(c *gin.Context) {
	var rule webuiModel.Rule
	if err := c.ShouldBindJSON(&rule); err != nil {
		log.Println("error CreateRule: ", err)
		c.JSON(500, gin.H{"message": "error CreateRule"})
		return
	}

	modelRule := model.Rule{
		Name:        rule.Name,
		Description: rule.Description,
		Type:        rule.Type,
		Severity:    rule.Severity,
		IsEnable:    rule.IsEnable,
	}

	if err := api.CreateRule(&modelRule); err != nil {
		log.Println("error CreateRule: ", err)
		c.JSON(500, gin.H{"message": "error CreateRule"})
		return
	}

	log.Println("rule: ", modelRule)

	for _, expression := range rule.Expressions {
		modelExpression := model.Expression{
			Field:      expression.Field,
			Expression: expression.Expression,
			IsRegex:    expression.IsRegex,
			RuleID:     modelRule.ID,
		}

		if err := api.CreateExpression(&modelExpression); err != nil {
			log.Println("error CreateExpression: ", err)
			c.JSON(500, gin.H{"message": "error CreateExpression"})
			return
		}
	}

	c.JSON(200, rule)
}

// UpdateRule
//
//		@Summary Update rule
//		@Description Update rule
//		@Tags rule
//		@Accept  json
//		@Produce  json
//	 @Param rule body webuiModel.Rule true "Rule"
//	 @Param id path uint true "ID"
//	 @Success 200 {object} Rule
//		@Router /rule/{id} [post]
func UpdateRule(c *gin.Context) {
	ruleIdUint64, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		log.Println("error UpdateRule: ", err)
		c.JSON(500, gin.H{"message": "error UpdateRule"})
		return
	}
	ruleId := uint(ruleIdUint64)

	var rule webuiModel.Rule
	if err := c.ShouldBindJSON(&rule); err != nil {
		log.Println("error UpdateRule: ", err)
		c.JSON(500, gin.H{"message": "error UpdateRule"})
		return
	}

	modelRule := model.Rule{
		ID:          ruleId,
		Name:        rule.Name,
		Description: rule.Description,
		Type:        rule.Type,
		Severity:    rule.Severity,
		IsEnable:    rule.IsEnable,
	}

	if err := api.UpdateRule(&modelRule); err != nil {
		log.Println("error UpdateRule: ", err)
		c.JSON(500, gin.H{"message": "error UpdateRule"})
		return
	}

	log.Println("rule: ", modelRule)

	if err := api.DeleteExpressionByRuleId(modelRule.ID); err != nil {
		log.Println("error DeleteExpressionByRuleId: ", err)
		c.JSON(500, gin.H{"message": "error DeleteExpressionByRuleId"})
		return
	}

	for _, expression := range rule.Expressions {
		modelExpression := model.Expression{
			Field:      expression.Field,
			Expression: expression.Expression,
			IsRegex:    expression.IsRegex,
			RuleID:     modelRule.ID,
		}

		if err := api.CreateExpression(&modelExpression); err != nil {
			log.Println("error CreateExpression: ", err)
			c.JSON(500, gin.H{"message": "error CreateExpression"})
			return
		}
	}

	c.JSON(200, rule)
}

// DeleteRule
//
//		@Summary Delete rule
//		@Description Delete rule
//		@Tags rule
//		@Accept  json
//		@Produce  json
//	 @Param id path uint true "ID"
//	 @Success 200 {object} Rule
//		@Router /rule/{id} [delete]
func DeleteRule(c *gin.Context) {
	ruleIdUint64, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		log.Println("error DeleteRule: ", err)
		c.JSON(500, gin.H{"message": "error DeleteRule"})
		return
	}
	ruleId := uint(ruleIdUint64)

	rule := model.Rule{
		ID: ruleId,
	}

	if err := api.DeleteRule(&rule); err != nil {
		log.Println("error DeleteRule: ", err)
		c.JSON(500, gin.H{"message": "error DeleteRule"})
		return
	}

	if err := api.DeleteExpressionByRuleId(rule.ID); err != nil {
		log.Println("error DeleteExpressionByRuleId: ", err)
		c.JSON(500, gin.H{"message": "error DeleteExpressionByRuleId"})
		return
	}

	c.JSON(200, rule)
}
