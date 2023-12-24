package utils

import (
	"regexp"

	"log"

	"hids/model"
)

// CheckExpression
//
//	@param expression model.Expression
//	@param value string
//	@return bool
func CheckExpression(expression model.Expression, value string) bool {
	if expression.IsRegex {
		re, err := regexp.Compile(expression.Expression)
		if err != nil {
			log.Println("error Compile: ", err)
			return false
		}
		return re.MatchString(value)
	} else {
		return expression.Expression == value
	}
}
