package utils

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"regexp"

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

// ReadJson
//
//	@param path string
//	@param v interface{}
//	@return err error
func ReadJson(path string, v interface{}) (err error) {
	file, err := os.Open(path)
	if err != nil {
		log.Println("error Open: ", err)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		log.Println("error ReadAll: ", err)
		return
	}

	err = json.Unmarshal(data, v)
	if err != nil {
		log.Println("error Unmarshal: ", err)
		return
	}
	return
}
