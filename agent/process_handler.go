package agent

import (
	"fmt"
	"os"

	"log"

	"hids/api"
	"hids/model"
	"hids/utils"
)

// getProcessCWD
//
//	@param pid int
//	@return cwd string
func getProcessCWD(pid int) string {
	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		// log.Println("error Readlink: ", err)
		return ""
	}
	return cwd
}

// getProcessName
//
//	@param pid int
//	@return name string
func getProcessName(pid int) string {
	name, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		// log.Println("error Readlink: ", err)
		return ""
	}
	return name
}

// getProcessCmdline
//
//	@param pid int
//	@return cmdline string
func getProcessCmdline(pid int) string {
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		// log.Println("error ReadFile: ", err)
		return ""
	}
	return string(cmdline)
}

// getProcessEnv
//
//	@param pid int
//	@return env string
func getProcessEnv(pid int) string {
	env, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		// log.Println("error ReadFile: ", err)
		return ""
	}
	return string(env)
}

// getProcessInfo
//
//	@param process model.Process
//	@return process model.Process
func getProcessInfo(process model.Process) model.Process {
	process.CWD = getProcessCWD(process.Pid)
	process.Cmdline = getProcessCmdline(process.Pid)
	process.Name = getProcessName(process.Pid)
	process.Env = getProcessEnv(process.Pid)
	return process
}

// checkProcess
//
//	@param process model.Process
//	@return []model.Warning
func checkProcess(process model.Process) []model.Warning {
	warnings := []model.Warning{}
	rules, err := api.GetRulesByField("type", "process")
	if err != nil {
		log.Println("error GetRuleByField: ", err)
		return warnings
	}

	for _, rule := range rules {
		result := true
		warning := model.Warning{
			Severity: rule.Severity,
			Process:  process,
			Rule:     rule,
		}
		for _, expression := range rule.Expressions {
			switch expression.Field {
			case "name":
				result = result && utils.CheckExpression(expression, process.Name)
				warning.Behaviors = append(warning.Behaviors, model.Behavior{
					Field: expression.Field,
					Value: process.Name,
				})
			case "cwd":
				result = result && utils.CheckExpression(expression, process.CWD)
				warning.Behaviors = append(warning.Behaviors, model.Behavior{
					Field: expression.Field,
					Value: process.CWD,
				})
			case "cmdline":
				result = result && utils.CheckExpression(expression, process.Cmdline)
				warning.Behaviors = append(warning.Behaviors, model.Behavior{
					Field: expression.Field,
					Value: process.Cmdline,
				})
			case "env":
				result = result && utils.CheckExpression(expression, process.Env)
				warning.Behaviors = append(warning.Behaviors, model.Behavior{
					Field: expression.Field,
					Value: process.Env,
				})
			}

			if !result {
				break
			}
		}
		if result {
			warnings = append(warnings, warning)
		}
	}

	return warnings
}
