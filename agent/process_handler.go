package agent

import (
	"fmt"
	"log"
	"os"

	"hids/model"
)

// getProcessCWD
//
//	@param pid int
//	@return cwd string
func getProcessCWD(pid int) string {
	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		log.Println("error Readlink: ", err)
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
		log.Println("error Readlink: ", err)
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
		log.Println("error ReadFile: ", err)
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
		log.Println("error ReadFile: ", err)
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
