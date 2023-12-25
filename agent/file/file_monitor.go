package file

import (
	"fmt"
	"log"

	"hids/api"
	"hids/model"

	"github.com/fsnotify/fsnotify"
)

var rules []model.Rule

// MonitorStart starts the file monitor
func MonitorStart() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		panic(err)
	}
	defer watcher.Close()

	rules, err = api.GetRulesByField("type", "file")
	if err != nil {
		panic(err)
	}

	for _, rule := range rules {
		err = watcher.Add(rule.Name)
		if err != nil {
			panic(err)
		}
	}

	for {
		select {
		case event := <-watcher.Events:
			warning := checkFile(event)
			msg := fmt.Sprintf("Warning: %s", warning.Rule.Description)
			msg += fmt.Sprintf("\n\tType: %s", warning.Type)
			msg += fmt.Sprintf("\n\tSeverity: %d", warning.Severity)
			msg += fmt.Sprintf("\n\tFile: %s", warning.Behaviors[0].Field)
			msg += fmt.Sprintf("\n\tBehavior: %s", warning.Behaviors[0].Value)
			log.Println(msg)
		case err := <-watcher.Errors:
			log.Println("error:", err)
		}
	}
}
