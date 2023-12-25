package file

import (
	"log"
	"strings"

	"hids/model"

	"github.com/fsnotify/fsnotify"
)

func getSeverity(path string) uint {
	for _, rule := range rules {
		if strings.Contains(path, rule.Name) {
			return rule.Severity
		}
	}
	return 0
}

func checkFile(event fsnotify.Event) (warning model.Warning) {
	warning = model.Warning{
		Type:     event.Op.String(),
		Severity: getSeverity(event.Name),
		Behaviors: []model.Behavior{
			{
				Field: event.Name,
				Value: event.Op.String(),
			},
		},
	}

	if event.Op&fsnotify.Create == fsnotify.Create {
		log.Println("create file:", event.Name)
	} else if event.Op&fsnotify.Write == fsnotify.Write {
		log.Println("write file:", event.Name)
	} else if event.Op&fsnotify.Remove == fsnotify.Remove {
		log.Println("remove file:", event.Name)
	} else if event.Op&fsnotify.Rename == fsnotify.Rename {
		log.Println("rename file:", event.Name)
	} else if event.Op&fsnotify.Chmod == fsnotify.Chmod {
		log.Println("chmod file:", event.Name)
	}

	return warning
}
