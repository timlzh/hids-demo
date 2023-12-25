package webui

import (
	"hids/config"
	"hids/webui/controller"

	"github.com/gin-gonic/gin"
)

func Run() {
	r := gin.Default()

	r.LoadHTMLGlob("webui/templates/*")
	r.Static("/static", "webui/static")

	apiGroup := r.Group("/api")
	{
		apiGroup.GET("/rule", controller.GetRules)
		apiGroup.POST("/rule", controller.CreateRule)
		apiGroup.PUT("/rule/:id", controller.UpdateRule)
		apiGroup.DELETE("/rule/:id", controller.DeleteRule)
	}

	err := r.Run(config.GetConfig().WebUI.Host + ":" + config.GetConfig().WebUI.Port)
	if err != nil {
		panic(err)
	}
}
