package webui

import (
	"github.com/gin-gonic/gin"
	"hids/config"
	"hids/webui/controller"
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

	r.Run(config.GetConfig().WebUI.Host + ":" + config.GetConfig().WebUI.Port)
}
