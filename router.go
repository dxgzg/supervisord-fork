package main

import (
	"github.com/gin-gonic/gin"
	"github.com/ochinchina/supervisord/types"
)

func Register(engine *gin.Engine, s *Supervisor) {
	engine.GET("/program/list", func(context *gin.Context) {
		result := struct{ AllProcessInfo []types.ProcessInfo }{make([]types.ProcessInfo, 0)}
		if s.GetAllProcessInfo(nil, nil, &result) == nil {
			context.JSON(200, result.AllProcessInfo)
		} else {
			r := map[string]bool{"success": false}
			context.JSON(200, r)
		}
	})

}
