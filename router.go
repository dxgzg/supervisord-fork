package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/ochinchina/supervisord/types"
	"net/http"
)

func Register(engine *gin.Engine, supervisor *Supervisor) {
	processGroup := engine.Group("/program")
	processGroup.GET("/list", func(context *gin.Context) {
		result := struct{ AllProcessInfo []types.ProcessInfo }{make([]types.ProcessInfo, 0)}
		if supervisor.GetAllProcessInfo(nil, nil, &result) == nil {
			context.JSON(200, result.AllProcessInfo)
		} else {
			r := map[string]bool{"success": false}
			context.JSON(http.StatusOK, r)
		}
	})
	processGroup.POST("/stop/:name", func(context *gin.Context) {
		processName := context.Param("name")

		success, err := _stopProgram(processName, supervisor)
		r := map[string]bool{"success": err == nil && success}

		if err != nil {
			fmt.Println("error:", err.Error())
			context.String(http.StatusBadRequest, err.Error())
		} else {
			context.JSON(http.StatusOK, r)
		}
	})
	processGroup.POST("/start/:name", func(context *gin.Context) {
		processName := context.Param("name")

		success, err := _startProgram(processName, supervisor)
		r := map[string]bool{"success": err == nil && success}

		if err != nil {
			context.String(http.StatusBadRequest, err.Error())
		} else {
			context.JSON(http.StatusOK, r)
		}

	})

	confGroup := engine.Group("/processConfFile")
	confGroup.GET("/read/:processName", func(context *gin.Context) {
		programName := context.Param("processName")
		programConfigPath := GetProgramConfigPath(programName, supervisor)
		if programConfigPath == "" {
			context.String(http.StatusBadRequest, "not process name")
			return
		}

		b, err := ReadFile(programConfigPath)
		if err != nil {
			context.String(http.StatusBadRequest, err.Error())
			return
		}

		context.String(http.StatusOK, string(b))
	})

	confGroup.POST("/modify/:processName", func(context *gin.Context) {
		programName := context.Param("processName")
		programConfigPath := GetProgramConfigPath(programName, supervisor)
		if programConfigPath == "" {
			context.String(http.StatusBadRequest, "not process name")
			return
		}

		//context.BindJSON()
	})
}

func _stopProgram(programName string, supervisor *Supervisor) (bool, error) {
	stopArgs := StartProcessArgs{Name: programName, Wait: true}
	result := struct{ Success bool }{false}
	err := supervisor.StopProcess(nil, &stopArgs, &result)
	return result.Success, err
}

func _startProgram(program string, supervisor *Supervisor) (bool, error) {
	startArgs := StartProcessArgs{Name: program, Wait: true}
	result := struct{ Success bool }{false}
	err := supervisor.StartProcess(nil, &startArgs, &result)
	return result.Success, err
}
