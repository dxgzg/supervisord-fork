package main

import (
	"github.com/gorilla/mux"
	"net/http"
)

type ConfApi struct {
	router     *mux.Router
	supervisor *Supervisor
}

// NewLogtail creates a Logtail object
func NewConfApi(supervisor *Supervisor) *ConfApi {
	return &ConfApi{router: mux.NewRouter(), supervisor: supervisor}
}

// CreateHandler creates http handlers to process the program stdout and stderr through http interface
func (ca *ConfApi) CreateHandler() http.Handler {

	//ca.router.HandleFunc("/confFile/", ca.readConfFileHtml)
	ca.router.HandleFunc("/confFile/modify/{program}", ca.modifyProgramConfFile).Methods("POST")
	ca.router.HandleFunc("/confFile/read/{program}", ca.readProgramConfFile).Methods("GET")
	ca.router.PathPrefix("/confFile").HandlerFunc(ca.readConfFileHtml)
	return ca.router
}

func (ca *ConfApi) modifyProgramConfFile(writer http.ResponseWriter, request *http.Request) {
	//vars := mux.Vars(request)
	//if vars == nil {
	//	writer.WriteHeader(http.StatusNotFound)
	//	return
	//}
	//
	//programName := vars["program"]
	//programConfigPath := getProgramConfigPath(programName, ca.supervisor)
	//if programConfigPath == "" {
	//	writer.WriteHeader(http.StatusNotFound)
	//	return
	//}
	//
	//err := ca.writeProgramConfFile(programName, request)
	//if err != nil {
	//	writer.WriteHeader(http.StatusNotFound)
	//	return
	//}
	//
	//writer.WriteHeader(http.StatusOK)
	//writer.Write([]byte("ok"))

}

func (ca *ConfApi) readProgramConfFile(writer http.ResponseWriter, request *http.Request) {
	//vars := mux.Vars(request)
	//if vars == nil {
	//	writer.WriteHeader(http.StatusNotFound)
	//	return
	//}
	//
	//programName := vars["program"]
	//programConfigPath := getProgramConfigPath(programName, ca.supervisor)
	//if programConfigPath == "" {
	//	writer.WriteHeader(http.StatusNotFound)
	//	return
	//}
	//
	//b, err := readFile(programConfigPath)
	//if err != nil {
	//	writer.WriteHeader(http.StatusNotFound)
	//	return
	//}
	//
	//writer.WriteHeader(http.StatusOK)
	//writer.Write(b)
}

func (ca *ConfApi) readConfFileHtml(writer http.ResponseWriter, request *http.Request) {
	b, err := readFile(ca.getConfFilePath())
	if err != nil {
		writer.WriteHeader(http.StatusNotFound)
		return
	}

	writer.WriteHeader(http.StatusOK)
	writer.Write(b)
}

func (ca *ConfApi) getConfFilePath() string {
	return "webgui/confFile.html"
}

func (ca *ConfApi) writeProgramConfFile(programName string, request *http.Request) error {
	// 根据 body 创建一个 json 解析器实例
	//decoder := json.NewDecoder(request.Body)
	//var params map[string]string
	//err := decoder.Decode(&params)
	//if err != nil {
	//	return err
	//}
	//
	//data, ok := params["data"]
	//if !ok {
	//	return errors.New("not exist data")
	//}
	//
	//programConfigPath := getProgramConfigPath(programName, ca.supervisor)
	//if programConfigPath == "" {
	//	return errors.New("not exist conf file")
	//}
	//
	//f, err := os.OpenFile(programConfigPath, os.O_WRONLY|os.O_TRUNC, 0644)
	//if err != nil {
	//	return err
	//}
	//defer f.Close()
	//f.Write([]byte(data))

	return nil
}
