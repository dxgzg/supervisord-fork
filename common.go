package main

import (
	"io/ioutil"
	"os"
)

func GetProgramConfigPath(programName string, s *Supervisor) string {
	c := s.config.GetProgram(programName)
	if c == nil {
		return ""
	}

	res := c.GetString("conf_file", "")
	return res
}

func ReadFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return b, nil
}
