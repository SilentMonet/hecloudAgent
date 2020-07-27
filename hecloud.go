package main

import (
	"fmt"
)

func main() {
	fmt.Println("start")
	var agent UserAgent
	agent.user.name = "XXXXXXX"
	agent.user.encryptedPassword = "passwordHashXXXXXXXXX"

	err := agent.init("XXXXXXX")

	if err != nil {
		fmt.Println(err)
		return
	}

	agent.diskUpload("filename", "localpath", agent.disk.RootID)

	fmt.Println("end")
}
