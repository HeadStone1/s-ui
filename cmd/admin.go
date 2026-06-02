package cmd

import (
	"fmt"

	"github.com/HeadStone1/s-ui/config"
	"github.com/HeadStone1/s-ui/database"
	"github.com/HeadStone1/s-ui/service"
	"github.com/HeadStone1/s-ui/util/common"
)

func resetAdmin() {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println(err)
		return
	}

	userService := service.UserService{}
	password := common.Random(24)
	err = userService.UpdateFirstUser("admin", password)
	if err != nil {
		fmt.Println("reset admin credentials failed:", err)
	} else {
		fmt.Println("reset admin credentials success")
		fmt.Println("Username:\tadmin")
		fmt.Println("Password:\t", password)
		fmt.Println("Save this password now. It will not be shown again.")
	}
}

func updateAdmin(username string, password string) {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println(err)
		return
	}

	if username != "" || password != "" {
		userService := service.UserService{}
		err := userService.UpdateFirstUser(username, password)
		if err != nil {
			fmt.Println("reset admin credentials failed:", err)
		} else {
			fmt.Println("reset admin credentials success")
		}
	}
}

func showAdmin() {
	err := database.InitDB(config.GetDBPath())
	if err != nil {
		fmt.Println(err)
		return
	}
	userService := service.UserService{}
	userModel, err := userService.GetFirstUser()
	if err != nil {
		fmt.Println("get current user info failed,error info:", err)
	}
	username := userModel.Username
	if username == "" {
		fmt.Println("current username is empty")
	}
	fmt.Println("First admin account:")
	fmt.Println("\tUsername:\t", username)
	fmt.Println("\tPassword:\t", "(hidden)")
}
