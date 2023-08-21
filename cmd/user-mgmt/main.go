package main

import (
	"context"
	"fmt"
	"log"

	"github.com/nitinjangam/user-mgmt-service/api"
	"github.com/nitinjangam/user-mgmt-service/internal/config"
	"github.com/nitinjangam/user-mgmt-service/internal/db"
	"github.com/nitinjangam/user-mgmt-service/internal/service"
)

func main() {
	fmt.Println("Starting user-mgmt-service....")
	cnfg := config.New()
	if cnfg == nil {
		log.Fatal("error while reading configuration")
	}
	ctx := context.Background()
	cnfg.InitLogger(ctx)

	//Initiate database
	dbService := db.New(ctx, &cnfg.DBConfig)

	//Initiate service
	userService := service.New(cnfg, dbService)

	//Create api handler by injecting all the services
	apiHandler, _ := api.New(&api.Config{
		Port:     fmt.Sprintf(":%s", cnfg.Port),
		Services: []api.ServerInterface{userService},
	})

	if err := apiHandler.Run(ctx); err != nil {
		cnfg.Logger.Error("error while running api", err)
	}

}
