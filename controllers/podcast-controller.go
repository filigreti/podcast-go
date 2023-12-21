package controllers

import (
	"github.com/filigreti/podcast-backend/configs"
	lksdk "github.com/livekit/server-sdk-go"
)

var host = configs.GetEnv("LIVEKIT_URL")
var apiKey = configs.GetEnv("LIVEKIT_KEY")
var apiSecret = configs.GetEnv("LIVEKIT_SECRET")

var roomClient = lksdk.NewRoomServiceClient(host, apiKey, apiSecret)
