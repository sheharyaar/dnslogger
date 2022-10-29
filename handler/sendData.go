package handler

import (
	"log"
	"time"
)

type SendDataStruct struct {
	TimePacket time.Time
	Host       string
	QueryName  string
	QueryType  string
}

// Send Data to a data source for storage
func SendData(sendBuffer <-chan SendDataStruct) {
	for {
		sendData := <-sendBuffer
		// Convert the received struct to map[string]string
		log.Printf("Received data from channel: %+v", sendData)
	}

}
