package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

var messagesQueue = []normalizedPacketInformation{}

type normalizedPacketInformation struct {
	Timestamp        string `json:"timestamp"`
	MessageType      string `json:"message_type"`
	MessageCategory  string `json:"message_category"`
	Hostname         string `json:"hostname"`
	UserName         string `json:"username"`
	ProcessName      string `json:"process_name"`
	PID              int    `json:"pid"`
	Win32APIFunction string `json:"win32_api_function"`
	MainData         string `json:"main_data"`
	AdditionalData   string `json:"additional_data"`
}

func normalizePacketInformations(hostname string, messageType string, messageCategory string, username string, processName string, pid int, win32APIFunction string, mainData string, additionalData string) *normalizedPacketInformation {
	return &normalizedPacketInformation{
		Timestamp:        time.Now().UTC().Format("2006-01-02 15:04:05.000000"),
		MessageType:      messageType,
		MessageCategory:  messageCategory,
		Hostname:         hostname,
		UserName:         username,
		ProcessName:      processName,
		PID:              pid,
		Win32APIFunction: win32APIFunction,
		MainData:         mainData,
		AdditionalData:   additionalData,
	}
}

func addNewPacketToQueue(messageType string, messageCategory string, win32APIFunction string, mainData string, additionalData string) {
	if !AppConfig.DataMonitorHTTPForwardEvents.Enabled {
		return
	}

	normalizedPacket := normalizePacketInformations(hostname, messageType, messageCategory, username, processName, pid, win32APIFunction, mainData, additionalData)
	messagesQueue = append(messagesQueue, *normalizedPacket)
}

func sendPacketToUrlAddress(url string, headers *map[string]string) (int, error) {
	if len(messagesQueue) == 0 {
		return 0, nil
	}

	sendingQueue := messagesQueue
	messagesQueue = []normalizedPacketInformation{}

	packetJSON, err := json.Marshal(sendingQueue)
	if err != nil {
		return 0, fmt.Errorf("error marshaling packets to JSON: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(packetJSON))
	if err != nil {
		return 0, fmt.Errorf("error creating HTTP request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if headers != nil {
		for key, value := range *headers {
			req.Header.Set(key, value)
		}
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("error sending packet to URL: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("error response from server: %d - %s", resp.StatusCode, resp.Status)
	}

	return len(sendingQueue), nil
}
