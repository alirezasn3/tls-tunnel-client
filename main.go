package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"
)

var configs []ClientConfig

var fyneLogsChannel = make(chan string)

var fyneLogs []string

type ClientConfig struct {
	ServiceName         string `json:"serviceName"`
	Connect             string `json:"connect"`
	Listen              string `json:"listen"`
	Protocol            string `json:"protocol"`
	CertificateLocation string `json:"certificateLocation"`
	KeyLocation         string `json:"KeyLocation"`
	TLSConfig           tls.Config
}

func handleError(err error, fatal bool, config *ClientConfig) bool {
	if err != nil {
		if fatal {
			log.Fatalln("["+config.ServiceName+"]"+" [error] ", err)
			fyneLogsChannel <- "[" + config.ServiceName + "]" + " [error] " + err.Error()
		} else {
			log.Println("["+config.ServiceName+"]"+" [error] ", err)
			fyneLogsChannel <- "[" + config.ServiceName + "]" + " [error] " + err.Error()
		}
		return true
	}
	return false
}

func logMessage(message string, config *ClientConfig) {
	fyneLogsChannel <- "[" + config.ServiceName + "] " + "[info] " + message
	log.Println("[" + config.ServiceName + "] " + "[info] " + message)
}

func loadConfigFile(configs *[]ClientConfig) {
	bytes, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatalln("[error] ", err)
	}
	err = json.Unmarshal(bytes, &configs)
	if err != nil {
		log.Fatalln("[error] ", err)
	}
	log.Println("[info] config file loaded")
}

func loadCertificates(config *[]ClientConfig) {
	for i := range configs {
		certificate, err := tls.LoadX509KeyPair(configs[i].CertificateLocation, configs[i].KeyLocation)
		if err != nil {
			log.Fatalln("[error] ", err)
		}
		configs[i].TLSConfig.MinVersion = tls.VersionTLS13
		configs[i].TLSConfig.Certificates = []tls.Certificate{certificate}
		configs[i].TLSConfig.InsecureSkipVerify = true
		logMessage("certificates loaded", &configs[i])
	}
}

func handleLocalTCPClient(config ClientConfig, localConnection net.Conn, err error) {
	defer localConnection.Close()

	// check if connection was successfull else exit go routine
	if handleError(err, false, &config) {
		return
	}
	logMessage("accepted connection from "+localConnection.LocalAddr().String(), &config)

	// create connection to the remote machine
	remoteConnection, err := tls.Dial("tcp", config.Connect, &config.TLSConfig)
	if handleError(err, false, &config) {
		logMessage("local connection from "+localConnection.LocalAddr().String()+" closed because could not create connection to the remote machine "+config.Connect, &config)
		return
	}
	defer remoteConnection.Close()
	logMessage(localConnection.LocalAddr().String()+" connected to "+config.Connect, &config)

	// listen for incoming traffic from local app and forward it to remote machine
	go io.Copy(remoteConnection, localConnection)

	// listen for incoming traffic from remote machine and forward it to local app
	io.Copy(localConnection, remoteConnection)

	logMessage("remote connection "+config.Connect+" closed", &config)
}

func handleLocalUDPClient(config ClientConfig, localConnection *net.UDPConn, localClientAddress *net.UDPAddr, firstChunk []byte) {
	defer logMessage("connection closed", &config)

	// create tcp tunnel to serer
	remoteConnection, err := tls.Dial("tcp", config.Connect, &config.TLSConfig)
	if err != nil {
		log.Fatalln("[error] ", err)
	}
	logMessage("connected to "+config.Connect, &config)

	// listen for incoming traffic from local app and forward it to remote machine
	go func() {
		_, err := remoteConnection.Write(firstChunk)
		handleError(err, false, &config)
		_, err = io.Copy(remoteConnection, localConnection)
		handleError(err, false, &config)
	}()

	// listen for incoming traffic from remote machine and forward it to local app
	buff := make([]byte, 1024*16)
	for {
		readBytes, err := remoteConnection.Read(buff)
		if handleError(err, false, &config) {
			break
		}
		_, err = localConnection.WriteToUDP(buff[:readBytes], localClientAddress)
		handleError(err, false, &config)
	}
}

func main() {
	go func() {
		// load client config and certificates
		loadConfigFile(&configs)
		loadCertificates(&configs)

		// add wait group to manage go routines
		var wg sync.WaitGroup

		for _, config := range configs {
			wg.Add(1)
			go func(config ClientConfig) {
				defer wg.Done()

				if config.Protocol == "tcp" {
					// create listener on local machine
					localListener, err := net.Listen("tcp", config.Listen)
					if err != nil {
						log.Fatalln("[error] ", err)
					}
					logMessage("listening on "+config.Listen, &config)
					defer localListener.Close()

					// accept new connections from local apps
					for {
						localConnection, err := localListener.Accept()
						go handleLocalTCPClient(config, localConnection, err)
					}
				} else {
					// create local udp listener
					listenAddress, err := net.ResolveUDPAddr("udp", config.Listen)
					if err != nil {
						log.Fatalln("[error] ", err)
					}
					localConnection, err := net.ListenUDP("udp", listenAddress)
					if err != nil {
						log.Fatalln("[error] ", err)
					}
					logMessage("listening on "+config.Listen, &config)

					var localClientAddress *net.UDPAddr
					// read the first chunk to get local client address
					firstChunk := make([]byte, 1024*16)
					readBytes, localClientAddress, err := localConnection.ReadFromUDP(firstChunk)
					handleError(err, false, &config)

					// udp mode only accepts udp data from one application only
					handleLocalUDPClient(config, localConnection, localClientAddress, firstChunk[:readBytes])
				}
			}(config)
		}

		wg.Wait()
	}()

	a := app.New()
	w := a.NewWindow("TLS Tunnel")

	if desk, ok := a.(desktop.App); ok {
		m := fyne.NewMenu("TLS Tunnel",
			fyne.NewMenuItem("Show", func() {
				w.Show()
			}),
		)
		desk.SetSystemTrayMenu(m)
	}

	logsList := widget.NewList(
		func() int { return len(fyneLogs) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(lii widget.ListItemID, co fyne.CanvasObject) { co.(*widget.Label).SetText(fyneLogs[lii]) },
	)

	go func() {
		for log := range fyneLogsChannel {
			fyneLogs = append(fyneLogs, log)
			logsList.Refresh()
			logsList.ScrollToBottom()
		}
	}()

	w.Resize(fyne.NewSize(1280, 720))
	w.CenterOnScreen()
	w.SetCloseIntercept(func() { w.Hide() })
	w.SetContent(logsList)
	w.ShowAndRun()
}
