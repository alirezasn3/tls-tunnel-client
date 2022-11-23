// var logs []string
// var logsList *widget.List
// func main() {
// 	debug.SetGCPercent(-1)
// 	a := app.New()
// 	w := a.NewWindow("TLS Tunnel Client")
// 	a.Settings().SetTheme(theme.LightTheme())
// 	w.SetFixedSize(true)
// 	w.Resize(fyne.NewSize(400, 400))
// 	w.CenterOnScreen()
// 	// vars
// 	connectTo := "135.181.88.125:8080"
// 	listenOn := "127.0.0.1:1194"
// 	// bindings
// 	connectToBinding := binding.BindString(&connectTo)
// 	listenOnBinding := binding.BindString(&listenOn)
// 	connectToWidget := widget.NewEntry()
// 	connectToWidget.SetPlaceHolder("Enter text...")
// 	connectToWidget.Bind(connectToBinding)
// 	connectToWidget.OnChanged = func(s string) {}
// 	listenOnEntry := widget.NewEntry()
// 	listenOnEntry.SetPlaceHolder("Enter text...")
// 	listenOnEntry.Bind(listenOnBinding)
// 	listenOnLable := widget.NewLabel("Connect To")
// 	connectToLable := widget.NewLabel("Listen On")
// 	formsContainer := container.New(layout.NewFormLayout(),
// 		connectToLable, listenOnEntry, listenOnLable, connectToWidget,
// 	)
// 	var connectButton *widget.Button
// 	connectButton = widget.NewButton("connect", func() {
// 		go func() {
// 			connectButton.SetText("disconnect")
// 			success := runClient(listenOn, connectTo)
// 			if !success {
// 				connectButton.SetText("connect")
// 			}
// 		}()
// 	})
// 	buttonsContainer := container.New(layout.NewHBoxLayout(),
// 		layout.NewSpacer(), connectButton, layout.NewSpacer(),
// 	)
// 	logsList = widget.NewList(
// 		func() int {
// 			return len(logs)
// 		},
// 		func() fyne.CanvasObject {
// 			return widget.NewLabel("")
// 		},
// 		func(i widget.ListItemID, o fyne.CanvasObject) {
// 			o.(*widget.Label).SetText(logs[i])
// 		},
// 	)
// 	logsListContainer := container.NewBorder(widget.NewLabel("Logs:"), nil, nil, nil, logsList)
// 	content := container.NewBorder(formsContainer, buttonsContainer, nil, nil, logsListContainer)
// 	w.SetContent(content)
// 	w.ShowAndRun()
// }

package main

import (
	"crypto/tls"
	"encoding/json"
	"log"
	"net"
	"os"
	"sync"
)

var config ClientConfig

type ClientConfig struct {
	Connect             string `json:"connect"`
	Listen              string `json:"listen"`
	CertificateLocation string `json:"certificateLocation"`
	KeyLocation         string `json:"KeyLocation"`
	TLSConfig           tls.Config
}

func handleError(err error, fatal bool) bool {
	if err != nil {
		if fatal {
			log.Fatalln("[error] ", err)
		} else {
			log.Println("[error] ", err)
		}
		return true
	}
	return false
}

func logMessage(message string) {
	log.Println("[info] " + message)
}

func loadConfigFile(config *ClientConfig) {
	bytes, err := os.ReadFile("config.json")
	handleError(err, true)
	err = json.Unmarshal(bytes, &config)
	handleError(err, true)
	logMessage("config file loaded")
}

func loadCertificates(config *ClientConfig) {
	certificate, err := tls.LoadX509KeyPair(config.CertificateLocation, config.KeyLocation)
	handleError(err, true)
	config.TLSConfig.Certificates = []tls.Certificate{certificate}
	config.TLSConfig.InsecureSkipVerify = true
	logMessage("certificates loaded")
}

func handleLocalClient(localConnection net.Conn, err error) {
	defer localConnection.Close()

	// check if connection was successfull else exit go routine
	if handleError(err, false) {
		return
	}
	logMessage("accepted connection from " + localConnection.LocalAddr().String())

	// create connection to the remote machine
	remoteConnection, err := tls.Dial("tcp", config.Connect, &config.TLSConfig)
	if handleError(err, false) {
		logMessage("local connection from " + localConnection.LocalAddr().String() + " closed because could not create connection to the remote machine " + config.Connect)
		return
	}
	defer remoteConnection.Close()
	logMessage(localConnection.LocalAddr().String() + " connected to " + config.Connect)

	// create wait group for go routines
	var wg sync.WaitGroup

	// listen for incoming traffic from local app and forward it to remote machine
	wg.Add(1)
	go func() {
		defer wg.Done()

		buff := make([]byte, 8192)

		for {
			readBytes, _ := localConnection.Read(buff) // TODO: check for error
			remoteConnection.Write(buff[:readBytes])   // TODO: check for error
		}
	}()

	// listen for incoming traffic from remote machine and forward it to local app
	wg.Add(1)
	go func() {
		defer wg.Done()

		buff := make([]byte, 8192)

		for {
			readBytes, _ := remoteConnection.Read(buff) // TODO: check for error
			localConnection.Write(buff[:readBytes])     // TODO: check for error
		}
	}()

	// wait for go routines to finish
	wg.Wait()

	logMessage("connection closed")
}

func main() {
	// load client config and certificates
	loadConfigFile(&config)
	loadCertificates(&config)
	config.TLSConfig.MinVersion = tls.VersionTLS13

	// create listener on local machine
	// if config.Protocol == "tcp" {
	var err error
	localListener, err := net.Listen("tcp", config.Listen)
	handleError(err, true)
	logMessage("listening on " + config.Listen)

	// accept new connections from local apps
	for {
		localConnection, err := localListener.Accept()
		go handleLocalClient(localConnection, err)
	}
}
