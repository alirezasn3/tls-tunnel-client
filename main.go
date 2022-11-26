package main

import (
	"crypto/tls"
	"encoding/json"
	"log"
	"net"
	"os"
)

var config ClientConfig

type ClientConfig struct {
	Connect             string `json:"connect"`
	Listen              string `json:"listen"`
	Protocol            string `json:"protocol"`
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

func handleLocalTCPClient(localConnection net.Conn, err error) {
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

	go func() {
		buff := make([]byte, 1024*16)
		for {
			readBytes, _ := localConnection.Read(buff) // TODO: check for error
			remoteConnection.Write(buff[:readBytes])   // TODO: check for error
		}
	}()

	buff := make([]byte, 1024*16)
	for {
		readBytes, _ := remoteConnection.Read(buff) // TODO: check for error
		localConnection.Write(buff[:readBytes])     // TODO: check for error
	}
}

func main() {
	// load client config and certificates
	loadConfigFile(&config)
	loadCertificates(&config)
	config.TLSConfig.MinVersion = tls.VersionTLS13

	// create listener on local machine
	if config.Protocol == "tcp" {
		localListener, err := net.Listen("tcp", config.Listen)
		handleError(err, true)
		logMessage("listening on " + config.Listen)
		defer localListener.Close()

		// accept new connections from local apps
		for {
			localConnection, err := localListener.Accept()
			go handleLocalTCPClient(localConnection, err)
		}
	} else {
		defer logMessage("connection closed")

		// intial local client address to avoid extra allocations
		var localClientAddress *net.UDPAddr

		// create local udp listener
		listenAddress, err := net.ResolveUDPAddr("udp", config.Listen)
		handleError(err, true)
		localConnection, err := net.ListenUDP("udp", listenAddress)
		handleError(err, true)
		logMessage("listening on " + config.Listen)

		// create tcp tunnel to serer
		remoteConnection, err := tls.Dial("tcp", config.Connect, &config.TLSConfig)
		handleError(err, true)
		logMessage("connected to " + config.Connect)

		// listen for incoming traffic from local app and forward it to remote machine
		go func() {
			// read the first chunk to get local client address and forward the chunk
			defer localConnection.Close()
			buff := make([]byte, 1024*16)
			var readBytes int
			readBytes, localClientAddress, err = localConnection.ReadFromUDP(buff)
			_, err = remoteConnection.Write(buff[:readBytes])
			handleError(err, false)
			// repeat the last step in a loop
			for {
				readBytes, _, err = localConnection.ReadFromUDP(buff)
				if handleError(err, false) {
					break
				}
				remoteConnection.Write(buff[:readBytes])
			}
		}()

		// listen for incoming traffic from remote machine and forward it to local app
		defer remoteConnection.Close()
		buff := make([]byte, 1024*16)
		for {
			readBytes, err := remoteConnection.Read(buff)
			if handleError(err, false) {
				break
			}
			localConnection.WriteToUDP(buff[:readBytes], localClientAddress)
		}
	}
}
