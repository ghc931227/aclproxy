package main

import (
	"aclproxy/acl"
	"aclproxy/server"
	"aclproxy/upstream"
	"aclproxy/utils"
	"encoding/json"
	"fmt"
	"github.com/oschwald/geoip2-golang"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type config struct {
	Listen string
	Router string
	Acl    string
	Mmdb   string
}

func main() {
	// log config
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetFormatter(&logrus.TextFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
	})

	if len(os.Args) < 2 {
		logrus.WithFields(logrus.Fields{
			"error": "no config provided",
		}).Fatal("Failed to parse client configuration")
	}
	configFile := os.Args[1]
	if configFile == "" {
		logrus.WithFields(logrus.Fields{
			"error": "no config provided",
		}).Fatal("Failed to parse client configuration")
	}
	bytes, err := ioutil.ReadFile(configFile)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Fatal("Failed to parse client configuration")
	}
	var config config
	err = json.Unmarshal(bytes, &config)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Fatal("Failed to parse client configuration")
	}
	config.Listen = strings.Replace(config.Listen, "socks://", "socks5://", 1)
	config.Router = strings.Replace(config.Router, "socks://", "socks5://", 1)

	upstreamURL, err := url.Parse(config.Listen)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Fatal("Failed to parse client configuration")
	}
	if upstreamURL.Scheme == "http" {
		proxy.RegisterDialerType("http", upstream.NewHttpProxy)
	}
	upstreamDialer, err := proxy.FromURL(upstreamURL, proxy.Direct)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Fatal("Failed to parse client configuration")
	}

	routerURL, err := url.Parse(config.Router)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Fatal("Failed to parse client configuration")
	}

	aclEngine, err := acl.LoadFromFile(config.Acl, utils.DefaultClientTransport.ResolveIPAddr,
		func() (*geoip2.Reader, error) {
			return geoip2.Open(config.Mmdb)
		},
	)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Fatal("Failed to parse client configuration")
	}

	var authFunc func(user, password string) bool
	routerPassword, routerPasswordSet := routerURL.User.Password()
	if routerPasswordSet {
		authFunc = func(username, password string) bool {
			return username == routerURL.User.Username() && password == routerPassword
		}
	}

	if routerURL.Scheme == "socks5" {
		socks5server, _ := server.NewSocks5Server(upstreamDialer, utils.DefaultClientTransport, routerURL.Host,
			authFunc, time.Duration(8)*time.Second, aclEngine, true)
		logrus.Info(fmt.Sprintf("[%s] %s up and running", routerURL.Host, routerURL.Scheme))
		err = socks5server.ListenAndServe()
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Fatal("Failed to start proxy server")
		}
	} else if routerURL.Scheme == "http" {
		httpServer, _ := server.NewProxyHTTPServer(upstreamDialer, utils.DefaultClientTransport, time.Duration(8)*time.Second, aclEngine, authFunc)
		logrus.Info(fmt.Sprintf("[%s] %s up and running", routerURL.Host, routerURL.Scheme))
		err = http.ListenAndServe(routerURL.Host, httpServer)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Fatal("Failed to start proxy server")
		}
	} else {
		logrus.Fatal("Unsupported router proxy scheme")
	}
}
