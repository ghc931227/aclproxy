package server

import (
	"aclproxy/acl"
	"aclproxy/utils"
	"errors"
	"fmt"
	"github.com/elazarl/goproxy/ext/auth"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
)

func NewProxyHTTPServer(proxyDialer proxy.Dialer, transport *utils.ClientTransport, idleTimeout time.Duration,
	aclEngine *acl.Engine,
	basicAuthFunc func(user, password string) bool,
) (*goproxy.ProxyHttpServer, error) {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Logger = &nopLogger{}
	proxy.NonproxyHandler = http.NotFoundHandler()
	proxy.Tr = &http.Transport{
		Dial: func(network, addr string) (conn net.Conn, err error) {
			defer func() {
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"error": err,
						"dst":   utils.DefaultIPMasker.Mask(addr),
					}).Info("HTTP error")
				}
			}()
			// Parse addr string
			host, port, err := utils.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			// ACL
			action, arg := acl.ActionProxy, ""
			var ipAddr *net.IPAddr
			var resErr error
			if aclEngine != nil {
				action, arg, _, ipAddr, resErr = aclEngine.ResolveAndMatch(host, port, false)
				// Doesn't always matter if the resolution fails, as we may send it through HyClient
			}
			logrus.WithFields(logrus.Fields{
				"action":  acl.ActionToString(action, arg),
				"request": utils.ParseRequest(addr),
			}).Debug("HTTP request")
			// Handle according to the action
			switch action {
			case acl.ActionDirect:
				if resErr != nil {
					return nil, resErr
				}
				return transport.DialTCP(&net.TCPAddr{
					IP:   ipAddr.IP,
					Port: int(port),
					Zone: ipAddr.Zone,
				})
			case acl.ActionProxy:
				return proxyDialer.Dial("tcp", addr)
			case acl.ActionBlock:
				return nil, errors.New("blocked by ACL")
			case acl.ActionHijack:
				argHost, argPort, err := utils.SplitHostPort(arg)
				if err != nil {
					if strings.HasSuffix(err.Error(), " missing port in address") {
						argHost = arg
						argPort = port
					} else {
						return nil, err
					}
				}
				hijackIPAddr, err := transport.ResolveIPAddr(argHost)
				if err != nil {
					return nil, err
				}
				return transport.DialTCP(&net.TCPAddr{
					IP:   hijackIPAddr.IP,
					Port: int(argPort),
					Zone: hijackIPAddr.Zone,
				})
			default:
				return nil, fmt.Errorf("unknown action %d", action)
			}
		},
		IdleConnTimeout: idleTimeout,
		// Disable HTTP2 support? ref: https://github.com/elazarl/goproxy/issues/361
	}
	proxy.ConnectDial = nil
	if basicAuthFunc != nil {
		auth.ProxyBasic(proxy, "", basicAuthFunc)
	}
	return proxy, nil
}

type nopLogger struct{}

func (n *nopLogger) Printf(format string, v ...interface{}) {}
