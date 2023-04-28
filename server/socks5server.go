package server

import (
	"aclproxy/acl"
	"aclproxy/utils"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
)

import (
	"net"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/txthinking/socks5"
	"golang.org/x/net/proxy"
)

var (
	ErrUnsupportedCmd = errors.New("unsupported command")
	ErrUserPassAuth   = errors.New("invalid username or password")
)

type Socks5Server struct {
	ProxyDialer proxy.Dialer
	Transport   utils.ClientTransport
	AuthFunc    func(username, password string) bool
	Method      byte
	TCPAddr     *net.TCPAddr
	TCPTimeout  time.Duration
	ACLEngine   *acl.Engine
	DisableUDP  bool

	tcpListener *net.TCPListener
}

func NewSocks5Server(proxyDialer proxy.Dialer, transport *utils.ClientTransport, addr string, authFunc func(username, password string) bool,
	tcpTimeout time.Duration, aclEngine *acl.Engine, disableUDP bool,
) (*Socks5Server, error) {
	tAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	m := socks5.MethodNone
	if authFunc != nil {
		m = socks5.MethodUsernamePassword
	}
	s := &Socks5Server{
		ProxyDialer: proxyDialer,
		Transport:   *transport,
		AuthFunc:    authFunc,
		Method:      m,
		TCPAddr:     tAddr,
		TCPTimeout:  tcpTimeout,
		ACLEngine:   aclEngine,
		DisableUDP:  disableUDP,
	}
	return s, nil
}

func (s *Socks5Server) negotiate(c *net.TCPConn) error {
	rq, err := socks5.NewNegotiationRequestFrom(c)
	if err != nil {
		return err
	}
	var got bool
	var m byte
	for _, m = range rq.Methods {
		if m == s.Method {
			got = true
		}
	}
	if !got {
		rp := socks5.NewNegotiationReply(socks5.MethodUnsupportAll)
		if _, err := rp.WriteTo(c); err != nil {
			return err
		}
	}
	rp := socks5.NewNegotiationReply(s.Method)
	if _, err := rp.WriteTo(c); err != nil {
		return err
	}

	if s.Method == socks5.MethodUsernamePassword {
		urq, err := socks5.NewUserPassNegotiationRequestFrom(c)
		if err != nil {
			return err
		}
		if !s.AuthFunc(string(urq.Uname), string(urq.Passwd)) {
			urp := socks5.NewUserPassNegotiationReply(socks5.UserPassStatusFailure)
			if _, err := urp.WriteTo(c); err != nil {
				return err
			}
			return ErrUserPassAuth
		}
		urp := socks5.NewUserPassNegotiationReply(socks5.UserPassStatusSuccess)
		if _, err := urp.WriteTo(c); err != nil {
			return err
		}
	}
	return nil
}

func (s *Socks5Server) ListenAndServe() error {
	var err error
	s.tcpListener, err = net.ListenTCP("tcp", s.TCPAddr)
	if err != nil {
		return err
	}
	defer s.tcpListener.Close()
	for {
		c, err := s.tcpListener.AcceptTCP()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			if s.TCPTimeout != 0 {
				if err := c.SetDeadline(time.Now().Add(s.TCPTimeout)); err != nil {
					return
				}
			}
			if err := s.negotiate(c); err != nil {
				return
			}
			r, err := socks5.NewRequestFrom(c)
			if err != nil {
				return
			}
			_ = s.handle(c, r)
		}()
	}
}

func (s *Socks5Server) handle(c *net.TCPConn, r *socks5.Request) error {
	if r.Cmd == socks5.CmdConnect {
		// TCP
		return s.handleTCP(c, r)
	} else {
		_ = sendReply(c, socks5.RepCommandNotSupported)
		return ErrUnsupportedCmd
	}
}

func (s *Socks5Server) handleTCP(c *net.TCPConn, r *socks5.Request) error {
	host, port, addr := parseRequestAddress(r)
	action, arg := acl.ActionProxy, ""
	var ipAddr *net.IPAddr
	var resErr error
	if s.ACLEngine != nil {
		action, arg, _, ipAddr, resErr = s.ACLEngine.ResolveAndMatch(host, port, false)
		// Doesn't always matter if the resolution fails, as we may send it through HyClient
	}
	TCPRequestFunc(c.RemoteAddr(), addr, action, arg)
	var closeErr error
	defer func() {
		TCPErrorFunc(c.RemoteAddr(), addr, closeErr)
	}()
	// Handle according to the action
	switch action {
	case acl.ActionDirect:
		if resErr != nil {
			_ = sendReply(c, socks5.RepHostUnreachable)
			closeErr = resErr
			return resErr
		}
		rc, err := s.Transport.DialTCP(&net.TCPAddr{
			IP:   ipAddr.IP,
			Port: int(port),
			Zone: ipAddr.Zone,
		})
		if err != nil {
			_ = sendReply(c, socks5.RepHostUnreachable)
			closeErr = err
			return err
		}
		defer rc.Close()
		_ = sendReply(c, socks5.RepSuccess)
		closeErr = utils.PipePairWithTimeout(c, rc, s.TCPTimeout)
		return nil
	case acl.ActionProxy:
		rc, err := s.ProxyDialer.Dial("tcp", addr)
		if err != nil {
			_ = sendReply(c, socks5.RepHostUnreachable)
			closeErr = err
			return err
		}
		defer rc.Close()
		_ = sendReply(c, socks5.RepSuccess)
		closeErr = utils.PipePairWithTimeout(c, rc, s.TCPTimeout)
		return nil
	case acl.ActionBlock:
		_ = sendReply(c, socks5.RepHostUnreachable)
		closeErr = errors.New("blocked in ACL")
		return nil
	case acl.ActionHijack:
		hijackIPAddr, err := s.Transport.ResolveIPAddr(arg)
		if err != nil {
			_ = sendReply(c, socks5.RepHostUnreachable)
			closeErr = err
			return err
		}
		rc, err := s.Transport.DialTCP(&net.TCPAddr{
			IP:   hijackIPAddr.IP,
			Port: int(port),
			Zone: hijackIPAddr.Zone,
		})
		if err != nil {
			_ = sendReply(c, socks5.RepHostUnreachable)
			closeErr = err
			return err
		}
		defer rc.Close()
		_ = sendReply(c, socks5.RepSuccess)
		closeErr = utils.PipePairWithTimeout(c, rc, s.TCPTimeout)
		return nil
	default:
		_ = sendReply(c, socks5.RepServerFailure)
		closeErr = fmt.Errorf("unknown action %d", action)
		return nil
	}
}

func sendReply(conn *net.TCPConn, rep byte) error {
	p := socks5.NewReply(rep, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
	_, err := p.WriteTo(conn)
	return err
}

func parseRequestAddress(r *socks5.Request) (host string, port uint16, addr string) {
	p := binary.BigEndian.Uint16(r.DstPort)
	if r.Atyp == socks5.ATYPDomain {
		d := string(r.DstAddr[1:])
		return d, p, net.JoinHostPort(d, strconv.Itoa(int(p)))
	} else {
		ipStr := net.IP(r.DstAddr).String()
		return ipStr, p, net.JoinHostPort(ipStr, strconv.Itoa(int(p)))
	}
}

func TCPRequestFunc(addr net.Addr, reqAddr string, action acl.Action, arg string) {
	logrus.WithFields(logrus.Fields{
		"action": acl.ActionToString(action, arg),
		"src":    utils.DefaultIPMasker.Mask(addr.String()),
		"dst":    utils.DefaultIPMasker.Mask(reqAddr),
	}).Debug("SOCKS5 TCP request")
}
func TCPErrorFunc(addr net.Addr, reqAddr string, err error) {
	if err != io.EOF {
		logrus.WithFields(logrus.Fields{
			"error": err,
			"src":   utils.DefaultIPMasker.Mask(addr.String()),
			"dst":   utils.DefaultIPMasker.Mask(reqAddr),
		}).Info("SOCKS5 TCP error")
	} else {
		logrus.WithFields(logrus.Fields{
			"src": utils.DefaultIPMasker.Mask(addr.String()),
			"dst": utils.DefaultIPMasker.Mask(reqAddr),
		}).Info("SOCKS5 TCP EOF")
	}
}
