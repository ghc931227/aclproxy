package acl

import (
	"aclproxy/utils"
	"bufio"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/idna"
	"net"
	"os"
	"strconv"
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/oschwald/geoip2-golang"
)

const entryCacheSize = 1024

type Engine struct {
	DefaultAction Action
	Entries       []Entry
	Cache         *lru.ARCCache[cacheKey, cacheValue]
	ResolveIPAddr func(string) (*net.IPAddr, error)
	GeoIPReader   *geoip2.Reader
}

type cacheKey struct {
	Host  string
	Port  uint16
	IsUDP bool
}

type cacheValue struct {
	Action Action
	Arg    string
}

func LoadFromFile(filename string, resolveIPAddr func(string) (*net.IPAddr, error), geoIPLoadFunc func() (*geoip2.Reader, error)) (*Engine, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	entries := make([]Entry, 0, 1024)
	var geoIPReader *geoip2.Reader
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			// Ignore empty lines & comments
			continue
		}
		entry, err := ParseEntry(line)
		if err != nil {
			return nil, err
		}
		if _, ok := entry.Matcher.(*countryMatcher); ok && geoIPReader == nil {
			geoIPReader, err = geoIPLoadFunc() // lazy load GeoIP reader only when needed
			if err != nil {
				return nil, err
			}
		}
		entries = append(entries, entry)
	}
	cache, err := lru.NewARC[cacheKey, cacheValue](entryCacheSize)
	if err != nil {
		return nil, err
	}
	return &Engine{
		DefaultAction: ActionProxy,
		Entries:       entries,
		Cache:         cache,
		ResolveIPAddr: resolveIPAddr,
		GeoIPReader:   geoIPReader,
	}, nil
}

// action, arg, isDomain, resolvedIP, error
func (e *Engine) ResolveAndMatch(host string, port uint16, isUDP bool) (Action, string, bool, *net.IPAddr, error) {
	ip, zone := utils.ParseIPZone(host)
	if ip == nil {
		// Domain
		// idna domain: unicode domain name
		if strings.HasPrefix(host, "xn--") {
			vhost, err := idna.ToUnicode(host)
			if err == nil {
				host = vhost
			}
		}
		ipAddr, err := e.ResolveIPAddr(host)
		if ce, ok := e.Cache.Get(cacheKey{host, port, isUDP}); ok {
			// Cache hit
			logrus.WithFields(logrus.Fields{
				"action": ActionToString(ce.Action, ce.Arg),
				"host":   host,
				"port":   strconv.Itoa(int(port)),
			}).Debug("HTTP request")
			return ce.Action, ce.Arg, true, ipAddr, err
		}
		for _, entry := range e.Entries {
			mReq := MatchRequest{
				Domain: host,
				Port:   port,
				DB:     e.GeoIPReader,
			}
			if ipAddr != nil {
				mReq.IP = ipAddr.IP
			}
			if isUDP {
				mReq.Protocol = ProtocolUDP
			} else {
				mReq.Protocol = ProtocolTCP
			}
			if entry.Match(mReq) {
				e.Cache.Add(cacheKey{host, port, isUDP},
					cacheValue{entry.Action, entry.ActionArg})
				logrus.WithFields(logrus.Fields{
					"action": ActionToString(entry.Action, entry.ActionArg),
					"host":   host,
					"port":   strconv.Itoa(int(port)),
				}).Debug("HTTP request")
				return entry.Action, entry.ActionArg, true, ipAddr, err
			}
		}
		e.Cache.Add(cacheKey{host, port, isUDP}, cacheValue{e.DefaultAction, ""})
		logrus.WithFields(logrus.Fields{
			"action": ActionToString(e.DefaultAction, ""),
			"host":   host,
			"port":   strconv.Itoa(int(port)),
		}).Debug("HTTP request")
		return e.DefaultAction, "", true, ipAddr, err
	} else {
		ipAddr := &net.IPAddr{
			IP:   ip,
			Zone: zone,
		}
		// IP
		if ce, ok := e.Cache.Get(cacheKey{ip.String(), port, isUDP}); ok {
			// Cache hit
			logrus.WithFields(logrus.Fields{
				"action": ActionToString(ce.Action, ce.Arg),
				"host":   host,
				"port":   strconv.Itoa(int(port)),
			}).Debug("HTTP request")
			return ce.Action, ce.Arg, false, ipAddr, nil
		}
		for _, entry := range e.Entries {
			mReq := MatchRequest{
				IP:   ip,
				Port: port,
				DB:   e.GeoIPReader,
			}
			if isUDP {
				mReq.Protocol = ProtocolUDP
			} else {
				mReq.Protocol = ProtocolTCP
			}
			if entry.Match(mReq) {
				e.Cache.Add(cacheKey{ip.String(), port, isUDP},
					cacheValue{entry.Action, entry.ActionArg})
				logrus.WithFields(logrus.Fields{
					"action": ActionToString(entry.Action, entry.ActionArg),
					"host":   host,
					"port":   strconv.Itoa(int(port)),
				}).Debug("HTTP request")
				return entry.Action, entry.ActionArg, false, ipAddr, nil
			}
		}
		e.Cache.Add(cacheKey{ip.String(), port, isUDP}, cacheValue{e.DefaultAction, ""})
		logrus.WithFields(logrus.Fields{
			"action": ActionToString(e.DefaultAction, ""),
			"host":   host,
			"port":   strconv.Itoa(int(port)),
		}).Debug("HTTP request")
		return e.DefaultAction, "", false, ipAddr, nil
	}
}
