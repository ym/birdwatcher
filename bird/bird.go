package bird

import (
	"bytes"
	"io"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"os/exec"
)

type BirdWatcher struct {
	ClientConf    BirdConfig
	StatusConf    StatusConfig
	ParserConf    ParserConfig
	IPVersion     string
	RateLimitConf struct {
		sync.RWMutex
		Conf RateLimitConfig
	}
	Cache Cache
}

type Cache struct {
	sync.RWMutex
	m map[string]Parsed
}

// NewBirdWatcher ..
func NewBirdWatcher(clientConf BirdConfig, statusConfig StatusConfig, parserConfig ParserConfig, ipVersion string) BirdWatcher {
	return BirdWatcher{
		ClientConf: clientConf,
		StatusConf: statusConfig,
		ParserConf: parserConfig,
		IPVersion:  ipVersion,
		Cache:      Cache{m: make(map[string]Parsed)},
	}
}

var NilParse Parsed = (Parsed)(nil)
var BirdError Parsed = Parsed{"error": "bird unreachable"}

func isSpecial(ret Parsed) bool {
	return reflect.DeepEqual(ret, NilParse) || reflect.DeepEqual(ret, BirdError)
}

func (b *BirdWatcher) fromCache(key string) (Parsed, bool) {
	b.Cache.RLock()
	val, ok := b.Cache.m[key]
	b.Cache.RUnlock()
	if !ok {
		return NilParse, false
	}

	ttl, correct := val["ttl"].(time.Time)
	if !correct || ttl.Before(time.Now()) {
		return NilParse, false
	}

	return val, ok
}

func (b *BirdWatcher) toCache(key string, val Parsed) {
	val["ttl"] = time.Now().Add(5 * time.Minute)
	b.Cache.Lock()
	b.Cache.m[key] = val
	b.Cache.Unlock()
}

// Run ..
func (b *BirdWatcher) Run(args string) (io.Reader, error) {
	args = "show " + args
	argsList := strings.Split(args, " ")

	out, err := exec.Command(b.ClientConf.BirdCmd, argsList...).Output()
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(out), nil
}

// InstallRateLimitReset ..
func (b *BirdWatcher) InstallRateLimitReset() {
	go func() {
		c := time.Tick(time.Second)

		for range c {
			b.RateLimitConf.Lock()
			b.RateLimitConf.Conf.Reqs = b.RateLimitConf.Conf.Max
			b.RateLimitConf.Unlock()
		}
	}()
}

func (b *BirdWatcher) checkRateLimit() bool {
	b.RateLimitConf.RLock()
	check := !b.RateLimitConf.Conf.Enabled
	b.RateLimitConf.RUnlock()
	if check {
		return true
	}

	b.RateLimitConf.RLock()
	check = b.RateLimitConf.Conf.Reqs < 1
	b.RateLimitConf.RUnlock()
	if check {
		return false
	}

	b.RateLimitConf.Lock()
	b.RateLimitConf.Conf.Reqs--
	b.RateLimitConf.Unlock()

	return true
}

// RunAndParse ..
func (b *BirdWatcher) RunAndParse(cmd string, parser func(io.Reader) Parsed) (Parsed, bool) {
	if val, ok := b.fromCache(cmd); ok {
		return val, true
	}

	if !b.checkRateLimit() {
		return NilParse, false
	}

	out, err := b.Run(cmd)
	if err != nil {
		// ignore errors for now
		return BirdError, false
	}

	parsed := parser(out)
	b.toCache(cmd, parsed)
	return parsed, false
}

// Status ..
func (b *BirdWatcher) Status() (Parsed, bool) {
	birdStatus, ok := b.RunAndParse("status", b.parseStatus)
	if isSpecial(birdStatus) {
		return birdStatus, ok
	}
	status := birdStatus["status"].(Parsed)

	// Last Reconfig Timestamp source:
	var lastReconfig string
	switch b.StatusConf.ReconfigTimestampSource {
	case "bird":
		lastReconfig = status["last_reconfig"].(string)
		break
	case "config_modified":
		lastReconfig = lastReconfigTimestampFromFileStat(
			b.ClientConf.ConfigFilename,
		)
	case "config_regex":
		lastReconfig = lastReconfigTimestampFromFileContent(
			b.ClientConf.ConfigFilename,
			b.StatusConf.ReconfigTimestampMatch,
		)
	}

	status["last_reconfig"] = lastReconfig

	// Filter fields
	for _, field := range b.StatusConf.FilterFields {
		status[field] = nil
	}

	birdStatus["status"] = status

	return birdStatus, ok
}

// Protocols ..
func (b *BirdWatcher) Protocols() (Parsed, bool) {
	return b.RunAndParse("protocols all", b.parseProtocols)
}

// ProtocolsBgp ..
func (b *BirdWatcher) ProtocolsBgp() (Parsed, bool) {
	p, fromCache := b.Protocols()
	if isSpecial(p) {
		return p, fromCache
	}
	protocols := p["protocols"].([]string)

	bgpProto := Parsed{}

	for _, v := range protocols {
		if strings.Contains(v, " BGP ") {
			key := strings.Split(v, " ")[0]
			bgpProto[key] = b.parseBgp(v)
		}
	}

	return Parsed{"protocols": bgpProto, "ttl": p["ttl"]}, fromCache
}

// Symbols ..
func (b *BirdWatcher) Symbols() (Parsed, bool) {
	return b.RunAndParse("symbols", b.parseSymbols)
}

// RoutesPrefixed ..
func (b *BirdWatcher) RoutesPrefixed(prefix string) (Parsed, bool) {
	cmd := b.routeQueryForChannel("route all")
	return b.RunAndParse(cmd, b.parseRoutes)
}

// RoutesProto ..
func (b *BirdWatcher) RoutesProto(protocol string) (Parsed, bool) {
	cmd := b.routeQueryForChannel("route all protocol " + protocol)
	return b.RunAndParse(cmd, b.parseRoutes)
}

// RoutesProtoCount ..
func (b *BirdWatcher) RoutesProtoCount(protocol string) (Parsed, bool) {
	cmd := b.routeQueryForChannel("route protocol "+protocol) + " count"
	return b.RunAndParse(cmd, b.parseRoutes)
}

// RoutesFiltered ..
func (b *BirdWatcher) RoutesFiltered(protocol string) (Parsed, bool) {
	cmd := b.routeQueryForChannel("route all filtered " + protocol)
	return b.RunAndParse(cmd, b.parseRoutes)
}

// RoutesExport ..
func (b *BirdWatcher) RoutesExport(protocol string) (Parsed, bool) {
	cmd := b.routeQueryForChannel("route all export " + protocol)
	return b.RunAndParse(cmd, b.parseRoutes)
}

// RoutesNoExport ..
func (b *BirdWatcher) RoutesNoExport(protocol string) (Parsed, bool) {

	// In case we have a multi table setup, we have to query
	// the pipe protocol.
	if b.ParserConf.PerPeerTables &&
		strings.HasPrefix(protocol, b.ParserConf.PeerProtocolPrefix) {

		// Replace prefix
		protocol = b.ParserConf.PipeProtocolPrefix +
			protocol[len(b.ParserConf.PeerProtocolPrefix):]
	}

	cmd := b.routeQueryForChannel("route all noexport " + protocol)
	return b.RunAndParse(cmd, b.parseRoutes)
}

// RoutesExportCount ..
func (b *BirdWatcher) RoutesExportCount(protocol string) (Parsed, bool) {
	cmd := b.routeQueryForChannel("route export "+protocol) + " count"
	return b.RunAndParse(cmd, b.parseRoutesCount)
}

// RoutesTable ..
func (b *BirdWatcher) RoutesTable(table string) (Parsed, bool) {
	return b.RunAndParse("route table '"+table+"' all", b.parseRoutes)
}

// RoutesTableCount ..
func (b *BirdWatcher) RoutesTableCount(table string) (Parsed, bool) {
	return b.RunAndParse("route table '"+table+"' count", b.parseRoutesCount)
}

// RoutesLookupTable ..
func (b *BirdWatcher) RoutesLookupTable(net string, table string) (Parsed, bool) {
	return b.RunAndParse("route for "+net+" table '"+table+"' all", b.parseRoutes)
}

// RoutesLookupProtocol ..
func (b *BirdWatcher) RoutesLookupProtocol(net string, protocol string) (Parsed, bool) {
	return b.RunAndParse("route for "+net+" protocol '"+protocol+"' all", b.parseRoutes)
}

// RoutesPeer ..
func (b *BirdWatcher) RoutesPeer(peer string) (Parsed, bool) {
	cmd := b.routeQueryForChannel("route export " + peer)
	return b.RunAndParse(cmd, b.parseRoutes)
}

// RoutesDump ..
func (b *BirdWatcher) RoutesDump() (Parsed, bool) {
	if b.ParserConf.PerPeerTables {
		return b.RoutesDumpPerPeerTable()
	}

	return b.RoutesDumpSingleTable()
}

// RoutesDumpSingleTable ..
func (b *BirdWatcher) RoutesDumpSingleTable() (Parsed, bool) {
	importedRes, cached := b.RunAndParse(b.routeQueryForChannel("route all"), b.parseRoutes)
	filteredRes, _ := b.RunAndParse(b.routeQueryForChannel("route all filtered"), b.parseRoutes)

	imported := importedRes["routes"]
	filtered := filteredRes["routes"]

	result := Parsed{
		"imported": imported,
		"filtered": filtered,
	}

	return result, cached
}

// RoutesDumpPerPeerTable ..
func (b *BirdWatcher) RoutesDumpPerPeerTable() (Parsed, bool) {
	importedRes, cached := b.RunAndParse(b.routeQueryForChannel("route all"), b.parseRoutes)
	imported := importedRes["routes"]
	filtered := []Parsed{}

	// Get protocols with filtered routes
	protocolsRes, _ := b.ProtocolsBgp()
	protocols := protocolsRes["protocols"].(Parsed)

	for protocol, details := range protocols {
		details, ok := details.(Parsed)
		if !ok {
			continue
		}
		counters, ok := details["routes"].(Parsed)
		if !ok {
			continue
		}
		filterCount := counters["filtered"]
		if filterCount == 0 {
			continue // nothing to do here.
		}
		// Lookup filtered routes
		pfilteredRes, _ := b.RoutesFiltered(protocol)

		pfiltered, ok := pfilteredRes["routes"].([]Parsed)
		if !ok {
			continue // something went wrong...
		}

		filtered = append(filtered, pfiltered...)
	}

	result := Parsed{
		"imported": imported,
		"filtered": filtered,
	}

	return result, cached
}

func (b *BirdWatcher) routeQueryForChannel(cmd string) string {
	status, _ := b.Status()
	birdStatus, ok := status["status"].(Parsed)
	if !ok {
		return cmd
	}

	version, ok := birdStatus["version"].(string)
	if !ok {
		return cmd
	}

	v, err := strconv.Atoi(string(version[0]))
	if err != nil || v <= 2 {
		return cmd
	}

	return cmd + " where net.type = NET_IP" + b.IPVersion
}
