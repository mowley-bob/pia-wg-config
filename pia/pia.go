package pia

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/benburkert/dns"
	"github.com/pkg/errors"
)

type PIAWgClient interface {
	GetToken() (string, error)
	AddKey(token, publickey string) (AddKeyResult, error)
}

type Region string
type ServerList map[Region][]Server

type PIAClient struct {
	region           string
	wireguardServers ServerList
	username         string
	password         string
	verbose          bool
	caCert           []byte
}

type piaServerList struct {
	Regions []struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Country     string `json:"country"`
		AutoRegion  bool   `json:"auto_region"`
		DNS         string `json:"dns"`
		PortForward bool   `json:"port_forward"`
		Geo         bool   `json:"geo"`
		Servers     struct {
			Meta []Server `json:"meta"`
			Wg   []Server `json:"wg"`
		} `json:"servers"`
	} `json:"regions"`
}

type AddKeyResult struct {
	Status     string   `json:"status"`
	ServerKey  string   `json:"server_key"`
	ServerPort int      `json:"server_port"`
	ServerIP   string   `json:"server_ip"`
	ServerVip  string   `json:"server_vip"`
	PeerIP     string   `json:"peer_ip"`
	PeerPubkey string   `json:"peer_pubkey"`
	DNSServers []string `json:"dns_servers"`
}

type Server struct {
	Cn string
	IP string
}

// Request tuning shared across the PIA API calls.
const (
	piaRequestTimeout     = 20 * time.Second
	piaServerListMaxBytes = 5 * 1024 * 1024 // 5 MiB
)

// NewPIAClient creates a new PIA client for with the list of servers populated
func NewPIAClient(username, password, region string, verbose bool) (*PIAClient, error) {
	piaClient := PIAClient{
		username: username,
		password: password,
		region:   region,
		verbose:  verbose,
	}

	// Get list of servers
	serverList, err := piaClient.getServerList()
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch server list from PIA")
	}

	// Set servers
	piaClient.wireguardServers = piaClient.generateWireguardServerList(serverList)

	// Validate region exists
	if _, exists := piaClient.wireguardServers[Region(region)]; !exists {
		availableRegions := make([]string, 0, len(piaClient.wireguardServers))
		for r := range piaClient.wireguardServers {
			availableRegions = append(availableRegions, string(r))
		}
		return nil, fmt.Errorf("region '%s' not found. Available regions: %v. Use 'pia-wg-config regions' to see all available regions", region, availableRegions[:5]) // Show first 5 as example
	}

	return &piaClient, nil
}

// GetToken obtains an auth token from PIA's central API, matching the
// manual-connections token flow (form POST to /api/client/v2/token over the
// public TLS endpoint).
func (p *PIAClient) GetToken() (string, error) {
	form := url.Values{}
	form.Set("username", p.username)
	form.Set("password", p.password)

	req, err := http.NewRequest("POST", "https://www.privateinternetaccess.com/api/client/v2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: piaRequestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error executing token request")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("token endpoint returned status %d", resp.StatusCode)
	}

	var tokenResp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", errors.Wrap(err, "error decoding token response")
	}
	if tokenResp.Token == "" {
		return "", fmt.Errorf("token endpoint returned an empty token")
	}

	if p.verbose {
		log.Print("Got token: ", tokenResp.Token)
	}

	return tokenResp.Token, nil
}

// GetAvailableRegions returns all available regions
func (p *PIAClient) GetAvailableRegions() (map[Region]string, error) {
	serverList, err := p.getServerList()
	if err != nil {
		return nil, err
	}

	regions := make(map[Region]string)
	for _, r := range serverList.Regions {
		regions[Region(r.ID)] = r.Name
	}

	return regions, nil
}

// AddKey registers the WireGuard public key with the region's WireGuard
// server and returns the peer details, matching the manual-connections addKey
// flow (GET over the PIA-pinned TLS connection to the wg[0] endpoint).
func (p *PIAClient) AddKey(token, publickey string) (AddKeyResult, error) {
	var addKeyResp AddKeyResult
	server := p.getWireguardServerForRegion()

	reqURL := fmt.Sprintf("https://%v:1337/addKey?pt=%v&pubkey=%v", server.Cn, url.QueryEscape(token), url.QueryEscape(publickey))
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return addKeyResp, err
	}
	req.Header.Set("Content-Type", "application/json")

	client, err := p.newPIAPinnedClient(server)
	if err != nil {
		return addKeyResp, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return addKeyResp, errors.Wrap(err, "error executing request")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return addKeyResp, fmt.Errorf("addKey endpoint returned status %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(&addKeyResp); err != nil {
		return addKeyResp, errors.Wrap(err, "error decoding add key response")
	}

	return addKeyResp, nil
}

func (p *PIAClient) getWireguardServerForRegion() Server {
	if p.verbose {
		log.Print("Getting wireguard server for region: ", p.region)
	}
	servers := p.wireguardServers[Region(p.region)]
	if len(servers) == 0 {
		log.Fatalf("No Wireguard servers available for region: %s", p.region)
	}
	return servers[0]
}

// WireguardServer exposes the chosen WireGuard server (hostname and IP)
func (p *PIAClient) WireguardServer() Server {
	return p.getWireguardServerForRegion()
}

// getServerList returns the PIA server list. It uses the v6 endpoint (whose
// JSON object sits on a single line) and parses only the first line — the
// manual-connections `head -1` approach — to avoid the trailing base64 blob.
func (p *PIAClient) getServerList() (piaServerList, error) {
	var serverList piaServerList

	client := &http.Client{Timeout: piaRequestTimeout}
	resp, err := client.Get("https://serverlist.piaservers.net/vpninfo/servers/v6")
	if err != nil {
		return piaServerList{}, err
	}
	defer resp.Body.Close()

	reader := io.LimitReader(resp.Body, piaServerListMaxBytes+1)
	respBytes, err := io.ReadAll(reader)
	if err != nil {
		return piaServerList{}, err
	}
	if len(respBytes) > piaServerListMaxBytes {
		return piaServerList{}, fmt.Errorf("server list exceeds %d bytes", piaServerListMaxBytes)
	}

	// The v6 JSON object is on the first line; the trailing base64 blob
	// follows on subsequent lines. Take only the first line (head -1).
	firstLine := respBytes
	if idx := bytes.IndexByte(firstLine, '\n'); idx >= 0 {
		firstLine = firstLine[:idx]
	}

	if err := json.Unmarshal(firstLine, &serverList); err != nil {
		return piaServerList{}, err
	}

	return serverList, nil
}

// generateWireguardServerList
func (p *PIAClient) generateWireguardServerList(list piaServerList) ServerList {
	servers := ServerList{}

	for _, r := range list.Regions {
		for _, server := range r.Servers.Wg {
			servers[Region(r.ID)] = append(servers[Region(r.ID)], Server{
				Cn: server.Cn,
				IP: server.IP,
			})
		}
	}

	return servers
}

// newPIAPinnedClient returns an http.Client that verifies against PIA's CA
// certificate and resolves server.Cn to server.IP. This is the Go equivalent
// of manual-connections' `curl --connect-to host::ip: --cacert ca.crt`: the
// server is addressed by its hostname for the TLS handshake but dialed at the
// given IP.
func (p *PIAClient) newPIAPinnedClient(server Server) (*http.Client, error) {
	if err := p.downloadPIACertificate(); err != nil {
		return nil, errors.Wrap(err, "error downloading ca certificate")
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(p.caCert)

	// Resolve the server hostname to its pinned IP for the dial, while keeping
	// the hostname for TLS SNI/verification.
	zone := &dns.Zone{
		Origin: "",
		TTL:    5 * time.Minute,
		RRs: dns.RRSet{
			server.Cn: {
				dns.TypeA: []dns.Record{
					&dns.A{A: net.ParseIP(server.IP)},
				},
			},
		},
	}
	mux := new(dns.ResolveMux)
	mux.Handle(dns.TypeANY, zone.Origin, zone)
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: (&dns.Client{
			Resolver: mux,
		}).Dial,
	}

	dialer := &net.Dialer{
		Resolver: resolver,
	}
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	return &http.Client{
		Timeout: piaRequestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
			DialContext: dialContext,
		},
	}, nil
}

// downloadPIACertificate downloads and caches PIA's CA certificate, the same
// pinned cert shipped by the manual-connections repo.
func (p *PIAClient) downloadPIACertificate() error {
	// caCert already loaded
	if len(p.caCert) > 0 {
		return nil
	}

	client := &http.Client{Timeout: piaRequestTimeout}
	resp, err := client.Get("https://raw.githubusercontent.com/pia-foss/manual-connections/master/ca.rsa.4096.crt")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	p.caCert, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return nil
}
