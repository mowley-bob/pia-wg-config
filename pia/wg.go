package pia

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"text/template"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/pkg/errors"
)

type PIAWgGenerator struct {
	pia        PIAWgClient
	verbose    bool
	privatekey string
	publickey  string
}

type PIAWgGeneratorConfig struct {
	Verbose    bool
	PrivateKey string
	PublicKey  string
}

type templateConfig struct {
	Address             string
	AllowedIPs          string
	DNS                 string
	Endpoint            string
	PrivateKey          string
	PublicKey           string
	PersistentKeepalive string
}

func NewPIAWgGenerator(pia PIAWgClient, config PIAWgGeneratorConfig) *PIAWgGenerator {
	return &PIAWgGenerator{
		pia:        pia,
		verbose:    config.Verbose,
		privatekey: config.PrivateKey,
		publickey:  config.PublicKey,
	}
}

// Generate
func (p *PIAWgGenerator) Generate() (string, error) {
	// Get PIA token
	if p.verbose {
		log.Println("Getting PIA token")
	}
	token, err := p.pia.GetToken()
	if err != nil {
		return "", errors.Wrap(err, "error getting PIA token")
	}

	// Generate Wireguard keys
	if p.verbose {
		log.Println("Generating Wireguard keys")
	}
	privatekey, publickey, err := p.generateKeys()
	if err != nil {
		return "", errors.Wrap(err, "error generating Wireguard keys")
	}

	// Add Wireguard publickey to PIA account
	if p.verbose {
		log.Println("Adding Wireguard publickey to PIA account")
	}
	key, err := p.pia.AddKey(token, publickey)
	if err != nil {
		return "", errors.Wrap(err, "error adding Wireguard publickey to PIA account")
	}

	// Generate Wireguard config
	if p.verbose {
		log.Println("Generating Wireguard config")
	}
	config, err := p.generateConfig(key, privatekey)
	if err != nil {
		return "", errors.Wrap(err, "error generating Wireguard config")
	}

	return config, nil
}

// generateKeys
func (p *PIAWgGenerator) generateKeys() (string, string, error) {
	if p.privatekey != "" && p.publickey != "" {
		return p.privatekey, p.publickey, nil
	}

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", errors.Wrap(err, fmt.Sprintf("failed to generate private key: %v", privateKey.String()))
	}
	if p.verbose {
		log.Println("Private key: ", privateKey)
	}

	// Call host 'wg pubkey' to generate public key
	publicKey := privateKey.PublicKey()
	if err != nil {
		return "", "", errors.Wrap(err, fmt.Sprintf("failed to generate public key: %v", publicKey.String()))
	}
	if p.verbose {
		log.Println("Public key: ", publicKey)
	}

	return privateKey.String(), publicKey.String(), nil
}

// generateConfig
func (p *PIAWgGenerator) generateConfig(key AddKeyResult, privatekey string) (string, error) {
	// Resolve template file path relative to executable
	execPath, err := os.Executable()
	if err != nil {
		log.Printf("Could not determine executable path: %v; using embedded template", err)
	}
	var templateData []byte
	if execPath != "" {
		templatePath := filepath.Join(filepath.Dir(execPath), "pia-wg-template.conf")
		if data, readErr := os.ReadFile(templatePath); readErr == nil && len(strings.TrimSpace(string(data))) > 0 {
			templateData = data
		} else {
			if readErr != nil {
				log.Printf("Could not read template %s: %v; using embedded template", templatePath, readErr)
			}
			// fallback to embedded template
			templateData = []byte(wireguardConfigTemplate)
		}
	} else {
		// fallback if we couldn't get executable path
		templateData = []byte(wireguardConfigTemplate)
	}
	template, err := template.New("config").Parse(string(templateData))
	if err != nil {
		return "", errors.Wrap(err, "error parsing wireguard config template")
	}

	// execute template
	tc := templateConfig{
		PrivateKey:          privatekey,
		PublicKey:           key.ServerKey,
		Endpoint:            key.ServerIP,
		DNS:                 key.DNSServers[0],
		Address:             key.PeerIP,
		AllowedIPs:          "0.0.0.0/0",
		PersistentKeepalive: "25",
	}

	var config bytes.Buffer
	err = template.Execute(&config, tc)
	if err != nil {
		return "", errors.Wrap(err, "error executing wireguard config template")
	}

	return config.String(), nil
}

var wireguardConfigTemplate = `[Interface]
PrivateKey = {{.PrivateKey}}
Address = {{.Address}}
DNS = {{.DNS}}
Table = off
FwMark = 51820  # Tell Kernel to mark packets for routing via table 51820
# Add vpn-if as default route to table 51820
PostUp = ip route add default dev %i table 51820
# Add rule to route through main table for all local packets
PostUp = ip rule add priority 4000 table main suppress_prefixlength 0
# Add rule to route all fwmarked packets via table 51820
PostUp = ip rule add priority 10000 not fwmark 51820 table 51820
# Create the default route in the bypass table pointing to WLAN gateway
PostUp = ip route add default via 192.168.1.254 dev wlp7s0f3u2 table 1000
# Force traffic bound explicitly to wlan0 (sli0rp4netns) to use that table 
# (vpn-egress containers)
PostUp = ip rule add from 192.168.1.1 priority 5000 table 1000

# Clean up on exit
PostDown = ip rule del priority 10000
PostDown = ip rule del priority 4000
PostDown = ip rule del priority 5000
PostDown = ip route flush table 1000

[Peer]
PublicKey = {{.PublicKey}}
AllowedIPs = {{.AllowedIPs}}
Endpoint = {{.Endpoint}}:1337
PersistentKeepalive = {{.PersistentKeepalive}}`
