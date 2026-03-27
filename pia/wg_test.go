package pia

import (
	"testing"
)

type PIAClientMock struct{}

func (p *PIAClientMock) GetToken() (string, error) {
	return "", nil
}

func (p *PIAClientMock) AddKey(token, publickey string) (AddKeyResult, error) {
	return AddKeyResult{
		ServerIP:   "1.2.3.4",
		DNSServers: []string{"1.1.1.1"},
		PeerIP:     "4.5.6.7",
		ServerKey:  publickey,
	}, nil
}

func TestPIAWgGenerator_Generate(t *testing.T) {
	type fields struct {
		pia        PIAWgClient
		config     PIAWgGeneratorConfig
		verbose    bool
		privatekey string
		publickey  string
	}
	tests := []struct {
		name    string
		fields  fields
		want    string
		wantErr bool
	}{
		{
			name: "basic generate",
			fields: fields{
				pia: &PIAClientMock{},
				config: PIAWgGeneratorConfig{
					Verbose:    false,
					PrivateKey: "test_privatekey",
					PublicKey:  "test_publickey",
				},
			},
			want: `[Interface]
PrivateKey = test_privatekey
Address = 4.5.6.7
DNS = 1.1.1.1
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
PublicKey = test_publickey
AllowedIPs = 0.0.0.0/0
Endpoint = 1.2.3.4:1337
PersistentKeepalive = 25`,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPIAWgGenerator(tt.fields.pia, tt.fields.config)
			got, err := p.Generate()
			if (err != nil) != tt.wantErr {
				t.Errorf("PIAWgGenerator.Generate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("PIAWgGenerator.Generate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPIAWgGenerator_generateKeys(t *testing.T) {
	type fields struct {
		pia     PIAWgClient
		verbose bool
	}
	tests := []struct {
		name       string
		fields     fields
		wantResult bool
		wantErr    bool
	}{
		{
			name: "basic generateKeys",
			fields: fields{
				pia: &PIAClientMock{},
			},
			wantResult: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &PIAWgGenerator{
				pia:     tt.fields.pia,
				verbose: tt.fields.verbose,
			}
			got, got1, err := p.generateKeys()
			if (err != nil) != tt.wantErr {
				t.Errorf("PIAWgGenerator.generateKeys() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (got == "" || got1 == "") && tt.wantResult {
				t.Errorf("PIAWgGenerator.generateKeys() got no keys")
			}
		})
	}
}
