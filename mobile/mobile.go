// Package mobile exposes a gomobile-compatible API for the usque MASQUE client.
package mobile

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"

	_ "golang.org/x/mobile/bind"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/models"
)

// Ping returns "pong". Used for M0 smoke-test.
func Ping() string {
	return "pong"
}

// RegisterAccount creates a new Cloudflare WARP account.
// acceptTos must be true; passing false returns USQUE_ERR_TOS_NOT_ACCEPTED.
// Returns the JSON of models.AccountData on success.
func RegisterAccount(model, locale, jwt string, acceptTos bool) (string, error) {
	if !acceptTos {
		return "", fmt.Errorf("USQUE_ERR_TOS_NOT_ACCEPTED: user must accept Terms of Service")
	}

	logf("RegisterAccount: model=%s locale=%s", model, locale)

	accountData, err := api.Register(model, locale, jwt, true)
	if err != nil {
		return "", fmt.Errorf("USQUE_ERR_NETWORK: %w", err)
	}

	jsonBytes, err := json.Marshal(accountData)
	if err != nil {
		return "", fmt.Errorf("USQUE_ERR_CONFIG: failed to marshal account data: %w", err)
	}

	logf("RegisterAccount: success id=%s", accountData.ID)
	return string(jsonBytes), nil
}

// EnrollDevice generates a new ECDSA key pair, enrolls it with Cloudflare WARP,
// and returns a JSON of config.Config on success.
// accountJson must be a JSON-encoded models.AccountData (from RegisterAccount).
func EnrollDevice(accountJson, deviceName string) (string, error) {
	logf("EnrollDevice: deviceName=%s", deviceName)

	var accountData models.AccountData
	if err := json.Unmarshal([]byte(accountJson), &accountData); err != nil {
		return "", fmt.Errorf("USQUE_ERR_CONFIG: failed to parse account JSON: %w", err)
	}

	privKeyBytes, publicKey, err := internal.GenerateEcKeyPair()
	if err != nil {
		return "", fmt.Errorf("USQUE_ERR_CONFIG: failed to generate key pair: %w", err)
	}

	updatedAccountData, apiErr, err := api.EnrollKey(accountData, publicKey, deviceName)
	if err != nil {
		if apiErr != nil && apiErr.HasErrorMessage(models.InvalidPublicKey) {
			return "", fmt.Errorf("USQUE_ERR_INVALID_PUBKEY: %s", apiErr.ErrorsAsString("; "))
		}
		if apiErr != nil {
			return "", fmt.Errorf("USQUE_ERR_AUTH: %v (API: %s)", err, apiErr.ErrorsAsString("; "))
		}
		return "", fmt.Errorf("USQUE_ERR_NETWORK: %w", err)
	}

	endpointV4 := stripPortSuffix(updatedAccountData.Config.Peers[0].Endpoint.V4)
	endpointV6 := stripIPv6Brackets(updatedAccountData.Config.Peers[0].Endpoint.V6)

	cfg := config.Config{
		PrivateKey:     base64.StdEncoding.EncodeToString(privKeyBytes),
		EndpointV4:     endpointV4,
		EndpointV6:     endpointV6,
		EndpointH2V4:   config.DefaultEndpointH2V4,
		EndpointH2V6:   "",
		EndpointPubKey: updatedAccountData.Config.Peers[0].PublicKey,
		License:        updatedAccountData.Account.License,
		ID:             updatedAccountData.ID,
		AccessToken:    accountData.Token,
		IPv4:           updatedAccountData.Config.Interface.Addresses.V4,
		IPv6:           updatedAccountData.Config.Interface.Addresses.V6,
	}

	jsonBytes, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("USQUE_ERR_CONFIG: failed to marshal config: %w", err)
	}

	logf("EnrollDevice: success ipv4=%s ipv6=%s", cfg.IPv4, cfg.IPv6)
	return string(jsonBytes), nil
}

// GetConfigIPv4 extracts IPv4 from a config JSON.
func GetConfigIPv4(configJson string) (string, error) {
	cfg, err := parseConfig(configJson)
	if err != nil {
		return "", err
	}
	return cfg.IPv4, nil
}

// GetConfigIPv6 extracts IPv6 from a config JSON.
func GetConfigIPv6(configJson string) (string, error) {
	cfg, err := parseConfig(configJson)
	if err != nil {
		return "", err
	}
	return cfg.IPv6, nil
}

// parseConfig deserializes a config JSON string into config.Config.
func parseConfig(configJson string) (config.Config, error) {
	var cfg config.Config
	if err := json.Unmarshal([]byte(configJson), &cfg); err != nil {
		return config.Config{}, fmt.Errorf("USQUE_ERR_CONFIG: failed to parse config: %w", err)
	}
	return cfg, nil
}

// buildTLSConfig constructs a *tls.Config from a parsed config and SNI override.
func buildTLSConfig(cfg config.Config, sni string) (*tls.Config, error) {
	if sni == "" {
		sni = internal.ConnectSNI
	}

	privKey, err := cfg.GetEcPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("USQUE_ERR_CONFIG: failed to get private key: %w", err)
	}
	peerPubKey, err := cfg.GetEcEndpointPublicKey()
	if err != nil {
		return nil, fmt.Errorf("USQUE_ERR_CONFIG: failed to get peer public key: %w", err)
	}
	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("USQUE_ERR_CONFIG: failed to generate cert: %w", err)
	}
	tlsCfg, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, sni, false)
	if err != nil {
		return nil, fmt.Errorf("USQUE_ERR_CONFIG: failed to prepare TLS config: %w", err)
	}
	return tlsCfg, nil
}

// parseDNSAddrs parses a comma-separated list of IP addresses.
func parseDNSAddrs(dnsAddrs string) ([]netip.Addr, error) {
	if dnsAddrs == "" {
		return []netip.Addr{
			netip.MustParseAddr("1.1.1.1"),
			netip.MustParseAddr("1.0.0.1"),
		}, nil
	}
	var addrs []netip.Addr
	for _, s := range strings.Split(dnsAddrs, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("invalid DNS address %q: %w", s, err)
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

// selectEndpoint picks the right net.Addr from config based on mode/IPv6 flag.
func selectEndpoint(cfg config.Config, useHTTP2, useIPv6 bool, connectPort int) (net.Addr, error) {
	saved := config.AppConfig
	config.AppConfig = cfg
	defer func() { config.AppConfig = saved }()

	ep, err := config.SelectEndpointFromConfig(useHTTP2, useIPv6, connectPort)
	if err != nil {
		return nil, fmt.Errorf("USQUE_ERR_CONFIG: %w", err)
	}
	return ep, nil
}

// stripPortSuffix removes ":0" suffix from IPv4 endpoint strings.
func stripPortSuffix(s string) string {
	if strings.HasSuffix(s, ":0") {
		return s[:len(s)-2]
	}
	return s
}

// stripIPv6Brackets removes "[" prefix and "]:0" suffix from IPv6 endpoint strings.
func stripIPv6Brackets(s string) string {
	if len(s) > 4 && s[0] == '[' && strings.HasSuffix(s, "]:0") {
		return s[1 : len(s)-3]
	}
	return s
}

var _ *tls.Config
