package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WireguardConfig struct {
	PrivateKey string
	Address    string
	ListenPort int
	Peers      []PeerConfig
}

type PeerConfig struct {
	PublicKey    string
	AllowedIPs   string
	Endpoint     string
	PresharedKey string
}

func setupWireguard() {
	config, err := parseWGConfig(args.WGConfig)
	if err != nil {
		log.Fatal(err)
	}

	if err := validateConfig(config); err != nil {
		log.Fatal("Configuration validation failed:", err)
	}

	if err := setupInterface(config); err != nil {
		log.Fatal(err)
	}

	log.Printf(green("Interface `%s` successfully configured"), INTERFACE_NAME)
}

func removeWireguard(force bool) {
	if force || !args.Persistent {
		// Remove MASQUERADE rule
		if useNFT {
			execCommand("nft delete table ip dnsr-nat")
		} else {
			execCommand(fmt.Sprintf("iptables -t nat -D POSTROUTING -o %s -j MASQUERADE", INTERFACE_NAME))
		}
		execCommand("ip", "link", "delete", INTERFACE_NAME)
		log.Printf(green("Interface `%s` successfully removed"), INTERFACE_NAME)
	} else {
		fmt.Printf(yellow("WireGuard interface '%s' remains active.\n"), INTERFACE_NAME)
	}
}

func parseWGConfig(filename string) (*WireguardConfig, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	config := &WireguardConfig{}
	var currentPeer *PeerConfig

	scanner := bufio.NewScanner(file)
	var section string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if args.Verbose {
			log.Printf("Processing line: %s", line)
		}

		// Пропускаем пустые строки и комментарии
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Определяем секцию
		if line == "[Interface]" {
			section = "interface"
			continue
		} else if line == "[Peer]" {
			section = "peer"
			// Создаем нового пира и добавляем его в слайс
			currentPeer = &PeerConfig{}
			config.Peers = append(config.Peers, *currentPeer)
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch section {
		case "interface":
			switch key {
			case "PrivateKey":
				config.PrivateKey = value
			case "Address":
				config.Address = value
			case "ListenPort":
				port, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("invalid ListenPort: %v", err)
				}
				config.ListenPort = port
			}
		case "peer":
			// Получаем указатель на последнего добавленного пира
			if len(config.Peers) > 0 {
				currentPeer = &config.Peers[len(config.Peers)-1]
				switch key {
				case "PublicKey":
					currentPeer.PublicKey = value
				case "AllowedIPs":
					currentPeer.AllowedIPs = value
				case "Endpoint":
					currentPeer.Endpoint = value
				case "PresharedKey":
					currentPeer.PresharedKey = value
				}
			}
		}
	}

	if args.Verbose {
		log.Printf("Parsed configuration: %+v", config)
		for i, peer := range config.Peers {
			log.Printf("Peer %d: %+v", i, peer)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config: %v", err)
	}

	return config, nil
}

func validateConfig(config *WireguardConfig) error {
	if config.PrivateKey == "" {
		return fmt.Errorf("private key is required")
	}
	if config.Address == "" {
		return fmt.Errorf("address is required")
	}

	for i, peer := range config.Peers {
		if peer.PublicKey == "" {
			return fmt.Errorf("public key is required for peer %d", i)
		}
		if peer.AllowedIPs == "" {
			return fmt.Errorf("allowed IPs are required for peer %d", i)
		}
	}

	return nil
}

func setupInterface(config *WireguardConfig) error {
	// Create WireGuard interface
	if args.Verbose {
		log.Printf("Creating WireGuard interface: %s", INTERFACE_NAME)
	}
	execCommand("modprobe", "wireguard")

	// При использовании нашего execCommand программа умрёт при ошибке, что нам и нужно
	execCommand("ip", "link", "add", "dev", INTERFACE_NAME, "type", "wireguard")

	// Set IP address
	if args.Verbose {
		log.Printf("Setting IP address: %s", config.Address)
	}
	execCommand("ip", "addr", "add", config.Address, "dev", INTERFACE_NAME)

	// Create WireGuard client
	wgClient, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to create WireGuard client: %v", err)
	}
	defer wgClient.Close()

	// Parse private key
	privateKey, err := wgtypes.ParseKey(config.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	// Configure WireGuard device
	peerConfigs := make([]wgtypes.PeerConfig, len(config.Peers))
	for i, peer := range config.Peers {
		if args.Verbose {
			log.Printf("Configuring peer %d with public key: %s", i+1, peer.PublicKey)
		}

		pubKey, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to parse public key for peer %d: %v", i+1, err)
		}

		peerConfig := wgtypes.PeerConfig{
			PublicKey: pubKey,
		}

		if peer.AllowedIPs != "" {
			allowedIPs := strings.Split(peer.AllowedIPs, ",")
			for _, ipStr := range allowedIPs {
				_, ipNet, err := net.ParseCIDR(strings.TrimSpace(ipStr))
				if err != nil {
					return fmt.Errorf("failed to parse AllowedIPs for peer %d: %v", i+1, err)
				}
				peerConfig.AllowedIPs = append(peerConfig.AllowedIPs, *ipNet)
			}
		}

		if peer.Endpoint != "" {
			endpoint, err := net.ResolveUDPAddr("udp", peer.Endpoint)
			if err != nil {
				return fmt.Errorf("failed to resolve endpoint for peer %d: %v", i+1, err)
			}
			peerConfig.Endpoint = endpoint
		}

		if peer.PresharedKey != "" {
			psk, err := wgtypes.ParseKey(peer.PresharedKey)
			if err != nil {
				return fmt.Errorf("failed to parse preshared key for peer %d: %v", i+1, err)
			}
			peerConfig.PresharedKey = &psk
		}

		peerConfigs[i] = peerConfig
	}

	// Apply WireGuard configuration
	deviceConfig := wgtypes.Config{
		PrivateKey: &privateKey,
		ListenPort: &config.ListenPort,
		Peers:      peerConfigs,
	}

	if err := wgClient.ConfigureDevice(INTERFACE_NAME, deviceConfig); err != nil {
		return fmt.Errorf("failed to configure WireGuard device: %v", err)
	}

	// Bring up interface
	if args.Verbose {
		log.Printf("Bringing up interface %s", INTERFACE_NAME)
	}
	// ip link set up dev <NAME>
	execCommand("ip", "link", "set", "up", "dev", INTERFACE_NAME)

	// Add MASQUERADE rule
	setUpMasquerade(INTERFACE_NAME)

	// Display final configuration
	if args.Verbose {
		log.Printf("=========================")
		device, err := wgClient.Device(INTERFACE_NAME)
		if err != nil {
			log.Printf("Warning: failed to show configuration: %v", err)
		} else {
			log.Printf("Interface: %s", device.Name)
			log.Printf("  Public key: %s", device.PublicKey.String())
			log.Printf("  Listen port: %d", device.ListenPort)
			for _, peer := range device.Peers {
				log.Printf("  Peer: %s", peer.PublicKey.String())
				log.Printf("    Endpoint: %s", peer.Endpoint)
				log.Printf("    Allowed IPs: %v", peer.AllowedIPs)
			}
		}
		log.Printf("=========================")
	}

	return nil
}

///////////////////////////////////////////////////////////////////////////////

func setUpMasquerade(name string) {
	if useNFT {
		execCommand("nft add table dnsr-nat")
		execCommand("nft add chain ip dnsr-nat postrouting { type nat hook postrouting priority 100 \\; }")
		execCommand("nft add rule ip dnsr-nat postrouting oifname", name, "masquerade")
	} else {
		execCommand(fmt.Sprintf("iptables -t nat -A POSTROUTING -o %s -j MASQUERADE", name))
	}
}
