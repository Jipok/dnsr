package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Jipok/wgctrl-go"
	"github.com/Jipok/wgctrl-go/wgtypes"
)

type WireguardConfig struct {
	PrivateKey string
	Address    string
	ListenPort int
	MTU        int
	Peers      []PeerConfig

	// AmneziaWG Specific Configuration
	Jc, Jmin, Jmax     int
	S1, S2, S3, S4     int
	H1, H2, H3, H4     string
	I1, I2, I3, I4, I5 string
}

type PeerConfig struct {
	PublicKey           string
	AllowedIPs          string
	Endpoint            string
	PresharedKey        string
	PersistentKeepalive int
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

	link, err = net.InterfaceByName(INTERFACE_NAME)
	if err != nil {
		log.Fatalf(red("Created interface `%s` could not be found: %v"), INTERFACE_NAME, err)
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

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Determine section
		if line == "[Interface]" {
			section = "interface"
			continue
		} else if line == "[Peer]" {
			section = "peer"
			currentPeer = &PeerConfig{}
			config.Peers = append(config.Peers, *currentPeer)
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			log.Printf(yellow("Warning:")+" Skipped invalid line (no '='): %s", line)
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch section {
		case "interface":
			switch key {
			// Standard WireGuard Params
			case "PrivateKey":
				config.PrivateKey = value
			case "Address":
				config.Address = value
			case "MTU":
				mtu, err := strconv.Atoi(value)
				if err == nil {
					config.MTU = mtu
				}
			case "ListenPort":
				port, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("invalid ListenPort: %v", err)
				}
				config.ListenPort = port
			case "DNS", "PostUp", "PostDown", "PreUp", "PreDown":
				// Known keys that we explicitly ignore or handle elsewhere/not supported yet
				if args.Verbose {
					log.Printf("Info: Ignoring supported but unused key: %s", key)
				}

			// AmneziaWG Integer Params
			case "Jc":
				if v, err := strconv.Atoi(value); err == nil {
					config.Jc = v
				}
			case "Jmin":
				if v, err := strconv.Atoi(value); err == nil {
					config.Jmin = v
				}
			case "Jmax":
				if v, err := strconv.Atoi(value); err == nil {
					config.Jmax = v
				}
			case "S1":
				if v, err := strconv.Atoi(value); err == nil {
					config.S1 = v
				}
			case "S2":
				if v, err := strconv.Atoi(value); err == nil {
					config.S2 = v
				}
			case "S3":
				if v, err := strconv.Atoi(value); err == nil {
					config.S3 = v
				}
			case "S4":
				if v, err := strconv.Atoi(value); err == nil {
					config.S4 = v
				}

			// AmneziaWG String Params
			case "H1":
				config.H1 = value
			case "H2":
				config.H2 = value
			case "H3":
				config.H3 = value
			case "H4":
				config.H4 = value

			// AmneziaWG Init Packet Magic Params
			case "I1":
				config.I1 = value
			case "I2":
				config.I2 = value
			case "I3":
				config.I3 = value
			case "I4":
				config.I4 = value
			case "I5":
				config.I5 = value

			default:
				log.Printf(yellow("Warning:")+" Unknown or unsupported config key in [Interface]: %s", key)
			}
		case "peer":
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
				case "PersistentKeepalive":
					ka, err := strconv.Atoi(value)
					if err == nil {
						currentPeer.PersistentKeepalive = ka
					}
				default:
					log.Printf(yellow("Warning:")+"Unknown or unsupported config key in [Peer]: %s", key)
				}
			}
		default:
			log.Printf(yellow("Warning:")+" Key defined outside of [Interface] or [Peer] section: %s", key)
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
	// Check if config requires AmneziaWG interface
	isAmnezia := config.Jc > 0 || config.H1 != "" || config.I1 != ""

	interfaceType := "wireguard"
	if isAmnezia {
		interfaceType = "amneziawg"
	}

	// Create Interface
	if args.Verbose {
		log.Printf("Creating interface: %s (%s)", INTERFACE_NAME, interfaceType)
	}

	// Load appropriate kernel module
	execCommand("modprobe", interfaceType)

	// Create the interface with the determined type
	execCommand("ip", "link", "add", "dev", INTERFACE_NAME, "type", interfaceType)

	// Set MTU if specified
	if config.MTU > 0 {
		execCommand("ip", "link", "set", "dev", INTERFACE_NAME, "mtu", strconv.Itoa(config.MTU))
	}

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

		if peer.PersistentKeepalive > 0 {
			ka := time.Duration(peer.PersistentKeepalive) * time.Second
			peerConfig.PersistentKeepaliveInterval = &ka
		}

		peerConfigs[i] = peerConfig
	}

	// Apply WireGuard configuration
	deviceConfig := wgtypes.Config{
		PrivateKey: &privateKey,
		ListenPort: &config.ListenPort,
		Peers:      peerConfigs,
	}

	// Apply AmneziaWG parameters if they exist in the config
	// We check for non-zero/non-empty values before assiging pointers

	// Junk Packet parameters
	if config.Jc > 0 {
		deviceConfig.Jc = &config.Jc
	}
	if config.Jmin > 0 {
		deviceConfig.Jmin = &config.Jmin
	}
	if config.Jmax > 0 {
		deviceConfig.Jmax = &config.Jmax
	}

	// Message Padding parameters
	if config.S1 > 0 {
		deviceConfig.S1 = &config.S1
	}
	if config.S2 > 0 {
		deviceConfig.S2 = &config.S2
	}
	if config.S3 > 0 {
		deviceConfig.S3 = &config.S3
	}
	if config.S4 > 0 {
		deviceConfig.S4 = &config.S4
	}

	// Message Magic Headers
	if config.H1 != "" {
		deviceConfig.H1 = &config.H1
	}
	if config.H2 != "" {
		deviceConfig.H2 = &config.H2
	}
	if config.H3 != "" {
		deviceConfig.H3 = &config.H3
	}
	if config.H4 != "" {
		deviceConfig.H4 = &config.H4
	}

	// Init Packet params
	if config.I1 != "" {
		deviceConfig.I1 = &config.I1
	}
	if config.I2 != "" {
		deviceConfig.I2 = &config.I2
	}
	if config.I3 != "" {
		deviceConfig.I3 = &config.I3
	}
	if config.I4 != "" {
		deviceConfig.I4 = &config.I4
	}
	if config.I5 != "" {
		deviceConfig.I5 = &config.I5
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
			log.Printf(yellow("Warning:")+" failed to show configuration: %v", err)
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
