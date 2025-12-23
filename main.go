package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	flag "github.com/spf13/pflag"
)

const (
	GID            = 2354
	NFQUEUE        = 2034
	INTERFACE_NAME = "dnsr0"
	APP_VERSION    = "dnsr 5.0.0"
)

type Args struct {
	WGConfig   string
	Interface  string
	ProxyList  string
	BlockList  string
	PresetIPs  string
	Force      bool
	Silent     bool
	Verbose    bool
	Persistent bool
}

var (
	args   Args
	useNFT bool
	link   *net.Interface
)

func main() {
	// Configure flags using pflag
	flag.StringVarP(&args.Interface, "interface", "i", "", "Use existing WireGuard/Amnezia interface")

	flag.StringVar(&args.ProxyList, "proxy-list", "proxy.lst", "File with list of domains to proxy")
	flag.StringVar(&args.BlockList, "block-list", "blocks.lst", "File with list of domains to block")
	flag.StringVar(&args.PresetIPs, "preset-ips", "", "File with IP addresses to proxy immediately")

	flag.BoolVarP(&args.Force, "force", "f", false, "Force remove existing dnsr interface")
	flag.BoolVarP(&args.Silent, "silent", "s", false, "Don't show when new routes are added")
	flag.BoolVarP(&args.Verbose, "verbose", "v", false, "Enable verbose output")
	flag.BoolVarP(&args.Persistent, "persistent", "p", false, "Keep interface (if created) and routes after exit")

	// Disable sorting to keep logical grouping defined above
	flag.CommandLine.SortFlags = false

	flag.Usage = func() {
		fmt.Printf("%s\n\n", APP_VERSION)

		// Improved usage block: shows two distinct modes immediately
		fmt.Println("Usage:")
		fmt.Printf("  %s [options] <WG/Amnezia Config>\n", os.Args[0])
		fmt.Printf("  %s [options] -i <InterfaceName>\n\n", os.Args[0])

		fmt.Println("Options:")
		flag.PrintDefaults()

		fmt.Println("\nExamples:")
		fmt.Println(green("  sudo " + os.Args[0] + " ~/wg0.conf"))
		fmt.Println(green("  sudo " + os.Args[0] + " ~/awg.conf --verbose"))
		fmt.Println(green("  sudo " + os.Args[0] + " -i wg0"))
	}

	flag.Parse()

	// Positional argument handling (Config file)
	if flag.NArg() > 0 {
		args.WGConfig = flag.Arg(0)
	}

	// Validate
	if args.WGConfig != "" && args.Interface != "" {
		log.Fatal(red("Mutually exclusive options: use either config file or -i flag"))
	}
	if args.WGConfig == "" && args.Interface == "" {
		println(red("Required: ") + "specify either WireGuard/Amnezia config file or existing interface with -i flag")
		println("EXAMPLE:")
		println(green("  sudo ./dnsr ~/my-wireguard.conf"))
		println("OR")
		println(green("  sudo ./dnsr --interface wg0"))
		os.Exit(1)
	}

	if args.ProxyList == "proxy.lst" && !fileExists(args.ProxyList) {
		fmt.Printf(red("Error:")+" The proxy list file '%s' does not exist.\n", args.ProxyList)
		fmt.Println("To download a good proxy list, you can use the following command:")
		fmt.Println(green("  wget https://github.com/1andrevich/Re-filter-lists/raw/refs/heads/main/domains_all.lst -O proxy.lst"))
		os.Exit(1)
	}
	if args.BlockList == "blocks.lst" && !fileExists(args.BlockList) {
		fmt.Printf(yellow("Warning:")+" The block list file '%s' does not exist.\n", args.BlockList)
		fmt.Println("To download a sample block list, you can use the following command:")
		fmt.Println(green("  wget https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts -O blocks.lst\n"))
	}

	if args.PresetIPs == "" && !args.Silent {
		log.Print(yellow("Notice: Consider routing your DNS server's IP through VPN too."))
		log.Print(yellow("Your ISP might block websites by manipulating DNS responses."))
		log.Print(yellow("You can add DNS server IPs to a file and use --preset-ips option, for example:"))
		log.Print("  echo -e '8.8.8.8\\n1.1.1.1' > dns-ips.txt")
		log.Print("  sudo ./dnsr --preset-ips dns-ips.txt /etc/wireguard/wg0.conf")
		log.Print("")
	}

	if os.Getuid() != 0 {
		log.Fatal(red("Must be run as root"))
	}

	// Detect iptables/nftables
	_, err := exec.LookPath("iptables")
	iptablesAvailable := err == nil
	_, err = exec.LookPath("nft")
	nftablesAvailable := err == nil
	//
	iptablesActive := checkRules("iptables -L") || fileExists("/proc/net/ip_tables_names")
	nftablesActive := checkRules("nft list ruleset") || fileExists("/proc/net/nf_tables")
	//
	if nftablesAvailable && nftablesActive {
		if args.Verbose {
			log.Println("Detected nftables")
		}
		useNFT = true
	} else if iptablesAvailable && iptablesActive {
		if args.Verbose {
			log.Println("Detected iptables")
		}
	} else if nftablesAvailable {
		log.Println(yellow("Warning! Detected nftables, but may not be active"))
		useNFT = true
	} else if iptablesAvailable {
		log.Println(yellow("Warning! Detected iptables, but may not be active"))
	} else {
		log.Fatal(red("Neither iptables nor nftables were found."))
	}

	if err := syscall.Setgid(GID); err != nil {
		log.Fatalf(red("Can't change GID: %v\n"), err)
	}

	// Enable IP forwarding
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		log.Fatalf(red("Failed to enable IP forwarding: %v"), err)
	}

	// Catch Ctrl-C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	//
	readDomains(args.ProxyList, addProxiedDomain)
	log.Printf("Proxies %d top-level domains, %d globs\n", len(proxiedDomains), len(proxiedPatterns))

	if fileExists(args.BlockList) {
		readDomains(args.BlockList, addBlockedDomain)
		log.Printf("Block %d domains, %d globs\n", len(blockedDomains), len(blockedPatterns))
	}

	if args.Silent {
		fmt.Println("Silent mode, run without -s for verbose output")
	}

	// Check for existing interface
	link, err = net.InterfaceByName(INTERFACE_NAME)
	if err == nil && args.Interface != INTERFACE_NAME {
		log.Printf(yellow("An existing `%s` interface was found."), INTERFACE_NAME)
		log.Print(yellow("This could be because:"))
		log.Print(yellow(" - Previous process was terminated incorrectly"))
		log.Print(yellow(" - Interface was preserved with --persistent flag"))
		if args.Force {
			log.Print("Removing existing interface as --force flag is set")
			removeWireguard(true)
			removeNfqueue()
			log.Print(green("Cleanup completed. Proceeding with normal startup\n"))
		} else {
			log.Print(red("To proceed, either:"))
			log.Print(" - Use --force to remove existing interface and create new one")
			log.Printf(" - Use -i %s to use existing interface", INTERFACE_NAME)
			log.Fatalf(" - Or manually remove interface with: ip link delete %s", INTERFACE_NAME)
		}
	}

	// Configure interface
	if args.WGConfig != "" {
		setupWireguard()
		defer removeWireguard(false)
	} else {
		link, err = net.InterfaceByName(args.Interface)
		if err != nil {
			log.Fatalf(red("Error:")+" getting `%s` interface: %v", args.Interface, err)
		}
		setUpMasquerade(args.Interface)
		log.Printf(green("Using `%s` interface"), args.Interface)
	}

	setupRouting()
	defer cleanupRouting()

	setupNfqueue()
	defer removeNfqueue()

	fmt.Println("====================")
	<-sigChan
	log.Println("Shutting down...")

	if args.Interface != "" {
		// Remove MASQUERADE rule
		if useNFT {
			execCommand("nft delete table ip dnsr-nat")
		} else {
			execCommand(fmt.Sprintf("iptables -t nat -D POSTROUTING -o %s -j MASQUERADE", args.Interface))
		}
	}
}

///////////////////////////////////////////////////////////////////////////////

func printOption(flags, desc string) {
	fmt.Printf("  %-28s %s\n", flags, desc)
}

func red(str string) string {
	return "\033[31m" + str + "\033[0m"
}

func green(str string) string {
	return "\033[32m" + str + "\033[0m"
}

func yellow(str string) string {
	return "\033[33m" + str + "\033[0m"
}

func fileExists(path string) bool {
	stat, err := os.Stat(path)
	return !os.IsNotExist(err) && !stat.IsDir()
}

func execCommand(cmdargs ...string) {
	cmd := strings.Join(cmdargs, " ")
	if args.Verbose {
		fmt.Println(yellow("EXEC") + "  " + cmd)
	}
	output, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		if !args.Verbose {
			fmt.Println(yellow("EXEC") + "  " + cmd)
		}
		log.Fatalf(red("%v")+", output: %s \n", err, output)
	}
}

func checkRules(cmd string) bool {
	output, err := exec.Command("sh", "-c", cmd).Output()
	return err == nil && len(output) > 0
}
