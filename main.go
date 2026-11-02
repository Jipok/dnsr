package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"
)

const (
	NFQUEUE     = 2034
	APP_VERSION = "dnsr 5.2.0"
)

type Args struct {
	WGConfigs     []string
	Interfaces    []string
	ProxyList     string
	BlockList     string
	PresetIPs     string
	Force         bool
	Silent        bool
	Verbose       bool
	Persistent    bool
	NoConntrack   bool
	CheckInterval time.Duration
	CheckTimeout  time.Duration
	FailThreshold int
}

type Tunnel struct {
	Name       string
	ConfigPath string // empty for external interfaces (-i)
	AddressIP  string
	Link       *net.Interface
	AWGProcess *os.Process
}

var (
	args    Args
	useNFT  bool
	tunnels []*Tunnel
)

func main() {
	// Configure flags using pflag
	flag.StringSliceVarP(&args.Interfaces, "interface", "i", nil, "Use existing WireGuard/Amnezia interface(s)")

	flag.StringVar(&args.ProxyList, "proxy-list", "proxy.lst", "File with list of domains to proxy")
	flag.StringVar(&args.BlockList, "block-list", "blocks.lst", "File with list of domains to block")
	flag.StringVar(&args.PresetIPs, "preset-ips", "ips.lst", "File with IP addresses to proxy immediately")

	flag.BoolVarP(&args.Force, "force", "f", false, "Force remove existing dnsr interface(s)")
	flag.BoolVarP(&args.Silent, "silent", "s", false, "Don't show when new routes are added")
	flag.BoolVarP(&args.Verbose, "verbose", "v", false, "Enable verbose output")
	flag.BoolVarP(&args.Persistent, "persistent", "p", false, "Keep interface (if created) and routes after exit")
	flag.BoolVar(&args.NoConntrack, "no-conntrack", false, "Disable dropping active connections via conntrack")

	flag.DurationVar(&args.CheckInterval, "check-interval", 10*time.Second, "Health check interval when multiple tunnels are used")
	flag.DurationVar(&args.CheckTimeout, "check-timeout", 3*time.Second, "Health check timeout per tunnel")
	flag.IntVar(&args.FailThreshold, "fail-threshold", 3, "Consecutive health check failures before switching tunnel")

	// Disable sorting to keep logical grouping defined above
	flag.CommandLine.SortFlags = false

	flag.Usage = func() {
		fmt.Printf("%s\n\n", APP_VERSION)

		fmt.Println("Usage:")
		fmt.Printf("  %s [options] <WG/Amnezia Config> [Backup Config...]\n", os.Args[0])
		fmt.Printf("  %s [options] -i <InterfaceName> [-i <BackupInterface>...]\n\n", os.Args[0])

		fmt.Println("Options:")
		flag.PrintDefaults()

		fmt.Println("\nExamples:")
		fmt.Println(green("  sudo " + os.Args[0] + " ~/wg0.conf"))
		fmt.Println(green("  sudo " + os.Args[0] + " ~/wg0.conf ~/awg1.conf --verbose"))
		fmt.Println(green("  sudo " + os.Args[0] + " -i wg0 -i wg1"))
	}

	flag.Parse()

	args.WGConfigs = flag.Args()

	// Validate
	if len(args.WGConfigs) == 0 && len(args.Interfaces) == 0 {
		println(red("Required: ") + "specify either WireGuard/Amnezia config file(s) or existing interface(s) with -i flag")
		println("EXAMPLE:")
		println(green("  sudo ./dnsr ~/my-wireguard.conf"))
		println("OR")
		println(green("  sudo ./dnsr --interface wg0"))
		os.Exit(1)
	}
	if args.CheckInterval <= 0 || args.CheckTimeout <= 0 || args.FailThreshold < 1 {
		log.Fatal(red("Invalid health check parameters: interval and timeout must be > 0, fail-threshold must be >= 1"))
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

	if args.PresetIPs == "ips.lst" && !fileExists(args.PresetIPs) {
		if !args.Silent {
			log.Print(yellow("Notice: Consider routing CDN IPs (like Cloudflare) and DNS through the VPN."))
			log.Print(yellow("Many blocked websites are hosted on Cloudflare, and DPI systems often drop these connections."))
			log.Print(green("  wget https://www.cloudflare.com/ips-v4 -O ips.lst"))
			log.Print(green("  echo -e '\\n8.8.8.8\\n8.8.4.4\\n1.1.1.1' >> ips.lst\n"))
		}
		args.PresetIPs = ""
	}

	if os.Getuid() != 0 {
		log.Fatal(red("Must be run as root"))
	}

	if !args.NoConntrack {
		if _, err := exec.LookPath("conntrack"); err != nil {
			log.Println(yellow("Warning! conntrack utility not found. Active connections to newly proxied IPs won't be dropped automatically."))
			log.Println(yellow("To install it, run: opkg install conntrack (OpenWrt) or apt install conntrack (Debian/Ubuntu)"))
			// Auto-disable to prevent exec errors on every single route addition
			args.NoConntrack = true
		} else if args.Verbose {
			log.Println("Detected conntrack")
		}
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

	// Build tunnel list
	for i, cfgPath := range args.WGConfigs {
		tunnels = append(tunnels, &Tunnel{
			Name:       fmt.Sprintf("dnsr%d", i),
			ConfigPath: cfgPath,
		})
	}
	for _, ifName := range args.Interfaces {
		tunnels = append(tunnels, &Tunnel{Name: ifName})
	}

	// Check for existing dnsrN interfaces when creating from config
	if len(args.WGConfigs) > 0 {
		existing := findExistingDnsrInterfaces()
		if len(existing) > 0 {
			log.Printf(yellow("Existing interface(s) found: %s"), strings.Join(existing, ", "))
			log.Print(yellow("This could be because:"))
			log.Print(yellow(" - Previous process was terminated incorrectly"))
			log.Print(yellow(" - Interface was preserved with --persistent flag"))
			if args.Force {
				log.Print("Removing existing interface(s) as --force flag is set")
				cleanupExistingInterfaces(existing)
				log.Print(green("Cleanup completed. Proceeding with normal startup\n"))
			} else {
				log.Print(red("To proceed, either:"))
				log.Print(" - Use --force to remove existing interface(s) and create new one(s)")
				log.Printf(" - Use -i %s to use existing interface(s)", strings.Join(existing, " -i "))
				log.Fatalf(" - Or manually remove with: ip link delete %s", existing[0])
			}
		}
	}

	// Configure tunnel interfaces
	setupTunnels()
	defer removeTunnels()

	setupRouting()

	setupNfqueue()

	monitorCtx, monitorCancel := context.WithCancel(context.Background())
	if len(tunnels) > 1 {
		go startFailoverMonitor(monitorCtx)
	}

	fmt.Println("====================")
	<-sigChan
	log.Println("Shutting down...")

	monitorCancel()
	removeNfqueue()
	cleanupRouting()
}

///////////////////////////////////////////////////////////////////////////////

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
	return err == nil && !stat.IsDir()
}

func execCommand(cmdargs ...string) {
	cmdStr := strings.Join(cmdargs, " ")
	if args.Verbose {
		fmt.Println(yellow("EXEC") + "  " + cmdStr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)
	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		log.Printf(red("EXEC TIMEOUT")+"  %s", cmdStr)
		return
	}

	if err != nil && args.Verbose {
		fmt.Printf(yellow("EXEC ERROR")+" %v, output: %s \n", err, output)
	}
}

func checkRules(cmd string) bool {
	output, err := exec.Command("sh", "-c", cmd).Output()
	return err == nil && len(output) > 0
}
