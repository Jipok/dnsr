package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/florianl/go-nfqueue"
	nfNetlink "github.com/mdlayher/netlink"
)

var (
	nf       *nfqueue.Nfqueue
	nfCancel context.CancelFunc
)

func setupNfqueue() {
	config := nfqueue.Config{
		NfQueue:      NFQUEUE,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
	}

	var err error
	nf, err = nfqueue.Open(&config)
	if err != nil {
		log.Fatal("could not open nfqueue socket:", err)
		return
	}
	// defer nf.Close()

	// Avoid receiving ENOBUFS errors.
	if err := nf.SetOption(nfNetlink.NoENOBUFS, true); err != nil {
		fmt.Printf("failed to set netlink option %v: %v\n",
			nfNetlink.NoENOBUFS, err)
		return
	}

	var ctx context.Context
	ctx, nfCancel = context.WithCancel(context.Background())
	// defer cancel()

	fn := func(a nfqueue.Attribute) int {
		id := *a.PacketID
		nf.SetVerdict(id, processPacket(*a.Payload))
		return 0
	}

	err = nf.RegisterWithErrorFunc(ctx, fn, func(err error) int {
		if ctx.Err() != nil {
			return 0
		}
		log.Printf(red("NFQueue error:")+" %v", err)
		return -1
	})
	if err != nil {
		if useNFT {
			log.Println(red("Do you have `nft-queue` kernel module?"))
		}
		log.Fatal("Can't register NFQUEUE func: ", err)
	}

	if useNFT {
		execCommand("nft add table ip dnsr-nf")
		execCommand("nft add chain ip dnsr-nf input { type filter hook input priority 0 \\; }")
		execCommand("nft add chain ip dnsr-nf forward { type filter hook forward priority 0 \\; }")
		execCommand("nft add chain ip dnsr-nf output { type filter hook output priority 0 \\; }")
		execCommand("nft add rule ip dnsr-nf input udp sport 53 queue num ", strconv.Itoa(NFQUEUE), " bypass")
		execCommand("nft add rule ip dnsr-nf forward udp sport 53 queue num ", strconv.Itoa(NFQUEUE), " bypass")
		execCommand("nft add rule ip dnsr-nf output udp sport 53 queue num ", strconv.Itoa(NFQUEUE), " bypass")
	} else {
		execCommand("iptables -I INPUT -p udp --sport 53 -j NFQUEUE --queue-num", strconv.Itoa(NFQUEUE), "--queue-bypass")
		execCommand("iptables -I FORWARD -p udp --sport 53 -j NFQUEUE --queue-num", strconv.Itoa(NFQUEUE), "--queue-bypass")
		execCommand("iptables -I OUTPUT -p udp --sport 53 -j NFQUEUE --queue-num", strconv.Itoa(NFQUEUE), "--queue-bypass")
	}
	log.Printf(green("NFQUEUE `%d` successfully configured"), NFQUEUE)
}

func removeNfqueue() {
	if !useNFT {
		output, err := exec.Command("sh", "-c", "iptables -L -n -v").Output()
		if err == nil {
			if strings.Contains(string(output), "NFQUEUE num "+strconv.Itoa(NFQUEUE)) {
				execCommand("iptables -D INPUT -p udp --sport 53 -j NFQUEUE --queue-num", strconv.Itoa(NFQUEUE))
				execCommand("iptables -D FORWARD -p udp --sport 53 -j NFQUEUE --queue-num", strconv.Itoa(NFQUEUE))
				execCommand("iptables -D OUTPUT -p udp --sport 53 -j NFQUEUE --queue-num", strconv.Itoa(NFQUEUE))
				log.Printf(green("NFQUEUE `%d` cleanup completed"), NFQUEUE)
				return
			}
			log.Printf("NFQUEUE `%d` not found, nothing cleanup", NFQUEUE)
		} else {
			log.Fatal(err)
		}
	} else {
		output, err := exec.Command("sh", "-c", "nft list tables").Output()
		if err == nil {
			if strings.Contains(string(output), "dnsr-nf") {
				execCommand("nft delete table dnsr-nf")
				log.Printf(green("NFQUEUE `%d` cleanup completed"), NFQUEUE)
				return
			}
			log.Printf("NFQUEUE `%d` not found, nothing cleanup", NFQUEUE)
		} else {
			log.Fatal(err)
		}
	}

	if nf != nil {
		nfCancel()
		nf.Close()
	}
}

// processPacket handles the captured packet
func processPacket(packet []byte) int {
	dnsPayload, err := extractUdpPayload(packet)
	if err != nil {
		// Not a DNS-answer or malformed packet
		if args.Verbose {
			log.Printf("Received bad DNS-package")
		}
		// Accept it to avoid breaking non-DNS traffic that might have been caught accidentally
		return nfqueue.NfAccept
	}
	dnsResponse := parseDNSResponse(dnsPayload)

	// Block?
	for name, _ := range dnsResponse {
		_, blocked := blockedDomains[name]
		if blocked || checkPatterns(name, blockedPatterns) != "" {
			if args.Verbose {
				log.Printf("Blocking DNS-answer for %s", name)
			}
			// Ideally, we would send a fake NXDOMAIN response, but that requires more complex packet manipulation.
			return nfqueue.NfDrop
		}

	}

	// Collect routes to add in a batch
	var batch []routeBatchItem

	for name, ipList := range dnsResponse {
		trimmedDomain := trimDomain(name)
		_, proxied := proxiedDomains[trimmedDomain]
		// Proxy?
		if proxied || checkPatterns(name, proxiedPatterns) != "" {
			for _, ip := range ipList {
				// We update the cache first. If it's a new entry, we schedule it for kernel insertion.
				if proxyIPset.Add(ip) {
					// Cast specific IPs fetched automatically from DNS rules into standard /32s
					batch = append(batch, routeBatchItem{
						prefix: net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)},
						name:   name,
					})
				} else if args.Verbose {
					log.Printf("Old proxy route %s :: %v", name, ip)
				}
			}
		} else { // Direct
			if args.Verbose {
				var inherited []net.IP
				var direct []net.IP

				// Sort the DNS answers by checking actual preset route mappings
				for _, ip := range ipList {
					if proxyIPset.Contains(ip) {
						inherited = append(inherited, ip)
					} else {
						direct = append(direct, ip)
					}
				}

				if len(inherited) > 0 {
					log.Printf("Proxied (IP Match) %s :: %v\n", name, inherited)
				}
				if len(direct) > 0 {
					log.Printf("Direct %s :: %v\n", name, direct)
				}
			}
		}
	}

	// Apply
	if len(batch) > 0 {
		go addRoutesBatch(batch)
	}

	return nfqueue.NfAccept
}
