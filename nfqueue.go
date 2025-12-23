package main

import (
	"context"
	"fmt"
	"log"
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

	err = nf.RegisterWithErrorFunc(ctx, fn, func(e error) int {
		fmt.Println(err)
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
		execCommand("nft add rule ip dnsr-nf input udp sport 53 queue num ", strconv.Itoa(NFQUEUE))
		execCommand("nft add rule ip dnsr-nf forward udp sport 53 queue num ", strconv.Itoa(NFQUEUE))
		execCommand("nft add rule ip dnsr-nf output udp sport 53 queue num ", strconv.Itoa(NFQUEUE))
	} else {
		execCommand("iptables -I INPUT -p udp --sport 53 -j NFQUEUE --queue-num", strconv.Itoa(NFQUEUE))
		execCommand("iptables -I FORWARD -p udp --sport 53 -j NFQUEUE --queue-num", strconv.Itoa(NFQUEUE))
		execCommand("iptables -I OUTPUT -p udp --sport 53 -j NFQUEUE --queue-num", strconv.Itoa(NFQUEUE))
	}
	log.Printf(green("NFQUEUE `%d` successfully configured"), NFQUEUE)
}

func removeNfqueue() {
	if nf != nil {
		nfCancel()
		nf.Close()
	}
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
}

// processPacket обрабатывает перехваченный пакет
func processPacket(packet []byte) int {
	dnsPayload, err := extractUdpPayload(packet)
	if err != nil {
		// Not a DNS-answer
		if args.Verbose {
			log.Printf("Received bad DNS-package")
		}
		return nfqueue.NfAccept // TODO or drop?
	}
	dnsResponse := parseDNSResponse(dnsPayload)

	// Block?
	for name, _ := range dnsResponse {
		_, blocked := blockedDomains[name]
		if blocked || checkPatterns(name, blockedPatterns) != "" {
			if args.Verbose {
				log.Printf("Blocking DNS-answer for %s", name)
			}
			return nfqueue.NfDrop
		}

	}

	for name, ipList := range dnsResponse {
		trimmedDomain := trimDomain(name)
		_, proxied := proxiedDomains[trimmedDomain]
		// Proxy?
		if proxied || checkPatterns(name, proxiedPatterns) != "" {
			for _, ip := range ipList {
				if proxyIPset.Add(ip) {
					addRoute(ip)
					if !args.Silent {
						log.Printf("New proxy route %s :: %v", name, ip)
					}
				} else if args.Verbose {
					log.Printf("Old proxy route %s :: %v", name, ip)
				}
			}
		} else { // Direct
			if args.Verbose {
				log.Printf("Direct %s :: %v\n", name, ipList)
			}
		}
	}

	return nfqueue.NfAccept
}
