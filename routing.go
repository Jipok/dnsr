package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

var (
	c          *netlink.Conn
	proxyIPset *RouteCache
)

func setupRouting() {
	proxyIPset = NewRouteCache(2500, func(ip net.IP) {
		err := delRoute(ip)
		if err != nil && !args.Silent {
			log.Printf("Dropping old route from kernel %s: %v", ip, err)
		} else if args.Verbose {
			log.Printf("Dropping old route from kernel %s", ip)
		}
	})

	// Open connection to NETLINK_ROUTE
	var err error
	c, err = netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		log.Fatalf(red("Error:")+" dialing netlink: %v", err)
	}

	// 1. Find collisions (analogous to nlListRoutes)
	existingIPs, err := listRoutes(c, link.Index)
	if err != nil {
		log.Fatalf(red("Error:")+" can't read netlink routes: %v", err)
		return
	}

	for _, ip := range existingIPs {
		proxyIPset.Add(ip)
	}

	if proxyIPset.Len() > 0 {
		log.Printf(yellow("WARNING! ")+"found %d collisions in routes table!", proxyIPset.Len())
	}

	// 2. Load user preset
	count := 0

	for _, source := range strings.Split(args.PresetIPs, ";") {
		source = strings.TrimSpace(source)
		if source == "" {
			continue
		}

		file, err := os.Open(source)
		if err != nil {
			log.Fatalf(red("Error")+" opening file %s: %v", source, err)
			continue
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if idx := strings.Index(line, "#"); idx != -1 {
				line = line[:idx]
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			ip := net.ParseIP(line)
			if ip == nil {
				continue
			}

			// Add route via open connection
			if proxyIPset.AddStatic(ip) {
				if err := addRoute(ip); err == nil {
					count++
				} else {
					proxyIPset.Remove(ip)
					log.Printf(yellow("Failed to add route %s: %v"), ip, err)
				}
			}
		}
		file.Close()
	}

	if args.PresetIPs != "" {
		log.Printf("Routing %d preset IP addresses", count)
	}
}

func cleanupRouting() {
	if args.Persistent {
		if proxyIPset.Len() > 0 {
			fmt.Printf(yellow("Persistent mode: %d entries remain.\n"), proxyIPset.Len())
		}
		return
	}

	proxyIPset.FlushCache(func(ip net.IP) {
		delRoute(ip)
	})

	c.Close()
	log.Println(green("Routing cleanup completed"))
}

func addRoute(ip net.IP) error {
	return manageRoute(c, unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK, link.Index, ip)
}

func delRoute(ip net.IP) error {
	// NLM_F_ACK is sufficient/required for deletion if we want confirmation
	return manageRoute(c, unix.RTM_DELROUTE, unix.NLM_F_ACK, link.Index, ip)
}

// --- Logic implementation via mdlayher/netlink ---

// Routing message structure (rtmsg)
// mdlayher/netlink is just the transport - it doesn't know the route payload structure.
type rtMessage struct {
	Family   uint8
	DstLen   uint8
	SrcLen   uint8
	Tos      uint8
	Table    uint8
	Protocol uint8
	Scope    uint8
	Type     uint8
	Flags    uint32
}

func (m *rtMessage) MarshalBinary() ([]byte, error) {
	b := make([]byte, 12)
	b[0] = m.Family
	b[1] = m.DstLen
	b[2] = m.SrcLen
	b[3] = m.Tos
	b[4] = m.Table
	b[5] = m.Protocol
	b[6] = m.Scope
	b[7] = m.Type
	binary.NativeEndian.PutUint32(b[8:12], m.Flags)
	return b, nil
}

func manageRoute(c *netlink.Conn, typeHeader netlink.HeaderType, flags netlink.HeaderFlags, LinkIndex int, ip net.IP) error {
	ip = ip.To4()
	if ip == nil {
		return fmt.Errorf("IPv6 not supported in this snippet")
	}

	// 1. Create message header (rtmsg)
	rt := rtMessage{
		Family:   unix.AF_INET,
		DstLen:   32, // /32
		Table:    unix.RT_TABLE_MAIN,
		Protocol: unix.RTPROT_BOOT,
		Scope:    unix.RT_SCOPE_UNIVERSE,
		Type:     unix.RTN_UNICAST,
	}
	rtData, _ := rt.MarshalBinary()

	// 2. Encode attributes (RTA_DST, RTA_OIF)
	ae := netlink.NewAttributeEncoder()
	ae.Bytes(unix.RTA_DST, ip)
	ae.Uint32(unix.RTA_OIF, uint32(LinkIndex))

	attrs, err := ae.Encode()
	if err != nil {
		return err
	}

	// 3. Assemble the complete message
	req := netlink.Message{
		Header: netlink.Header{
			Type:  typeHeader,
			Flags: netlink.Request | flags,
		},
		Data: append(rtData, attrs...),
	}

	// 4. Send and wait for confirmation (Execute does Send + Receive + Validate)
	if _, err := c.Execute(req); err != nil {
		// We could ignore "File exists" on add or "No such process" on delete here if needed
		return err
	}

	return nil
}

func listRoutes(c *netlink.Conn, linkIndex int) ([]net.IP, error) {
	// Request: RTM_GETROUTE + NLM_F_DUMP
	rt := rtMessage{
		Family: unix.AF_INET,
		Table:  unix.RT_TABLE_MAIN,
	}
	rtData, _ := rt.MarshalBinary()

	req := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.RTM_GETROUTE),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: rtData,
	}

	// Get list of messages (mdlayher handles multipart messages)
	msgs, err := c.Execute(req)
	if err != nil {
		return nil, err
	}

	var res []net.IP
	for _, m := range msgs {
		if m.Header.Type != netlink.HeaderType(unix.RTM_NEWROUTE) {
			continue
		}

		// Skip the first 12 bytes (this is the rtmsg struct),
		// we are interested in the attributes following them.
		if len(m.Data) < 12 {
			continue
		}

		ad, err := netlink.NewAttributeDecoder(m.Data[12:])
		if err != nil {
			continue
		}

		var dst net.IP
		var oif int

		for ad.Next() {
			switch ad.Type() {
			case unix.RTA_DST:
				dst = net.IP(ad.Bytes())
			case unix.RTA_OIF:
				oif = int(ad.Uint32())
			}
		}

		if oif == linkIndex && dst != nil {
			res = append(res, dst)
		}
	}
	return res, nil
}
