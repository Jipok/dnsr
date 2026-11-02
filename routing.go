package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

var (
	proxyIPset   *RouteCache
	netlinkMu    sync.Mutex
	activeTunnel *Tunnel
	endpointIPs  []net.IP
	probeHosts   = []string{"8.8.4.4", "1.0.0.1"}
)

func setupRouting() {
	proxyIPset = NewRouteCache(2500, func(prefix net.IPNet) {
		err := delRoute(prefix)
		if err != nil && !args.Silent {
			log.Printf("Dropping old route from kernel %s: %v", prefix.String(), err)
		} else if args.Verbose {
			log.Printf("Dropping old route from kernel %s", prefix.String())
		}
	})

	activeTunnel = tunnels[0]
	if len(tunnels) > 1 {
		log.Printf("Probing %d tunnels to select initial active interface...", len(tunnels))
		selected := false
		for _, t := range tunnels {
			status := red("DOWN")
			if probeTunnel(context.Background(), t, args.CheckTimeout) {
				status = green("UP")
				if !selected {
					activeTunnel = t
					selected = true
				}
			}
			log.Printf("  Tunnel %s (%s): %s", t.Name, tunnelLabel(t), status)
		}
		if !selected {
			log.Printf(yellow("Warning: no tunnel answered initial probe, defaulting to %s (%s)"),
				activeTunnel.Name, tunnelLabel(activeTunnel))
		} else {
			log.Printf(green("Selected active tunnel: %s (%s)"), activeTunnel.Name, tunnelLabel(activeTunnel))
		}
	}

	// Open connection to NETLINK_ROUTE
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		log.Fatalf(red("Error:")+" dialing netlink: %v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		log.Printf(yellow("Warning:")+" failed to set netlink deadline: %v", err)
	}

	// 1. Find collisions (analogous to nlListRoutes)
	for _, t := range tunnels {
		existingPrefixes, err := listRoutes(conn, t.Link.Index)
		if err != nil {
			log.Fatalf(red("Error:")+" can't read netlink routes: %v", err)
			return
		}
		for _, prefix := range existingPrefixes {
			proxyIPset.AddPrefix(prefix)
			if t != activeTunnel {
				_ = conn.SetDeadline(time.Now().Add(1 * time.Second))
				_ = sendRouteRequest(conn, unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_REPLACE|unix.NLM_F_ACK, activeTunnel.Link.Index, prefix)
			}
		}
	}

	if proxyIPset.Len() > 0 {
		log.Printf(yellow("WARNING! ")+"found %d collisions in routes table!", proxyIPset.Len())
	}

	// 2. Load user preset
	totalCount := 0

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

		var batch []routeBatchItem

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

			// Try to interpret as structured CIDR subnet or default purely to isolated IPv4 sets
			var prefix *net.IPNet
			_, ipNet, err := net.ParseCIDR(line)
			if err == nil {
				ones, bits := ipNet.Mask.Size()
				if ipNet.IP.To4() == nil || bits != 32 || ones == 0 || !ipNet.IP.To4().IsGlobalUnicast() {
					continue
				}
				ipNet.IP = ipNet.IP.To4()
				prefix = ipNet
			} else {
				parsedIP := net.ParseIP(line)
				if parsedIP == nil || parsedIP.To4() == nil || !parsedIP.To4().IsGlobalUnicast() {
					continue
				}
				prefix = &net.IPNet{IP: parsedIP.To4(), Mask: net.CIDRMask(32, 32)}
			}

			if proxyIPset.AddStaticPrefix(*prefix) {
				batch = append(batch, routeBatchItem{
					prefix: *prefix,
					name:   "`user-preset`",
				})
			}
		}
		file.Close()

		if len(batch) > 0 {
			totalCount += addRoutesBatch(batch)
		}
	}

	if args.PresetIPs != "" {
		log.Printf("Loaded %d preset rules from files", totalCount)
	}
}

func cleanupRouting() {
	if args.Persistent {
		if proxyIPset.Len() > 0 {
			fmt.Printf(yellow("Persistent mode: %d entries remain.\n"), proxyIPset.Len())
		}
		return
	}

	proxyIPset.FlushCache(func(prefix net.IPNet) {
		delRoute(prefix)
	})

	log.Println(green("Routing cleanup completed"))
}

// delRoute handles specific IP/CIDR deletion using a dedicated connection
func delRoute(prefix net.IPNet) error {
	netlinkMu.Lock()
	defer netlinkMu.Unlock()

	c, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return fmt.Errorf("dial routes: %w", err)
	}
	defer c.Close()

	_ = c.SetDeadline(time.Now().Add(500 * time.Millisecond))

	// All our routes live on the active tunnel (switchActiveTunnel moves them under netlinkMu),
	// so keep RTA_OIF to never delete a foreign route with the same prefix
	return sendRouteRequest(c, unix.RTM_DELROUTE, unix.NLM_F_ACK, activeTunnel.Link.Index, prefix)
}

// --- Logic implementation via mdlayher/netlink ---

// mdlayher/netlink is just the transport - it doesn't know the route payload structure
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

type routeBatchItem struct {
	prefix net.IPNet
	name   string
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

// addRoutesBatch adds a slice of Subnets/IPs reusing a single netlink connection
func addRoutesBatch(items []routeBatchItem) int {
	netlinkMu.Lock()
	c, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		netlinkMu.Unlock()
		log.Printf(red("Error:")+" dialing netlink for batch: %v", err)
		for _, item := range items {
			proxyIPset.RemovePrefix(item.prefix)
		}
		return 0
	}

	linkIdx := activeTunnel.Link.Index
	var added []routeBatchItem
	for _, item := range items {
		if overlapsEndpoint(item.prefix) {
			proxyIPset.RemovePrefix(item.prefix)
			log.Printf(yellow("Skipping route %s because it overlaps VPN endpoint"), item.prefix.String())
			continue
		}
		_ = c.SetDeadline(time.Now().Add(1 * time.Second))
		err := sendRouteRequest(c, unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK, linkIdx, item.prefix)
		if err == nil || errors.Is(err, unix.EEXIST) {
			added = append(added, item)
		} else {
			proxyIPset.RemovePrefix(item.prefix)
			log.Printf(yellow("Failed to add route %s: %v"), item.prefix.String(), err)
		}
	}
	c.Close()
	netlinkMu.Unlock()

	for _, item := range added {
		killed := false
		if !args.NoConntrack {
			var err error
			killed, err = killConntrackByDst(item.prefix)
			if err != nil && args.Verbose {
				log.Printf(yellow("Conntrack cleanup failed for %s: %v"), item.prefix.String(), err)
			}
		}
		if !args.Silent {
			if killed {
				log.Printf("New proxy route %s :: %v (killed some connections)", item.name, item.prefix.String())
			} else {
				log.Printf("New proxy route %s :: %v", item.name, item.prefix.String())
			}
		}
	}
	return len(added)
}

// sendRouteRequest contains the low-level logic to construct and send the message on an existing connection
func sendRouteRequest(c *netlink.Conn, typeHeader netlink.HeaderType, flags netlink.HeaderFlags, LinkIndex int, prefix net.IPNet) error {
	ip := prefix.IP.To4()
	if ip == nil {
		return fmt.Errorf("IPv6 not supported")
	}
	maskLen, _ := prefix.Mask.Size()

	// 1. Create message header (rtmsg)
	rt := rtMessage{
		Family:   unix.AF_INET,
		DstLen:   uint8(maskLen),
		Table:    unix.RT_TABLE_MAIN,
		Protocol: unix.RTPROT_BOOT,
		Scope:    unix.RT_SCOPE_UNIVERSE,
		Type:     unix.RTN_UNICAST,
	}
	rtData, _ := rt.MarshalBinary()

	// 2. Encode attributes (RTA_DST, RTA_OIF)
	ae := netlink.NewAttributeEncoder()
	ae.Bytes(unix.RTA_DST, ip)
	if LinkIndex > 0 {
		ae.Uint32(unix.RTA_OIF, uint32(LinkIndex))
	}

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

	// 4. Send and wait for confirmation
	if _, err := c.Execute(req); err != nil {
		return err
	}

	return nil
}

func killConntrackByDst(dest net.IPNet) (bool, error) {
	dstStr := dest.String()
	// Safely fallback for tools misinterpreting basic /32 targets formatted as CIDRs.
	if ones, _ := dest.Mask.Size(); ones == 32 {
		dstStr = dest.IP.String()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "conntrack", "-D", "-d", dstStr)
	output, err := cmd.CombinedOutput()

	if err != nil {
		outStr := string(output)
		// If conntrack exits with status 1, it usually means no entries were found to delete.
		if strings.Contains(outStr, "0 flow") || strings.Contains(err.Error(), "exit status 1") {
			return false, nil
		}
		return false, fmt.Errorf("%v, output: %s", err, strings.TrimSpace(outStr))
	}

	return true, nil
}

func listRoutes(c *netlink.Conn, linkIndex int) ([]net.IPNet, error) {
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

	var res []net.IPNet
	for _, m := range msgs {
		if m.Header.Type != netlink.HeaderType(unix.RTM_NEWROUTE) {
			continue
		}

		// Skip the first 12 bytes (this is the rtmsg struct),
		// we are interested in the attributes following them.
		if len(m.Data) < 12 {
			continue
		}

		// Grabbing Prefix (CIDR/subnet) Limit applied on exact routes natively
		dstLen := m.Data[1]
		table := m.Data[4]
		protocol := m.Data[5]
		if table != unix.RT_TABLE_MAIN || protocol == unix.RTPROT_KERNEL {
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
			res = append(res, net.IPNet{IP: dst, Mask: net.CIDRMask(int(dstLen), 32)})
		}
	}
	return res, nil
}

// --- Failover / Health check logic ---

func registerEndpointIP(ip net.IP) {
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}
	for _, existing := range endpointIPs {
		if existing.Equal(ip4) {
			return
		}
	}
	endpointIPs = append(endpointIPs, ip4)
}

func overlapsEndpoint(prefix net.IPNet) bool {
	for _, epIP := range endpointIPs {
		if prefix.Contains(epIP) {
			return true
		}
	}
	return false
}

func tunnelLabel(t *Tunnel) string {
	if t.ConfigPath != "" {
		return t.ConfigPath
	}
	return t.Name
}

func probeTunnel(parentCtx context.Context, t *Tunnel, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	dialer := net.Dialer{
		Timeout: timeout / time.Duration(len(probeHosts)),
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, t.Name)
			})
			if err != nil {
				return err
			}
			return sockErr
		},
	}
	for _, host := range probeHosts {
		conn, err := dialer.DialContext(ctx, "tcp4", host+":443")
		if err == nil {
			_ = conn.Close()
			return true
		}
		if ctx.Err() != nil {
			return false
		}
	}
	return false
}

// moveRoutesLocked moves our routes from one dnsrN to another. Only routes the kernel actually
// holds on `from` are touched: proxyIPset may also contain prefixes owned by foreign routes (EEXIST)
func moveRoutesLocked(from, to int) int {
	c, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		log.Printf(red("Error:")+" dialing netlink for route replacement: %v", err)
		return 0
	}
	defer c.Close()

	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	prefixes, err := listRoutes(c, from)
	if err != nil {
		log.Printf(red("Error:")+" can't read netlink routes: %v", err)
		return 0
	}

	updated := 0
	for _, prefix := range prefixes {
		_ = c.SetDeadline(time.Now().Add(1 * time.Second))
		err := sendRouteRequest(c, unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_REPLACE|unix.NLM_F_ACK, to, prefix)
		if err == nil || errors.Is(err, unix.EEXIST) {
			updated++
		} else if args.Verbose {
			log.Printf(yellow("Failed to replace route %s: %v"), prefix.String(), err)
		}
	}
	return updated
}

func switchActiveTunnel(newTun *Tunnel) {
	netlinkMu.Lock()
	oldTun := activeTunnel
	if oldTun == newTun {
		netlinkMu.Unlock()
		return
	}
	activeTunnel = newTun
	updated := moveRoutesLocked(oldTun.Link.Index, newTun.Link.Index)
	netlinkMu.Unlock()

	if !args.NoConntrack && oldTun != nil && oldTun.AddressIP != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = exec.CommandContext(ctx, "conntrack", "-D", "-q", oldTun.AddressIP).Run()
		cancel()
	}

	log.Printf(green("[FAILOVER] Tunnel %s unreachable: switched active tunnel %s (%s) -> %s (%s) [updated %d routes]"),
		oldTun.Name, oldTun.Name, tunnelLabel(oldTun), newTun.Name, tunnelLabel(newTun), updated)
}

func startFailoverMonitor(ctx context.Context) {
	ticker := time.NewTicker(args.CheckInterval)
	defer ticker.Stop()

	fails := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		cur := activeTunnel
		if probeTunnel(ctx, cur, args.CheckTimeout) {
			if fails > 0 {
				log.Printf(green("[HEALTH] Active tunnel %s (%s) is healthy again"), cur.Name, tunnelLabel(cur))
				fails = 0
			}
			continue
		}
		if ctx.Err() != nil {
			return
		}

		fails++
		log.Printf(yellow("[HEALTH] Active tunnel %s (%s) check failed (%d/%d)"),
			cur.Name, tunnelLabel(cur), fails, args.FailThreshold)

		if fails < args.FailThreshold {
			continue
		}

		var next *Tunnel
		for _, cand := range tunnels {
			if cand != cur && probeTunnel(ctx, cand, args.CheckTimeout) {
				next = cand
				break
			}
		}
		if ctx.Err() != nil {
			return
		}

		if next != nil {
			fails = 0
			switchActiveTunnel(next)
		} else {
			log.Printf(red("[FAILOVER] Tunnel %s (%s) is unreachable and no healthy standby tunnel was found!"),
				cur.Name, tunnelLabel(cur))
		}
	}
}
