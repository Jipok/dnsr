package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

type ResolvedName struct {
	name string
	ip   net.IP
}

// extractUDPayload извлекает полезную нагрузку из IP пакета
func extractUdpPayload(packet []byte) ([]byte, error) {
	if len(packet) < 20 {
		return nil, fmt.Errorf("packet too short for IPv4 header")
	}

	// Парсим IPv4 заголовок
	versionIHL := packet[0]
	version := versionIHL >> 4
	if version != 4 {
		return nil, fmt.Errorf("not an IPv4 packet")
	}

	ihl := versionIHL & 0x0F
	ipHeaderLen := int(ihl) * 4
	if len(packet) < ipHeaderLen {
		return nil, fmt.Errorf("invalid IP header length")
	}

	protocol := packet[9]
	if protocol != 17 { // Протокол UDP имеет номер 17
		return nil, fmt.Errorf("not a UDP packet")
	}

	// Парсим UDP заголовок
	if len(packet) < ipHeaderLen+8 {
		return nil, fmt.Errorf("packet too short for UDP header")
	}

	udpHeaderStart := ipHeaderLen
	srcPort := binary.BigEndian.Uint16(packet[udpHeaderStart : udpHeaderStart+2])
	// dstPort := binary.BigEndian.Uint16(packet[udpHeaderStart+2 : udpHeaderStart+4])
	udpLength := binary.BigEndian.Uint16(packet[udpHeaderStart+4 : udpHeaderStart+6])

	// Проверяем длину UDP пакета
	if len(packet) < ipHeaderLen+int(udpLength) {
		return nil, fmt.Errorf("packet too short for UDP payload")
	}

	// Проверяем, является ли пакет DNS ответом (исходный порт 53)
	if srcPort != 53 {
		return nil, fmt.Errorf("not a DNS response (source port != 53)")
	}

	dnsPayload := packet[udpHeaderStart+8 : ipHeaderLen+int(udpLength)]
	return dnsPayload, nil
}

func parseDNSResponse(dnsPayload []byte) map[string][]net.IP {
	var p dnsmessage.Parser

	// 1. Start parsing and check for truncation
	_, err := p.Start(dnsPayload)
	if err != nil {
		if args.Verbose {
			log.Printf("Failed to parse DNS header: %v", err)
		}
		return nil
	}

	// If the packet is truncated, we can't trust its content.
	// The OS will retry over TCP, which we don't intercept.
	// We must accept the packet to not break the retry mechanism.
	// We return an empty map to signal "accept, but do nothing".
	// if header.Truncated {
	// 	if args.Verbose {
	// 		log.Println("Truncated DNS response (client will retry over TCP)")
	// 	}
	// 	return nil
	// }

	// 2. Parse Questions (info only, non-fatal if fails)
	questions, err := p.AllQuestions()
	if err != nil && err != dnsmessage.ErrSectionDone {
		if args.Verbose {
			log.Printf("Warning: failed to parse questions (continuing to answers): %v", err)
		}
		// Reset parser to try and skip to the answers section
		p.Start(dnsPayload)
		if err := p.SkipAllQuestions(); err != nil {
			// If we can't even skip questions, the packet structure is too broken.
			return nil
		}
	}

	var requestedName string
	if len(questions) > 0 {
		requestedName = strings.ToLower(strings.TrimSuffix(questions[0].Name.String(), "."))
	}

	// --- Core Logic ---
	cnameMap := make(map[string]string)
	ipMap := make(map[string][]net.IP)

	// Helper function to process any resource record from any section
	processResource := func(rr dnsmessage.Resource) {
		name := strings.ToLower(strings.TrimSuffix(rr.Header.Name.String(), "."))
		switch rr.Header.Type {
		case dnsmessage.TypeCNAME:
			if cnameBody, ok := rr.Body.(*dnsmessage.CNAMEResource); ok {
				target := strings.ToLower(strings.TrimSuffix(cnameBody.CNAME.String(), "."))
				cnameMap[name] = target
			}
		case dnsmessage.TypeA:
			if aBody, ok := rr.Body.(*dnsmessage.AResource); ok {
				ipMap[name] = append(ipMap[name], net.IP(aBody.A[:]))
			}
		case dnsmessage.TypeAAAA:
			if aaaaBody, ok := rr.Body.(*dnsmessage.AAAAResource); ok {
				ipMap[name] = append(ipMap[name], net.IP(aaaaBody.AAAA[:]))
			}
		}
	}

	// 3. Process Answers
	for {
		rr, err := p.Answer()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			if args.Verbose {
				log.Printf("Error parsing Answer RR: %v", err)
			}
			break
		}
		processResource(rr)
	}

	// 4. Process Authorities (Must be drained to reach Additionals)
	for {
		rr, err := p.Authority()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			// Just skip errors in authority, we rarely need them for simple routing
			break
		}
		processResource(rr)
	}

	// 5. Process Additionals (CRITICAL: Often contains the IP for the CNAME in Answer)
	for {
		rr, err := p.Additional()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			break
		}
		processResource(rr)
	}

	// --- End of Parsing ---

	result := make(map[string][]net.IP)

	// If we found no IPs or CNAMEs at all, there's nothing to resolve or route.
	// This prevents the "Empty/Useless" log for legitimate empty responses (like NXDOMAIN).
	if len(ipMap) == 0 && len(cnameMap) == 0 {
		if args.Verbose {
			log.Printf("DNS response for %s contains no A, AAAA, or CNAME records.", requestedName)
		}
		return result // Return the empty map
	}

	// --- Resolution Logic (matches IPs to CNAME chains) ---
	resolvedCache := make(map[string][]net.IP)

	var findIPs func(name string, depth int) []net.IP
	findIPs = func(name string, depth int) []net.IP {
		if depth > 10 { // Prevent infinite loops
			return nil
		}
		if ips, found := resolvedCache[name]; found {
			return ips
		}
		if ips, found := ipMap[name]; found {
			resolvedCache[name] = ips
			return ips
		}
		if target, found := cnameMap[name]; found {
			ips := findIPs(target, depth+1)
			resolvedCache[name] = ips
			return ips
		}
		resolvedCache[name] = nil
		return nil
	}

	// Collect all involved names
	allNames := make(map[string]struct{})
	if requestedName != "" {
		allNames[requestedName] = struct{}{}
	}
	for name := range cnameMap {
		allNames[name] = struct{}{}
	}
	for name := range ipMap {
		allNames[name] = struct{}{}
	}

	for name := range allNames {
		ips := findIPs(name, 0)
		if len(ips) > 0 {
			// Copy to avoid referencing internal slices
			ipCopy := make([]net.IP, len(ips))
			copy(ipCopy, ips)
			result[name] = ipCopy
		}
	}

	return result
}
