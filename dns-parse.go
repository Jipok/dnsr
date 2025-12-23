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
	result := make(map[string][]net.IP)
	var parser dnsmessage.Parser

	if _, err := parser.Start(dnsPayload); err != nil {
		fmt.Println("Failed to parse DNS message:", err)
		return result
	}

	// Question parsing
	var requestedName string
	for {
		qq, err := parser.Question()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		requestedName = qq.Name.String()
		if err != nil {
			fmt.Println("Failed to parse Question:", err)
			return result
		}
	}

	// Store all answers to process them later
	answers, err := parser.AllAnswers()
	if err != nil {
		fmt.Println("Failed to parse DNSAnswers:", err)
		return result
	}

	// First collect all CNAME records
	cnameMap := make(map[string]string)
	for _, rr := range answers {
		if rr.Header.Type == dnsmessage.TypeCNAME {
			if cname, ok := rr.Body.(*dnsmessage.CNAMEResource); ok {
				name := strings.ToLower(strings.TrimSuffix(rr.Header.Name.String(), "."))
				target := strings.ToLower(strings.TrimSuffix(cname.CNAME.String(), "."))
				cnameMap[name] = target
			}
		}
	}

	// Then process A records
	for _, rr := range answers {
		if rr.Header.Type == dnsmessage.TypeA {
			if a, ok := rr.Body.(*dnsmessage.AResource); ok {
				name := strings.ToLower(strings.TrimSuffix(rr.Header.Name.String(), "."))
				ip := net.IP(a.A[:])

				// Add IP to the original name
				result[name] = append(result[name], ip)

				// Follow and add to all CNAME references
				for source, target := range cnameMap {
					if target == name {
						result[source] = append(result[source], ip)
					}
				}
			}
		}
	}

	if args.Verbose && len(result) == 0 {
		log.Print("Empty/Useless DNS-answer for ", requestedName)
	}
	return result
}
