package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

var (
	proxiedDomains  = make(map[string]struct{})
	proxiedPatterns []string
	blockedDomains  = make(map[string]struct{})
	blockedPatterns []string
)

func isPattern(s string) bool {
	return strings.Contains(s, "*")
}

func checkPattern(pattern, str string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == str
	}

	// Begin
	if !strings.HasPrefix(str, parts[0]) {
		return false
	}
	str = str[len(parts[0]):]

	// Middle
	for i := 1; i < len(parts)-1; i++ {
		index := strings.Index(str, parts[i])
		if index == -1 {
			return false
		}
		str = str[index+len(parts[i]):]
	}

	// End
	return strings.HasSuffix(str, parts[len(parts)-1])
}

func checkPatterns(str string, list []string) string {
	for _, pattern := range list {
		ok := checkPattern(pattern, str)
		if ok {
			return pattern
		}
	}
	return ""
}

///////////////////////////////////////////////////////////////////////////////

// a.b.site.com   -> site.com
// aboba.ru       -> aboba.ru
// localhost      -> localhost
// a.test.co.uk   -> test.co.uk
// api.x.com      -> x.com
// a.b.c.test.com -> test.com
func trimDomain(domain string) string {
	parts := strings.Split(domain, ".")

	if len(parts) < 3 {
		return domain
	}
	lastTwo := parts[len(parts)-2:]

	// Если предпоследняя часть короче 3 символов (например, "co.uk"), берем три последние части
	if len(lastTwo[0]) <= 2 && !strings.HasSuffix(domain, ".x.com") {
		if len(parts) >= 3 {
			return strings.Join(parts[len(parts)-3:], ".")
		}
		return domain
	}

	return strings.Join(lastTwo, ".")
}

func readDomains(sources string, fn func(domain string)) {
	for _, source := range strings.Split(sources, ";") {
		source = strings.TrimSpace(source)
		if source == "" {
			continue
		}
		file, err := os.Open(source)
		if err != nil {
			log.Fatalf(red("Error")+" opening file %s: %v", source, err)
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			domain := scanner.Text()
			// Remove comment
			if idx := strings.Index(domain, "#"); idx != -1 {
				domain = domain[:idx]
			}
			domain = strings.TrimSpace(domain)
			domain, _ = strings.CutPrefix(domain, "https-")
			domain, _ = strings.CutPrefix(domain, "https.")
			domain, _ = strings.CutPrefix(domain, "http-")
			domain, _ = strings.CutPrefix(domain, "http.")
			domain, _ = strings.CutPrefix(domain, "0.0.0.0 ")
			domain, _ = strings.CutPrefix(domain, "127.0.0.1 ")
			domain = strings.TrimSpace(domain)
			domain = strings.ToLower(domain)
			if domain == "" {
				continue
			}
			fn(domain)
		}

		if err := scanner.Err(); err != nil {
			log.Fatalf(red("Error")+" reading file %s: %v", source, err)
		}
	}
}

func addProxiedDomain(domain string) {
	pattern := checkPatterns(domain, proxiedPatterns)
	if pattern != "" {
		if args.Verbose {
			fmt.Printf("PROXY: %s  ==  %s\n", pattern, domain)
		}
		return
	}
	if isPattern(domain) {
		proxiedPatterns = append(proxiedPatterns, domain)
		return
	}
	domain = trimDomain(domain)
	if _, exists := proxiedDomains[domain]; !exists {
		proxiedDomains[domain] = struct{}{}
	}
}

func addBlockedDomain(domain string) {
	pattern := checkPatterns(domain, blockedPatterns)
	if pattern != "" {
		if args.Verbose {
			fmt.Printf("BLOCK: %s  ==  %s\n", pattern, domain)
		}
		return
	}
	if isPattern(domain) {
		blockedPatterns = append(blockedPatterns, domain)
		if args.Verbose {
			fmt.Printf("Added block pattern: %s\n", domain)
		}
		return
	}
	if _, exists := blockedDomains[domain]; !exists {
		blockedDomains[domain] = struct{}{}
	}
}
