package main

import (
	"container/list"
	"net"
	"sync"
)

// cacheKey defines a unique hashable state for both Subnets & standard IPs
type cacheKey struct {
	ip   [4]byte
	mask uint8
}

func makeKey(prefix net.IPNet) (cacheKey, bool) {
	ip4 := prefix.IP.To4()
	if ip4 == nil {
		return cacheKey{}, false
	}

	ones, _ := prefix.Mask.Size()
	var key cacheKey

	// Fast path for standard /32 IPs to avoid unnecessary math
	if ones == 32 {
		copy(key.ip[:], ip4)
		key.mask = 32
		return key, true
	}

	// Apply bitwise AND with the subnet mask to zero-out host bits
	mask := net.CIDRMask(ones, 32)
	for i := 0; i < 4; i++ {
		key.ip[i] = ip4[i] & mask[i]
	}
	key.mask = uint8(ones)

	return key, true
}

// EvictCallback is called when a prefix is removed from the cache due to overflow
type EvictCallback func(prefix net.IPNet)

// RouteCache implements a Least Recently Used (LRU) cache for IPv4 prefixes (and IPs)
type RouteCache struct {
	mu sync.Mutex

	capacity int

	// items maps the cacheKey to the linked list element for O(1) access.
	// For static prefixes, the value (list element) will be nil!
	items map[cacheKey]*list.Element

	// static maps the cacheKey to a boolean.
	// If present here, this prefix will NEVER be evicted by the LRU logic.
	static map[cacheKey]struct{}

	// evictList is a doubly linked list wrapping most cacheKeys
	evictList *list.List

	onEvict EvictCallback
}

// NewRouteCache initializes the LRU cache
func NewRouteCache(capacity int, onEvict EvictCallback) *RouteCache {
	return &RouteCache{
		capacity:  capacity,
		items:     make(map[cacheKey]*list.Element),
		static:    make(map[cacheKey]struct{}),
		evictList: list.New(),
		onEvict:   onEvict,
	}
}

func (k cacheKey) Contains(ip4 []byte) bool {
	if k.mask == 32 {
		// Fast path for exact /32 match
		return k.ip[0] == ip4[0] && k.ip[1] == ip4[1] && k.ip[2] == ip4[2] && k.ip[3] == ip4[3]
	}

	mask := net.CIDRMask(int(k.mask), 32)
	for i := 0; i < 4; i++ {
		if ip4[i]&mask[i] != k.ip[i]&mask[i] {
			return false
		}
	}
	return true
}

// Add Contains method to verify if an IP resolves into an existing subset coverage
func (c *RouteCache) Contains(ip net.IP) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	var key32 cacheKey
	copy(key32.ip[:], ip4)
	key32.mask = 32

	// Fast path exact matches
	if _, isStatic := c.static[key32]; isStatic {
		return true
	}
	if _, exists := c.items[key32]; exists {
		return true
	}

	// Subnet / Subset CIDR match checks
	for k := range c.static {
		if k.mask < 32 && k.Contains(ip4) {
			return true
		}
	}
	for k := range c.items {
		if k.mask < 32 && k.Contains(ip4) {
			return true
		}
	}

	return false
}

// Checks if the newly resolved IP is ALREADY COVERED by wider CIDR blocks
func (c *RouteCache) Add(ip net.IP) bool {
	c.mu.Lock()

	ip4 := ip.To4()
	if ip4 == nil {
		c.mu.Unlock()
		return false
	}

	var key32 cacheKey
	copy(key32.ip[:], ip4)
	key32.mask = 32

	// Step 1: Check fast path (exact /32 match)
	if _, isStatic := c.static[key32]; isStatic {
		c.mu.Unlock()
		return false
	}
	if ent, exists := c.items[key32]; exists {
		// Route exists exactly, update LRU position and return
		c.evictList.MoveToFront(ent)
		c.mu.Unlock()
		return false
	}

	// Step 2: Check if the IP is covered by ANY existing CIDR subnet
	for k := range c.static {
		if k.mask < 32 && k.Contains(ip4) {
			// Covered by a static preset, no action needed
			c.mu.Unlock()
			return false
		}
	}
	for k, ent := range c.items {
		if k.mask < 32 && k.Contains(ip4) {
			// Covered by a dynamically added subnet.
			// Bump the covering CIDR rule to the front of LRU so it isn't evicted
			c.evictList.MoveToFront(ent)
			c.mu.Unlock()
			return false
		}
	}

	// Step 3: Not covered by anything. Add as a new /32 dynamic route!
	ent := c.evictList.PushFront(key32)
	c.items[key32] = ent

	// Check capacity limitations
	var evictedPrefix *net.IPNet
	if c.evictList.Len() > c.capacity {
		evictedPrefix = c.removeOldest()
	}

	// Release the lock BEFORE calling the external callback (Netlink I/O calls)
	c.mu.Unlock()

	// External Netlink Callback to drop route from kernel
	if evictedPrefix != nil && c.onEvict != nil {
		c.onEvict(*evictedPrefix)
	}

	return true
}

// AddPrefix inserts a new network subset or updates freshness of an existing one. Returns true if new.
func (c *RouteCache) AddPrefix(prefix net.IPNet) bool {
	c.mu.Lock()

	key, ok := makeKey(prefix)
	if !ok {
		c.mu.Unlock()
		return false
	}

	if _, isStatic := c.static[key]; isStatic {
		c.mu.Unlock()
		return false
	}

	if ent, exists := c.items[key]; exists {
		c.evictList.MoveToFront(ent)
		c.mu.Unlock()
		return false // Exists already
	}

	ent := c.evictList.PushFront(key)
	c.items[key] = ent

	var evictedPrefix *net.IPNet
	if c.evictList.Len() > c.capacity {
		evictedPrefix = c.removeOldest()
	}

	c.mu.Unlock()

	// External Netlink Callback logic
	if evictedPrefix != nil && c.onEvict != nil {
		c.onEvict(*evictedPrefix)
	}

	return true
}

// AddStaticPrefix establishes persistent CIDR/IP rules across caches
func (c *RouteCache) AddStaticPrefix(prefix net.IPNet) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	key, ok := makeKey(prefix)
	if !ok {
		return false
	}

	if _, isStatic := c.static[key]; isStatic {
		return false
	}

	if el, exists := c.items[key]; exists {
		// Found as dynamic route, UPGRADE to static safely
		c.evictList.Remove(el)
		delete(c.items, key) // safely delete so it is completely moved
		c.static[key] = struct{}{}
		return false
	}

	c.static[key] = struct{}{}
	return true
}

// removeOldest pops the rear item bounding Cache constraints
func (c *RouteCache) removeOldest() *net.IPNet {
	ent := c.evictList.Back()
	if ent != nil {
		c.evictList.Remove(ent)
		key := ent.Value.(cacheKey)
		delete(c.items, key)
		return &net.IPNet{IP: net.IP(key.ip[:]), Mask: net.CIDRMask(int(key.mask), 32)}
	}
	return nil
}

// Peek safely checks IP placement logic acting strictly as single /32 validation
func (c *RouteCache) Peek(ip net.IP) bool {
	return c.PeekPrefix(net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
}

func (c *RouteCache) PeekPrefix(prefix net.IPNet) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	key, ok := makeKey(prefix)
	if !ok {
		return false
	}
	if _, isStatic := c.static[key]; isStatic {
		return true
	}
	_, found := c.items[key]
	return found
}

// Remove drops IP logic securely bypassing limits
func (c *RouteCache) Remove(ip net.IP) {
	c.RemovePrefix(net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
}

func (c *RouteCache) RemovePrefix(prefix net.IPNet) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key, ok := makeKey(prefix)
	if !ok {
		return
	}

	if _, isStatic := c.static[key]; isStatic {
		delete(c.static, key)
		delete(c.items, key)
		return
	}

	if ent, ok := c.items[key]; ok {
		c.evictList.Remove(ent)
		delete(c.items, key)
	}
}

// FlushCache safely cycles arrays ensuring final system wipe out
func (c *RouteCache) FlushCache(callback func(net.IPNet)) {
	c.mu.Lock()

	var prefixes []net.IPNet

	for key := range c.items {
		ip := make(net.IP, 4)
		copy(ip, key.ip[:])
		prefixes = append(prefixes, net.IPNet{IP: ip, Mask: net.CIDRMask(int(key.mask), 32)})
	}
	for key := range c.static {
		ip := make(net.IP, 4)
		copy(ip, key.ip[:])
		prefixes = append(prefixes, net.IPNet{IP: ip, Mask: net.CIDRMask(int(key.mask), 32)})
	}

	c.items = make(map[cacheKey]*list.Element)
	c.static = make(map[cacheKey]struct{})
	c.evictList.Init()

	c.mu.Unlock()

	for _, p := range prefixes {
		callback(p)
	}
}

// Len summarizes entries tracked concurrently
func (c *RouteCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items) + len(c.static)
}
