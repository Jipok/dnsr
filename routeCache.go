package main

import (
	"container/list"
	"net"
	"sync"
)

// EvictCallback is called when an IP is removed from the cache due to overflow
type EvictCallback func(ip net.IP)

// RouteCache implements a Least Recently Used (LRU) cache for IPv4 addresses
type RouteCache struct {
	mu sync.Mutex

	capacity int

	// items maps the IPv4 array to the linked list element for O(1) access.
	// For static IPs, the value (list element) will be nil!
	items map[[4]byte]*list.Element

	// static maps the [4]byte key to a boolean.
	// If present here, this IP will NEVER be evicted by the LRU logic.
	static map[[4]byte]struct{}

	// evictList is a doubly linked list.
	// Front: Most recently used (hot).
	// Back: Least recently used (candidate for eviction).
	evictList *list.List

	// onEvict is the callback function to remove the route from the OS kernel
	onEvict EvictCallback
}

// NewRouteCache initializes the LRU cache
func NewRouteCache(capacity int, onEvict EvictCallback) *RouteCache {
	return &RouteCache{
		capacity:  capacity,
		items:     make(map[[4]byte]*list.Element),
		static:    make(map[[4]byte]struct{}),
		evictList: list.New(),
		onEvict:   onEvict,
	}
}

// Add inserts a new IP or updates the freshness of an existing one.
// Returns true if the IP is new.
func (c *RouteCache) Add(ip net.IP) bool {
	// 1. Critical section: Update memory state ONLY
	c.mu.Lock()

	ip4 := ip.To4()
	if ip4 == nil {
		c.mu.Unlock()
		return false // Ignore non-IPv4
	}

	var key [4]byte
	copy(key[:], ip4)

	if _, isStatic := c.static[key]; isStatic {
		// It exists and is pinned. Do not touch LRU order.
		c.mu.Unlock()
		return false
	}

	if ent, ok := c.items[key]; ok {
		c.evictList.MoveToFront(ent)
		c.mu.Unlock()
		return false // Route exists, update LRU position and return
	}

	// Add new IP to the front of the list
	ent := c.evictList.PushFront(key)
	c.items[key] = ent

	// Check capacity. If overflow, remove from map/list but defer the callback.
	var evictedIP net.IP
	if c.evictList.Len() > c.capacity {
		evictedIP = c.removeOldest()
	}

	// Release the lock BEFORE calling the external callback (Netlink I/O)
	c.mu.Unlock()

	// 2. I/O section: Perform system calls without holding the lock
	if evictedIP != nil && c.onEvict != nil {
		c.onEvict(evictedIP)
	}

	return true
}

// AddStatic adds an IP that acts as a permanent route for this session.
// It will NOT be removed when the cache fills up.
// It returns true if the route is new and needs to be added to the OS.
func (c *RouteCache) AddStatic(ip net.IP) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	var key [4]byte
	copy(key[:], ip4)

	// If it's already static, do nothing
	if _, isStatic := c.static[key]; isStatic {
		return false
	}

	// If it currently exists as a dynamic route, UPGRADE it to static
	if el, exists := c.items[key]; exists {
		// Remove from the LRU eviction list
		c.evictList.Remove(el)
		// Mark as static (nil element in items map indicates static in this logic)
		c.items[key] = nil
		c.static[key] = struct{}{}

		// It existed in the map (kernel), so we don't need to add it again
		return false
	}

	// It's a brand new static route
	c.items[key] = nil
	c.static[key] = struct{}{}

	return true
}

// removeOldest removes the item at the back of the list (LRU)
func (c *RouteCache) removeOldest() net.IP {
	ent := c.evictList.Back()
	if ent != nil {
		c.evictList.Remove(ent)
		key := ent.Value.([4]byte)
		delete(c.items, key)
		return net.IP(key[:])
	}
	return nil
}

// Peek checks if an IP is in the cache without changing its LRU position.
func (c *RouteCache) Peek(ip net.IP) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	var key [4]byte
	copy(key[:], ip4)

	_, ok := c.items[key]
	return ok
}

// Remove deletes an IP from cache
func (c *RouteCache) Remove(ip net.IP) {
	c.mu.Lock()
	defer c.mu.Unlock()

	ip4 := ip.To4()
	if ip4 == nil {
		return
	}
	var key [4]byte
	copy(key[:], ip4)

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

// FlushCache safely iterates over all items to clean them up
func (c *RouteCache) FlushCache(callback func(net.IP)) {
	c.mu.Lock()

	// Snapshot all IPs that need to be removed
	ips := make([]net.IP, 0, len(c.items))
	for key := range c.items {
		ip := make(net.IP, 4)
		copy(ip, key[:])
		ips = append(ips, ip)
	}

	c.items = make(map[[4]byte]*list.Element)
	c.static = make(map[[4]byte]struct{})
	c.evictList.Init()

	c.mu.Unlock()

	// Perform callbacks (Netlink calls) sequentially without blocking cache access for others
	for _, ip := range ips {
		callback(ip)
	}
}

// Len returns total number of managed routes (static + dynamic)
func (c *RouteCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}
