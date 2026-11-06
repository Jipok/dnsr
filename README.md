# DNSR (DNS Router)

> [!NOTE]
> **Major Update (4.0)**: 
> - Now uses DNS-based routing instead of transparent proxy
> - Better performance and reliability, especially on routers
> - If you need SOCKS5 proxy support, use old [v3 release](https://github.com/Jipok/dnsr/releases/tag/3.0.0)

A simple yet powerful tool that automatically routes your traffic through VPN for blocked websites while keeping everything else direct. Just download, run, and enjoy unrestricted internet access! Perfect for both personal computers and **routers**.

## Key Features

- ✨ **Simple to Use**: Download and run - that's it!
- 🌐 **Universal**: Works on both Linux PCs and routers (OpenWrt)
- 🚀 **Smart Routing**: Only routes specified websites through VPN, keeping other traffic direct
- ⚡ Lightweight: Minimal resource usage with maximum efficiency
- 🔧 Built-in WireGuard and AmneziaWG support (can automatically set up from config)
- 🔁 **Multi-Tunnel Failover**: Pass multiple configs or interfaces for automatic backup switching
- 🛡️ Optional domain blocking
- 🔄 Auto-cleanup on exit
- 📝 Support for OpenVPN, WireGuard, AmneziaWG, or any other network interface

## Quick Start (2 Minutes Setup)

1. Download the [latest release](https://github.com/Jipok/dnsr/releases/latest) or build from source
2. Prepare your domain and IP lists:
   ```bash
   # Preset IPs for CDNs/services throttled by IP (Cloudflare, Vercel, Fastly, Telegram, Discord, DNS)
   wget https://github.com/Jipok/dnsr/raw/refs/heads/master/ips.lst -O ips.lst

   # For proxy domain list (recommended)
   wget https://github.com/1andrevich/Re-filter-lists/raw/refs/heads/main/domains_all.lst -O proxy.lst
   
   # For block list (optional)
   wget https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts -O blocks.lst
   ```

3. Run with either a VPN config or an existing interface:
   ```bash
   # Using WireGuard config (automatic setup)
   sudo ./dnsr ~/my-wireguard.conf

   # Using AmneziaWG config (automatic setup)
   sudo ./dnsr ~/my-amnezia.conf

   # Multiple configs with automatic failover (primary + backup)
   sudo ./dnsr ~/primary-wg.conf ~/backup-awg.conf
   
   # Or using existing network interface(s)
   sudo ./dnsr --interface tun0            # Single OpenVPN interface
   sudo ./dnsr -i wg0 -i wg1               # Multiple interfaces with failover
   ```

That's it! DNSR automatically handles everything else.

## OpenWrt Setup Guide

1. First, check your router's architecture to download the correct binary:
```bash
uname -m    # or
opkg print-architecture
```

2. Download the appropriate binary for your architecture from the [releases page](https://github.com/Jipok/dnsr/releases/latest).

3. The DNSR requires the NFT queue kernel module. Install it using:
```bash
opkg update
opkg install kmod-nft-queue
```

4. Start dnsr

5. Once DNSR creates its network interface, you'll need to configure a new firewall zone:

<details>
<summary>Click to see firewall zone configuration</summary>

![изображение](https://github.com/user-attachments/assets/c2ffd3f9-2091-4a36-9074-f16787acf657)

![изображение](https://github.com/user-attachments/assets/20c97463-5fd4-4d13-9ced-61935715124a)

![изображение](https://github.com/user-attachments/assets/86d58ed9-485f-43e7-9aa7-e4da8b783e8a)

</details>

### Command Line Options

```
Usage:
  dnsr [options] <WG/Amnezia Config> [Backup Config...]
  dnsr [options] -i <InterfaceName> [-i <BackupInterface>...]

Options:
  -i, --interface strings         Use existing WireGuard/Amnezia interface(s)
      --proxy-list string         File with list of domains to proxy (default "proxy.lst")
      --block-list string         File with list of domains to block (default "blocks.lst")
      --preset-ips string         File with IP addresses to proxy immediately (default "ips.lst")
  -f, --force                     Force remove existing dnsr interface(s)
  -s, --silent                    Don't show when new routes are added
  -v, --verbose                   Enable verbose output
  -p, --persistent                Keep interface (if created) and routes after exit
      --no-conntrack              Disable dropping active connections via conntrack
      --check-interval duration   Health check interval when multiple tunnels are used (default 10s)
      --check-timeout duration    Health check timeout per tunnel (default 3s)
      --fail-threshold int        Consecutive health check failures before switching tunnel (default 3)

Multiple proxy/block/ips lists can be specified using semicolon (;)
Example: proxy1.lst;proxy2.lst;proxy3.lst
```

## How It Works

1. The tool monitors DNS responses using NFQUEUE
2. When a domain from the proxy list is resolved:
   - Creates specific routes for the resolved IP addresses
   - Directs matching traffic through specified interface
3. All other traffic continues to use the default route
4. Domains in the block list are dropped
