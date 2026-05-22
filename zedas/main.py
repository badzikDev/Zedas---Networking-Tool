import click
import json
import os
import sys
import shutil
import threading
import time
from datetime import datetime
from scapy.all import sniff, IP, Ether, ARP, conf, get_if_addr, srp

# Store the tracking database reliably in the root home directory since the 
# tool will automatically elevate to root privilege status on execution.
DB_FILE = "/root/.zedas_inventory.json"

# Thread safety lock for concurrent database modifications
db_lock = threading.Lock()

def ensure_root():
    """
    Guarantees the script runs with root permissions.
    If run as a normal user, it captures its own absolute path before 
    sudo strips the environment PATH, then self-elevates seamlessly.
    """
    if os.getuid() != 0:
        # Resolve the exact absolute execution binary path chosen by the user's system
        script_path = shutil.which(sys.argv[0]) or os.path.abspath(sys.argv[0])
        
        click.echo("[*] Zedas requires root privileges to open raw network sockets.")
        click.echo("[*] Automatically elevating via sudo...")
        
        try:
            # Replace the current process with a sudo-escalated instance using the absolute path
            os.execvp("sudo", ["sudo", script_path] + sys.argv[1:])
        except Exception as e:
            click.echo(f"[-] Critical Error: Failed to automatically elevate privileges: {e}")
            sys.exit(1)

def load_inventory():
    """Loads the saved network devices from disk."""
    if os.path.exists(DB_FILE):
        try:
            with db_lock:
                with open(DB_FILE, "r") as f:
                    return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}

def save_inventory(inventory):
    """Saves the current network state cleanly to disk with thread safety."""
    with db_lock:
        with open(DB_FILE, "w") as f:
            json.dump(inventory, f, indent=4)

def get_default_interface():
    """Fallback utility to find the active main network interface routing out."""
    try:
        return conf.route.route("0.0.0.0")[0]
    except Exception:
        return conf.iface

def is_local_ip(ip):
    """
    Returns True if the IP belongs to a standard private local network space.
    This safely strips out external public routing destinations.
    """
    if not ip:
        return False
    return (
        ip.startswith("10.") or 
        ip.startswith("192.168.") or 
        ip.startswith("172.") or 
        ip.startswith("127.")
    )

def active_subnet_scanner(subnet, interface, inventory):
    """
    Background worker that broadcasts ARP requests across the local subnet.
    Forces wireless clients to reply directly to us, bypassing managed-mode limits.
    """
    while True:
        try:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
            answered, _ = srp(arp_request, iface=interface, timeout=3, verbose=False)
            
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            mutated = False
            
            for _, received_packet in answered:
                src_mac = received_packet[Ether].src
                src_ip = received_packet[ARP].psrc
                
                if not src_mac or src_mac == "00:00:00:00:00:00" or not is_local_ip(src_ip):
                    continue
                
                if src_mac not in inventory:
                    inventory[src_mac] = {
                        "ip": src_ip,
                        "last_seen": now,
                        "packets": 1
                    }
                    click.echo(f"[NEW DEVICE FOUND VIA ACTIVE SCAN] MAC: {src_mac} --> {src_ip}")
                    mutated = True
                else:
                    if inventory[src_mac]["ip"] != src_ip:
                        inventory[src_mac]["ip"] = src_ip
                        click.echo(f"[IP ROAMED/CHANGED VIA ACTIVE SCAN] MAC: {src_mac} --> {src_ip}")
                        mutated = True
                    
                    inventory[src_mac]["last_seen"] = now
                    inventory[src_mac]["packets"] += 1
                    if inventory[src_mac]["packets"] % 5 == 0:
                        mutated = True
            
            if mutated:
                save_inventory(inventory)
                
        except Exception:
            pass
        
        time.sleep(30)


@click.group()
def cli():
    """Zedas: A custom network asset tracking and capture utility."""
    # Intercept every CLI command entry and ensure it runs with root permissions
    ensure_root()

@cli.command()
@click.option('--interface', '-i', default=None, help='Specific network interface to sniff on (e.g., eth0, wlan0)')
def listen(interface):
    """Start the live background tracking engine to capture devices."""
    target_iface = interface if interface else get_default_interface()
    
    click.echo(f"Initializing Zedas network listener on interface: {target_iface}...")
    
    try:
        local_ip = get_if_addr(target_iface)
        ip_parts = local_ip.split('.')
        target_subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        click.echo(f"Targeting Local Subnet for Active Sweeps: {target_subnet}")
    except Exception:
        target_subnet = "192.168.1.0/24"
        click.echo(f"Could not automatically resolve subnet; falling back to: {target_subnet}")

    click.echo("Press Ctrl+C to halt tracking safely.")
    
    inventory = load_inventory()

    scanner_thread = threading.Thread(
        target=active_subnet_scanner, 
        args=(target_subnet, target_iface, inventory),
        daemon=True
    )
    scanner_thread.start()

    def process_packet(packet):
        src_ip = None
        if packet.haslayer(IP):
            src_ip = packet[IP].src
        elif packet.haslayer(ARP):
            src_ip = packet[ARP].psrc
        else:
            return
       
        if not is_local_ip(src_ip):
            return

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_mac = None

        if packet.haslayer(Ether):
            src_mac = packet[Ether].src
        elif packet.haslayer(ARP):
            src_mac = packet[ARP].hwsrc
        elif hasattr(packet, 'linktype') and packet.linktype == 113:
            src_mac = packet.fields.get('src', None)
        else:
            src_mac = packet.src if hasattr(packet, 'src') else None

        if not src_mac or src_mac == "00:00:00:00:00:00":
             return

        if src_mac not in inventory:
            inventory[src_mac] = {
                "ip": src_ip,
                "last_seen": now,
                "packets": 1
            }
            save_inventory(inventory)
            click.echo(f"[NEW DEVICE FOUND] MAC: {src_mac} --> {src_ip}")
        else:
            if inventory[src_mac]["ip"] != src_ip:
                inventory[src_mac]["ip"] = src_ip
                click.echo(f"[IP ROAMED/CHANGED] MAC: {src_mac} --> {src_ip}")

            inventory[src_mac]["last_seen"] = now
            inventory[src_mac]["packets"] += 1
            
            if inventory[src_mac]["packets"] % 5 == 0:
                save_inventory(inventory)

    try:
        sniff(prn=process_packet, store=False, promisc=True, iface=target_iface)
    except KeyboardInterrupt:
        click.echo("\n[!] Stopping Zedas listener engine. State committed.")
        save_inventory(inventory)

@cli.command()
def show():
    """Display all discovered network assets on your current local network."""
    inventory = load_inventory()
    
    if not inventory:
        click.echo("\n[!] No devices cataloged yet. Run 'zedas listen' first to discover assets.\n")
        return

    click.echo("\n" + "="*75)
    click.echo(f"{'MAC ADDRESS':<20} | {'LAST OBSERVED IP':<18} | {'SEEN AT':<20} | {'VOLUME':<8}")
    click.echo("="*75)
    
    sorted_inventory = sorted(inventory.items(), key=lambda x: x[1]['last_seen'], reverse=True)
    
    for mac, data in sorted_inventory:
        click.echo(f"{mac:<20} | {data['ip']:<18} | {data['last_seen']:<20} | {data['packets']:<8}")
        
    click.echo("="*75 + "\n")

if __name__ == "__main__":
    cli()
