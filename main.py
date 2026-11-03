from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import ipaddress
import os
import asyncio
import itertools
import socket
import struct
import time
import urllib.request
import logging

try:
    import fcntl
except ImportError:  # non-Unix
    fcntl = None
from datetime import datetime, timezone
from uuid import uuid4

app = FastAPI(title="Network Scanner API", version="1.0.0")

# In-memory storage for scans
scans: Dict[str, dict] = {}

# Ports probed to decide whether a host is up
COMMON_PORTS = [80, 443, 22, 8080, 3000, 8000, 9000]
# Max hosts scanned per network
MAX_HOSTS = 254
# Max concurrent TCP connection attempts
MAX_CONCURRENT_CONNECTIONS = 512
HOSTNAME_TIMEOUT = 2.0

# Common home/office gateways probed (in order) when no usable network is detected,
# e.g. in a Kubernetes pod with a /32 address. Each one that answers gets its /24 scanned.
FALLBACK_GATEWAYS = ["192.168.0.1", "192.168.1.1", "192.168.88.1", "10.0.0.1"]
FALLBACK_PREFIX = 24

# Interfaces created by container runtimes, CNIs and hypervisors. On a node
# (hostNetwork) they hold pod/VM subnets, not the node's LAN, so auto-scan skips them.
VIRTUAL_IFACE_PREFIXES = (
    "cni", "flannel", "cali", "veth", "docker", "kube-", "cilium", "lxc", "vxlan",
    "tunl", "weave", "virbr", "br-", "genev", "nodelocaldns", "podman", "antrea", "ovn",
)

# Service that echoes back the caller's public IP as plain text
PUBLIC_IP_URL = os.environ.get("PUBLIC_IP_URL", "https://ifconfig.me/ip")
PUBLIC_IP_TIMEOUT = 5.0

PROC_NET_ROUTE = "/proc/net/route"
RTF_UP = 0x0001
RTF_GATEWAY = 0x0002
SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891B

logger = logging.getLogger("network_scanner")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()

class ScanRequest(BaseModel):
    network: Optional[str] = None
    scan_ports: Optional[bool] = False
    port_list: Optional[List[int]] = None

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

class HostResult(BaseModel):
    ip: str
    is_up: bool
    hostname: Optional[str] = None
    response_time_ms: Optional[float] = None
    mac_address: Optional[str] = None
    open_ports: Optional[List[int]] = []

class NetworkInfo(BaseModel):
    gateway: Optional[str]
    interfaces: List[Dict[str, Any]]
    routes: List[Dict[str, Any]]

@app.get("/")
def root():
    return {
        "name": "Network Scanner API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs"
    }

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "timestamp": utcnow(),
        "version": "1.0.0"
    }

@app.get("/api/v1/network/info")
def get_network_info():
    """Get network configuration including gateway, interfaces, and routes"""
    try:
        interfaces = list_interfaces()
        routes = list_routes()

        return {
            "gateway": find_gateway(),
            "default_interface": default_interface(routes),
            "public_ip": get_public_ip(),
            "scan_targets": [str(n) for n in node_networks(interfaces, routes)],
            "interfaces": interfaces,
            "routes": routes
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/scan", response_model=ScanResponse)
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new network scan"""
    if request.network:
        try:
            ipaddress.ip_network(request.network, strict=False)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid network: {request.network}")
    if request.port_list and any(not 1 <= p <= 65535 for p in request.port_list):
        raise HTTPException(status_code=400, detail="Ports must be between 1 and 65535")

    scan_id = str(uuid4())
    
    scans[scan_id] = {
        "scan_id": scan_id,
        "status": "running",
        "created_at": utcnow(),
        "completed_at": None,
        "network_info": None,
        "hosts": [],
        "error": None
    }
    
    # Start scan in background
    background_tasks.add_task(run_scan, scan_id, request)
    
    return ScanResponse(
        scan_id=scan_id,
        status="running",
        message="Scan started successfully"
    )

@app.get("/api/v1/scan/{scan_id}")
def get_scan_status(scan_id: str):
    """Get scan status"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return scans[scan_id]

@app.get("/api/v1/scan/{scan_id}/results")
def get_scan_results(scan_id: str):
    """Get scan results"""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    
    scan = scans[scan_id]
    if scan["status"] != "completed":
        raise HTTPException(status_code=400, detail=f"Scan is still {scan['status']}")
    
    return scan["hosts"]

@app.get("/api/v1/network/public-ip")
def public_ip():
    """Get this machine's public IP as seen from the internet"""
    ip = get_public_ip()
    if ip is None:
        raise HTTPException(status_code=502, detail=f"Could not get public IP from {PUBLIC_IP_URL}")
    return {"public_ip": ip, "source": PUBLIC_IP_URL}

@app.get("/api/v1/scans")
def list_scans():
    """List all scans"""
    return list(scans.values())

def get_public_ip() -> Optional[str]:
    """Ask PUBLIC_IP_URL for our public IP. Returns None if unreachable."""
    request = urllib.request.Request(
        PUBLIC_IP_URL,
        headers={"User-Agent": "curl/8.0", "Accept": "text/plain"}
    )
    try:
        with urllib.request.urlopen(request, timeout=PUBLIC_IP_TIMEOUT) as response:
            body = response.read(64).decode("ascii", errors="replace").strip()
        return str(ipaddress.ip_address(body))
    except (OSError, ValueError) as e:
        logger.warning("Could not get public IP from %s: %s", PUBLIC_IP_URL, e)
        return None


def hex_to_ip(value: str) -> str:
    """Convert a little-endian hex address from /proc/net/route to dotted form"""
    return socket.inet_ntoa(struct.pack("<I", int(value, 16)))


def read_proc_routes() -> List[Dict[str, Any]]:
    """Read the IPv4 routing table from /proc/net/route (no external tools needed)"""
    routes = []
    try:
        with open(PROC_NET_ROUTE) as f:
            lines = f.read().strip().splitlines()[1:]
    except OSError as e:
        logger.warning("Could not read %s: %s", PROC_NET_ROUTE, e)
        return routes

    for line in lines:
        fields = line.split()
        if len(fields) < 8:
            continue
        iface, dest, gateway, flags, mask = fields[0], fields[1], fields[2], int(fields[3], 16), fields[7]
        if not flags & RTF_UP:
            continue
        prefix = ipaddress.IPv4Address(hex_to_ip(mask)).packed
        prefix_len = sum(bin(b).count("1") for b in prefix)
        destination = "default" if prefix_len == 0 else f"{hex_to_ip(dest)}/{prefix_len}"
        routes.append({
            "destination": destination,
            "gateway": hex_to_ip(gateway) if flags & RTF_GATEWAY else None,
            "interface": iface
        })
    return routes


def find_gateway() -> Optional[str]:
    """Find the default gateway"""
    for route in list_routes():
        if route["destination"] == "default" and route["gateway"]:
            return route["gateway"]
    return None


def ioctl_ipv4(sock: socket.socket, request: int, name: str) -> Optional[str]:
    try:
        packed = fcntl.ioctl(sock.fileno(), request, struct.pack("256s", name[:15].encode()))
        return socket.inet_ntoa(packed[20:24])
    except OSError:
        return None  # interface has no IPv4 address


def list_interfaces_ioctl() -> List[Dict[str, Any]]:
    """List IPv4 interfaces through socket ioctls (no external tools needed)"""
    interfaces = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _, name in socket.if_nameindex():
            ip = ioctl_ipv4(sock, SIOCGIFADDR, name)
            netmask = ioctl_ipv4(sock, SIOCGIFNETMASK, name)
            if ip and netmask:
                interfaces.append(make_interface(name, f"{ip}/{netmask}"))
    return interfaces


def make_interface(name: str, cidr: str) -> Dict[str, Any]:
    iface = ipaddress.ip_interface(cidr)
    return {
        "name": name,
        "ip": str(iface.ip),
        "netmask": str(iface.netmask),
        "network": str(iface.network)
    }


def list_interfaces() -> List[Dict[str, Any]]:
    """List network interfaces"""
    if fcntl is None:
        logger.warning("Interface lookup requires Linux (fcntl unavailable)")
        return []
    try:
        return list_interfaces_ioctl()
    except OSError as e:
        logger.warning("Interface lookup via ioctl failed: %s", e)
        return []


def list_routes() -> List[Dict[str, Any]]:
    """List routing table"""
    return read_proc_routes()

async def run_scan(scan_id: str, request: ScanRequest):
    """Run network scan in background"""
    try:
        # Get network info
        interfaces = list_interfaces()
        routes = list_routes()

        scans[scan_id]["network_info"] = {
            "gateway": find_gateway(),
            "default_interface": default_interface(routes),
            "public_ip": await asyncio.to_thread(get_public_ip),
            "interfaces": interfaces,
            "routes": routes
        }
        
        # Determine network to scan
        networks_to_scan = []
        if request.network:
            try:
                networks_to_scan.append(ipaddress.ip_network(request.network, strict=False))
            except ValueError:
                scans[scan_id]["status"] = "failed"
                scans[scan_id]["error"] = f"Invalid network: {request.network}"
                return
        else:
            networks_to_scan = node_networks(interfaces, routes)

            if not networks_to_scan:
                networks_to_scan = await find_fallback_networks(request)
                scans[scan_id]["network_info"]["fallback_networks"] = [str(n) for n in networks_to_scan]
        
        # Scan networks
        all_hosts = []
        for network in networks_to_scan:
            hosts = await scan_network(network, request)
            all_hosts.extend(hosts)
        
        scans[scan_id]["hosts"] = all_hosts
        scans[scan_id]["status"] = "completed"
        scans[scan_id]["completed_at"] = utcnow()
        
    except Exception as e:
        scans[scan_id]["status"] = "failed"
        scans[scan_id]["error"] = str(e)

def is_virtual_interface(name: str) -> bool:
    return name.startswith(VIRTUAL_IFACE_PREFIXES)


def default_interface(routes: List[Dict[str, Any]]) -> Optional[str]:
    """Name of the interface carrying the default route (the node's uplink)"""
    for route in routes:
        if route["destination"] == "default":
            return route["interface"]
    return None


def node_networks(interfaces: List[Dict[str, Any]], routes: List[Dict[str, Any]]) -> List[ipaddress.IPv4Network]:
    """Networks to auto-scan: the default-route interface's network first,
    then other physical interfaces. Virtual/CNI interfaces are skipped."""
    uplink = default_interface(routes)
    ordered = sorted(interfaces, key=lambda i: i["name"] != uplink)
    networks: List[ipaddress.IPv4Network] = []
    for iface in ordered:
        if iface["name"] != uplink and is_virtual_interface(iface["name"]):
            continue
        try:
            network = ipaddress.ip_network(iface["network"], strict=False)
        except ValueError:
            continue
        if is_scannable(network) and network not in networks:
            networks.append(network)
    return networks


def is_scannable(network: ipaddress.IPv4Network) -> bool:
    """Whether an interface network is worth scanning on its own"""
    # Loopback: every 127.x address answers, which is just noise.
    # Link-local, and /31-/32 point-to-point (typical of Kubernetes pods): no neighbours to find.
    return not (network.is_loopback or network.is_link_local or network.prefixlen >= 31)


async def find_fallback_networks(request: ScanRequest) -> List[ipaddress.IPv4Network]:
    """Probe common gateways and return the /24 of each one that answers"""
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_CONNECTIONS)
    results = await asyncio.gather(
        *(check_host(gw, ScanRequest(), semaphore, resolve=False) for gw in FALLBACK_GATEWAYS)
    )
    networks = []
    for gw, result in zip(FALLBACK_GATEWAYS, results):
        if result["is_up"]:
            logger.info("Fallback gateway %s answered", gw)
            networks.append(ipaddress.ip_network(f"{gw}/{FALLBACK_PREFIX}", strict=False))
    return networks


async def scan_network(network: ipaddress.IPv4Network, request: ScanRequest) -> List[dict]:
    """Scan a network for active hosts"""
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_CONNECTIONS)

    # Limit to the first MAX_HOSTS hosts without materialising huge networks
    host_ips = itertools.islice(network.hosts(), MAX_HOSTS)

    tasks = [check_host(str(ip), request, semaphore) for ip in host_ips]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    return [r for r in results if isinstance(r, dict) and r.get("is_up")]


async def probe_port(ip: str, port: int, timeout: float, semaphore: asyncio.Semaphore) -> Optional[str]:
    """Try a TCP connection. Returns "open", "closed" (host answered with a
    reset, so it is up) or None (no answer)."""
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        except ConnectionRefusedError:
            return "closed"
        except (OSError, asyncio.TimeoutError):
            return None
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return "open"


async def resolve_hostname(ip: str) -> Optional[str]:
    """Reverse DNS lookup without blocking the event loop"""
    try:
        return (await asyncio.wait_for(
            asyncio.to_thread(socket.gethostbyaddr, ip),
            timeout=HOSTNAME_TIMEOUT
        ))[0]
    except (OSError, asyncio.TimeoutError):
        return None


async def check_host(ip: str, request: ScanRequest, semaphore: Optional[asyncio.Semaphore] = None,
                     resolve: bool = True) -> dict:
    """Check if a host is up"""
    semaphore = semaphore or asyncio.Semaphore(MAX_CONCURRENT_CONNECTIONS)
    start_time = time.monotonic()
    response_time: Optional[float] = None
    statuses: Dict[int, Optional[str]] = {}

    async def probe(port: int) -> None:
        nonlocal response_time
        status = await probe_port(ip, port, 0.5, semaphore)
        statuses[port] = status
        if status and response_time is None:
            response_time = (time.monotonic() - start_time) * 1000

    # Probe common ports concurrently
    await asyncio.gather(*(probe(p) for p in COMMON_PORTS))

    is_up = response_time is not None
    open_ports = [p for p in COMMON_PORTS if statuses.get(p) == "open"]

    result = {
        "ip": ip,
        "is_up": is_up,
        "hostname": None,
        "response_time_ms": round(response_time, 2) if is_up else None,
        "mac_address": None,
        "open_ports": open_ports if request.scan_ports else []
    }

    if not is_up or not resolve:
        return result

    result["hostname"] = await resolve_hostname(ip)

    # Port scanning if requested
    if request.scan_ports and request.port_list:
        port_results = await asyncio.gather(
            *(check_port(ip, port, semaphore) for port in request.port_list)
        )
        result["open_ports"] = [p for p in port_results if p is not None]

    return result


async def check_port(ip: str, port: int, semaphore: Optional[asyncio.Semaphore] = None) -> Optional[int]:
    """Check if a specific port is open"""
    semaphore = semaphore or asyncio.Semaphore(1)
    return port if await probe_port(ip, port, 1.0, semaphore) == "open" else None


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.environ.get("HOST", "0.0.0.0"), port=int(os.environ.get("PORT", "8080")))
