from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import subprocess
import ipaddress
import asyncio
import socket
from datetime import datetime
from uuid import uuid4
import json

app = FastAPI(title="Network Scanner API", version="1.0.0")

# In-memory storage for scans
scans: Dict[str, dict] = {}

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
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }

@app.get("/api/v1/network/info")
def get_network_info():
    """Get network configuration including gateway, interfaces, and routes"""
    try:
        gateway = find_gateway()
        interfaces = list_interfaces()
        routes = list_routes()
        
        return {
            "gateway": gateway,
            "interfaces": interfaces,
            "routes": routes
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/scan", response_model=ScanResponse)
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new network scan"""
    scan_id = str(uuid4())
    
    scans[scan_id] = {
        "scan_id": scan_id,
        "status": "running",
        "created_at": datetime.utcnow().isoformat(),
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

@app.get("/api/v1/scans")
def list_scans():
    """List all scans"""
    return list(scans.values())

def find_gateway() -> Optional[str]:
    """Find default gateway using ip route"""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True
        )
        
        for line in result.stdout.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "default" and parts[1] == "via":
                return parts[2]
    except Exception:
        pass
    return None

def list_interfaces() -> List[Dict[str, Any]]:
    """List network interfaces"""
    interfaces = []
    try:
        result = subprocess.run(
            ["ip", "-o", "-f", "inet", "addr", "show"],
            capture_output=True,
            text=True
        )
        
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 4:
                name = parts[1].rstrip(':')
                cidr = parts[3]
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    interfaces.append({
                        "name": name,
                        "ip": str(network.network_address),
                        "netmask": str(network.netmask),
                        "network": cidr
                    })
                except:
                    pass
    except Exception:
        pass
    return interfaces

def list_routes() -> List[Dict[str, Any]]:
    """List routing table"""
    routes = []
    try:
        result = subprocess.run(
            ["ip", "route", "show"],
            capture_output=True,
            text=True
        )
        
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue
            parts = line.split()
            if parts:
                destination = parts[0]
                gateway = None
                interface = ""
                
                for i, part in enumerate(parts):
                    if part == "via" and i + 1 < len(parts):
                        gateway = parts[i + 1]
                    elif part == "dev" and i + 1 < len(parts):
                        interface = parts[i + 1]
                
                routes.append({
                    "destination": destination,
                    "gateway": gateway,
                    "interface": interface
                })
    except Exception:
        pass
    return routes

async def run_scan(scan_id: str, request: ScanRequest):
    """Run network scan in background"""
    try:
        # Get network info
        gateway = find_gateway()
        interfaces = list_interfaces()
        
        scans[scan_id]["network_info"] = {
            "gateway": gateway,
            "interfaces": interfaces,
            "routes": list_routes()
        }
        
        # Determine network to scan
        networks_to_scan = []
        if request.network:
            try:
                networks_to_scan.append(ipaddress.ip_network(request.network, strict=False))
            except:
                scans[scan_id]["status"] = "failed"
                scans[scan_id]["error"] = f"Invalid network: {request.network}"
                return
        else:
            for iface in interfaces:
                try:
                    networks_to_scan.append(ipaddress.ip_network(iface["network"], strict=False))
                except:
                    pass
        
        # Scan networks
        all_hosts = []
        for network in networks_to_scan:
            hosts = await scan_network(network, request)
            all_hosts.extend(hosts)
        
        scans[scan_id]["hosts"] = all_hosts
        scans[scan_id]["status"] = "completed"
        scans[scan_id]["completed_at"] = datetime.utcnow().isoformat()
        
    except Exception as e:
        scans[scan_id]["status"] = "failed"
        scans[scan_id]["error"] = str(e)

async def scan_network(network: ipaddress.IPv4Network, request: ScanRequest) -> List[dict]:
    """Scan a network for active hosts"""
    hosts = []
    tasks = []
    
    # Limit to first 254 hosts
    host_ips = list(network.hosts())[:254]
    
    for ip in host_ips:
        tasks.append(check_host(str(ip), request))
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for result in results:
        if isinstance(result, dict) and result.get("is_up"):
            hosts.append(result)
    
    return hosts

async def check_host(ip: str, request: ScanRequest) -> dict:
    """Check if a host is up"""
    import time
    start_time = time.time()
    
    is_up = False
    open_ports = []
    
    # Try common ports
    common_ports = [80, 443, 22, 8080, 3000, 8000, 9000]
    
    for port in common_ports:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=0.5
            )
            writer.close()
            await writer.wait_closed()
            is_up = True
            open_ports.append(port)
        except:
            pass
    
    response_time = (time.time() - start_time) * 1000 if is_up else None
    
    # Resolve hostname
    hostname = None
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except:
        pass
    
    result = {
        "ip": ip,
        "is_up": is_up,
        "hostname": hostname,
        "response_time_ms": round(response_time, 2) if response_time else None,
        "mac_address": None,
        "open_ports": open_ports if request.scan_ports else []
    }
    
    # Port scanning if requested
    if request.scan_ports and request.port_list and is_up:
        port_tasks = []
        for port in request.port_list:
            port_tasks.append(check_port(ip, port))
        
        port_results = await asyncio.gather(*port_tasks, return_exceptions=True)
        result["open_ports"] = [p for p in port_results if isinstance(p, int)]
    
    return result

async def check_port(ip: str, port: int) -> Optional[int]:
    """Check if a specific port is open"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=1.0
        )
        writer.close()
        await writer.wait_closed()
        return port
    except:
        return None

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
