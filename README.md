# Python Network Scanner

A FastAPI-based network scanner that discovers the gateway, network configuration, and scans for active hosts.

## Features

- **REST API** with FastAPI
- **Network Discovery**: Automatically finds gateway, interfaces, and routes
- **Host Scanning**: Scans networks for active hosts using TCP connections
- **Port Scanning**: Optional port scanning on discovered hosts
- **Async**: Fully asynchronous for better performance

- **Common networks**: when no `network` is given, scans the detected node network plus
  192.168.0.0/24, 192.168.1.0/24, 192.168.88.0/24 and 10.0.0.0/24
  (override with `COMMON_NETWORKS="a/24,b/24"`, disable per scan with `"include_common_networks": false`)
- **Main ports**: every host is checked on ~40 service ports (ssh, http/https, ftp, smb, rdp,
  databases, Kubernetes, ...) and open ones are reported with their service name
  (`GET /api/v1/ports` lists them; add more per scan with `port_list`)

## API Endpoints

- `GET /` - API info
- `GET /health` - Health check
- `GET /api/v1/network/info` - Get network configuration (includes `public_ip`)
- `GET /api/v1/network/public-ip` - Get the public IP via https://ifconfig.me (override with `PUBLIC_IP_URL`)
- `POST /api/v1/scan` - Start a network scan
- `GET /api/v1/scan/{scan_id}` - Get scan status
- `GET /api/v1/scan/{scan_id}/results` - Get scan results
- `GET /api/v1/scans` - List all scans
- `GET /api/v1/ports` - List the main ports probed on every host

## Running Locally

```bash
pip install -r requirements.txt
python main.py
```

Or with uvicorn directly:
```bash
uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```

## Running Tests

```bash
pip install -r requirements-dev.txt
pytest
```

## Kubernetes (node level)

`k8s/daemonset.yaml` runs one scanner per node with `hostNetwork: true`, so each
scanner sees its node's real interfaces, default route and LAN instead of the pod
network. Auto-scan picks the network of the default-route interface and skips
CNI/virtual interfaces (`cni0`, `flannel.1`, `cali*`, `veth*`, `docker0`, `kube-ipvs0`, ...).
It runs as non-root with all capabilities dropped (plain TCP connects only).

```bash
docker build -t <registry>/network-scanner:latest .
docker push <registry>/network-scanner:latest
# set the image in k8s/daemonset.yaml, then:
kubectl apply -f k8s/daemonset.yaml
curl http://<node-ip>:8080/api/v1/network/info
```

## Usage Examples

```bash
# Get network info
curl http://localhost:8080/api/v1/network/info

# Scan the node network + common networks on all main ports
curl -X POST http://localhost:8080/api/v1/scan -H "Content-Type: application/json" -d '{}'

# Scan one network, with extra ports
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"network": "192.168.1.0/24", "port_list": [8123, 32400]}'

# Check scan status
curl http://localhost:8080/api/v1/scan/{scan_id}

# Get scan results
curl http://localhost:8080/api/v1/scan/{scan_id}/results
```
