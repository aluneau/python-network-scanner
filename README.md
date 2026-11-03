# Python Network Scanner

A FastAPI-based network scanner that discovers the gateway, network configuration, and scans for active hosts.

## Features

- **REST API** with FastAPI
- **Network Discovery**: Automatically finds gateway, interfaces, and routes
- **Host Scanning**: Scans networks for active hosts using TCP connections
- **Port Scanning**: Optional port scanning on discovered hosts
- **Async**: Fully asynchronous for better performance

## API Endpoints

- `GET /` - API info
- `GET /health` - Health check
- `GET /api/v1/network/info` - Get network configuration
- `POST /api/v1/scan` - Start a network scan
- `GET /api/v1/scan/{scan_id}` - Get scan status
- `GET /api/v1/scan/{scan_id}/results` - Get scan results
- `GET /api/v1/scans` - List all scans

## Running Locally

```bash
pip install -r requirements.txt
python main.py
```

Or with uvicorn directly:
```bash
uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```

## Usage Examples

```bash
# Get network info
curl http://localhost:8080/api/v1/network/info

# Start a scan
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"network": "192.168.1.0/24", "scan_ports": true}'

# Check scan status
curl http://localhost:8080/api/v1/scan/{scan_id}

# Get scan results
curl http://localhost:8080/api/v1/scan/{scan_id}/results
```
