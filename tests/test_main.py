import asyncio
import ipaddress
import socket
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import main

client = TestClient(main.app)


@pytest.fixture(autouse=True)
def no_public_ip_calls(request):
    """Keep tests offline: stub the public IP lookup unless a test needs the real function"""
    if "real_public_ip" in request.keywords:
        yield
        return
    with patch("main.get_public_ip", return_value="203.0.113.7"):
        yield


@pytest.fixture(autouse=True)
def clear_scans():
    main.scans.clear()
    yield
    main.scans.clear()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_root_and_health():
    assert client.get("/").json()["status"] == "running"
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "healthy"


PROC_ROUTE = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
    "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
    "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
)


def test_routes_from_proc(tmp_path):
    route_file = tmp_path / "route"
    route_file.write_text(PROC_ROUTE)
    with patch.object(main, "PROC_NET_ROUTE", str(route_file)):
        assert main.list_routes() == [
            {"destination": "default", "gateway": "192.168.1.1", "interface": "eth0"},
            {"destination": "192.168.1.0/24", "gateway": None, "interface": "eth0"},
        ]
        assert main.find_gateway() == "192.168.1.1"


def test_interfaces_via_ioctl_include_loopback():
    interfaces = main.list_interfaces_ioctl()
    assert {"name": "lo", "ip": "127.0.0.1", "netmask": "255.0.0.0",
            "network": "127.0.0.0/8"} in interfaces


def test_network_info_endpoint():
    data = client.get("/api/v1/network/info").json()
    assert any(i["name"] == "lo" for i in data["interfaces"])
    assert data["routes"] == main.read_proc_routes()


def test_invalid_network_rejected():
    r = client.post("/api/v1/scan", json={"network": "not-a-network"})
    assert r.status_code == 400
    assert main.scans == {}


def test_invalid_port_rejected():
    r = client.post("/api/v1/scan", json={"network": "127.0.0.1/32", "port_list": [0]})
    assert r.status_code == 400


def test_unknown_scan_404():
    assert client.get("/api/v1/scan/nope").status_code == 404
    assert client.get("/api/v1/scan/nope/results").status_code == 404


def test_no_shell_commands_used():
    import inspect
    src = inspect.getsource(main)
    assert "subprocess" not in src and "os.system" not in src and "os.popen" not in src


def test_scan_lifecycle_with_port_scan():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    open_port = listener.getsockname()[1]
    closed_port = free_port()
    try:
        r = client.post("/api/v1/scan", json={
            "network": "127.0.0.1/32", "scan_ports": True,
            "port_list": [open_port, closed_port],
        })
        assert r.status_code == 200
        scan_id = r.json()["scan_id"]
        # TestClient runs background tasks before returning
        status = client.get(f"/api/v1/scan/{scan_id}").json()
        assert status["status"] == "completed", status
        hosts = client.get(f"/api/v1/scan/{scan_id}/results").json()
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "127.0.0.1"
        assert hosts[0]["is_up"] is True
        assert hosts[0]["open_ports"] == [open_port]
        assert client.get("/api/v1/scans").json()[0]["scan_id"] == scan_id
    finally:
        listener.close()


def test_host_with_only_closed_ports_is_up():
    # 127.0.0.1 refuses connections on closed ports (RST) -> host is alive
    with patch.object(main, "COMMON_PORTS", [free_port()]):
        result = asyncio.run(main.check_host("127.0.0.1", main.ScanRequest()))
    assert result["is_up"] is True


def test_unreachable_host_is_down():
    # TEST-NET-1 (RFC 5737) is never routed
    with patch.object(main, "COMMON_PORTS", [80]):
        result = asyncio.run(main.check_host("192.0.2.1", main.ScanRequest()))
    assert result["is_up"] is False
    assert result["hostname"] is None


def test_large_network_is_capped():
    seen = []

    async def fake_check(ip, request, semaphore=None):
        seen.append(ip)
        return {"ip": ip, "is_up": False}

    with patch("main.check_host", fake_check):
        asyncio.run(main.scan_network(ipaddress.ip_network("10.0.0.0/8"), main.ScanRequest()))
    assert len(seen) == main.MAX_HOSTS


def test_auto_scan_skips_loopback():
    scanned = []

    async def fake_scan(network, request):
        scanned.append(str(network))
        return []

    fake_ifaces = [
        {"name": "lo", "ip": "127.0.0.1", "netmask": "255.0.0.0", "network": "127.0.0.0/8"},
        {"name": "eth0", "ip": "192.168.1.42", "netmask": "255.255.255.0", "network": "192.168.1.0/24"},
    ]
    with patch("main.list_interfaces", return_value=fake_ifaces), \
            patch("main.list_routes", return_value=[]), \
            patch("main.scan_network", fake_scan):
        client.post("/api/v1/scan", json={})
    assert scanned == ["192.168.1.0/24"]


def run_auto_scan(interfaces, up_gateways, routes=()):
    scanned = []

    async def fake_scan(network, request):
        scanned.append(str(network))
        return []

    async def fake_check(ip, request, semaphore=None, resolve=True):
        return {"ip": ip, "is_up": ip in up_gateways}

    with patch("main.list_interfaces", return_value=interfaces), \
            patch("main.list_routes", return_value=routes), \
            patch("main.scan_network", fake_scan), patch("main.check_host", fake_check):
        scan_id = client.post("/api/v1/scan", json={}).json()["scan_id"]
    return scanned, main.scans[scan_id]


POD_IFACES = [
    {"name": "lo", "ip": "127.0.0.1", "netmask": "255.0.0.0", "network": "127.0.0.0/8"},
    {"name": "eth0", "ip": "10.42.0.17", "netmask": "255.255.255.255", "network": "10.42.0.17/32"},
]


def test_fallback_gateways_used_when_no_usable_network():
    scanned, scan = run_auto_scan(POD_IFACES, {"192.168.1.1", "10.0.0.1"})
    assert scanned == ["192.168.1.0/24", "10.0.0.0/24"]
    assert scan["status"] == "completed"
    assert scan["network_info"]["fallback_networks"] == scanned


def test_fallback_with_no_interfaces_and_nothing_answering():
    scanned, scan = run_auto_scan([], set())
    assert scanned == []
    assert scan["status"] == "completed"
    assert scan["network_info"]["fallback_networks"] == []


def test_no_fallback_when_real_network_found():
    ifaces = POD_IFACES + [{"name": "ens18", "ip": "10.244.1.5", "netmask": "255.255.255.0",
                            "network": "10.244.1.0/24"}]
    scanned, scan = run_auto_scan(ifaces, {"192.168.1.1"})
    assert scanned == ["10.244.1.0/24"]
    assert "fallback_networks" not in scan["network_info"]


def iface(name, cidr):
    return main.make_interface(name, cidr)


# What a hostNetwork pod sees on a typical k3s/flannel node
NODE_IFACES = [
    iface("lo", "127.0.0.1/8"),
    iface("ens18", "192.168.88.20/24"),
    iface("cni0", "10.42.0.1/24"),
    iface("flannel.1", "10.42.0.0/32"),
    iface("docker0", "172.17.0.1/16"),
    iface("kube-ipvs0", "10.43.0.10/32"),
]
NODE_ROUTES = [
    {"destination": "default", "gateway": "192.168.88.1", "interface": "ens18"},
    {"destination": "10.42.0.0/24", "gateway": None, "interface": "cni0"},
    {"destination": "192.168.88.0/24", "gateway": None, "interface": "ens18"},
]


def test_node_level_scans_uplink_not_cni():
    scanned, scan = run_auto_scan(NODE_IFACES, set(), NODE_ROUTES)
    assert scanned == ["192.168.88.0/24"]
    assert scan["network_info"]["default_interface"] == "ens18"
    assert "fallback_networks" not in scan["network_info"]


def test_uplink_first_then_other_physical_interfaces():
    ifaces = [iface("eth1", "10.10.0.5/24")] + NODE_IFACES
    assert [str(n) for n in main.node_networks(ifaces, NODE_ROUTES)] == ["192.168.88.0/24", "10.10.0.0/24"]


def test_virtual_uplink_is_still_used():
    # e.g. a node whose default route goes through a bridge such as br-lan
    ifaces = [iface("br-lan", "192.168.1.10/24"), iface("veth1", "10.0.5.1/24")]
    routes = [{"destination": "default", "gateway": "192.168.1.1", "interface": "br-lan"}]
    assert [str(n) for n in main.node_networks(ifaces, routes)] == ["192.168.1.0/24"]


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def read(self, n=-1):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.mark.real_public_ip
def test_get_public_ip_parses_response():
    with patch("main.urllib.request.urlopen", return_value=FakeResponse(b"198.51.100.23\n")) as m:
        assert main.get_public_ip() == "198.51.100.23"
    assert m.call_args.args[0].full_url == "https://ifconfig.me/ip"


@pytest.mark.real_public_ip
def test_get_public_ip_rejects_garbage():
    with patch("main.urllib.request.urlopen", return_value=FakeResponse(b"<html>oops</html>")):
        assert main.get_public_ip() is None


@pytest.mark.real_public_ip
def test_get_public_ip_offline():
    with patch("main.urllib.request.urlopen", side_effect=OSError("network unreachable")):
        assert main.get_public_ip() is None


def test_public_ip_endpoint():
    r = client.get("/api/v1/network/public-ip")
    assert r.status_code == 200
    assert r.json() == {"public_ip": "203.0.113.7", "source": "https://ifconfig.me/ip"}
    assert client.get("/api/v1/network/info").json()["public_ip"] == "203.0.113.7"


def test_public_ip_endpoint_unavailable():
    with patch("main.get_public_ip", return_value=None):
        assert client.get("/api/v1/network/public-ip").status_code == 502
        assert client.get("/api/v1/network/info").json()["public_ip"] is None


def test_scan_records_public_ip():
    scanned, scan = run_auto_scan(NODE_IFACES, set(), NODE_ROUTES)
    assert scan["network_info"]["public_ip"] == "203.0.113.7"
