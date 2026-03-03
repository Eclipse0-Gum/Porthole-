import sys
import ipaddress
import subprocess
import platform
import time
import socket


def ping_host(ip):
    system = platform.system().lower()

    if system == "windows":
        command = ["ping", "-n", "1", "-w", "1000", str(ip)]
    else:
        command = ["ping", "-c", "1", "-W", "1", str(ip)]

    try:
        start_time = time.time()
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        end_time = time.time()

        response_time = round((end_time - start_time) * 1000)

        if result.returncode == 0:
            return ("UP", response_time, None)
        else:
            return ("DOWN", None, "No response")

    except Exception as e:
        return ("ERROR", None, str(e))


def parse_ports(port_string):
    ports = set()
    parts = port_string.split(",")

    for part in parts:
        if "-" in part:
            start, end = part.split("-")
            for p in range(int(start), int(end) + 1):
                ports.add(p)
        else:
            ports.add(int(part))

    return sorted(ports)


def scan_port(ip, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((str(ip), port))
            return result == 0
    except Exception:
        return False

def main():
    if len(sys.argv) < 2:
        print("In Use: python ip_freely.py [-p ports] <CIDR>")
        sys.exit(1)

    ports_to_scan = None
    
    if ports_to_scan:
        for port in ports_to_scan:
            if scan_port(host, port):
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "Unknown"

            print(f"  - Port {port} (OPEN - {service.upper()})")


    if "-p" in sys.argv:
        try:
            p_index = sys.argv.index("-p")
            port_input = sys.argv[p_index + 1]
            ports_to_scan = parse_ports(port_input)
            cidr_input = sys.argv[p_index + 2]
        except (IndexError, ValueError):
            print("Invalid port specification.")
            sys.exit(1)
    else:
        cidr_input = sys.argv[1]

    try:
        network = ipaddress.ip_network(cidr_input, strict=False)
    except ValueError as e:
        print(f"Invalid CIDR notation: {e}")
        sys.exit(1)

    print(f"\nScanning network {network}...\n")

    up_count = 0
    down_count = 0
    error_count = 0

    for host in network.hosts():
        status, response_time, error = ping_host(host)

        if status == "UP":
            up_count += 1
            print(f"{host} (UP)")

            if ports_to_scan:
                for port in ports_to_scan:
                    if scan_port(host, port):
                        print(f"  - Port {port} (OPEN)")

        elif status == "DOWN":
            down_count += 1
            print(f"{host} (DOWN)")
        else:
            error_count += 1
            print(f"{host} (ERROR: {error})")

    print("\nScan complete.")
    print(f"Found {up_count} active hosts, {down_count} down, {error_count} errors.")


if __name__ == "__main__":
    main()
