import os
import subprocess
import shutil
import time
import sys
import serial
import csv
import shlex
import glob
import datetime

def save_benchmark_result(name, duration_ms):
    filename = "pqc_benchmark_results.csv"
    file_exists = os.path.isfile(filename)
    
    with open(filename, 'a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Benchmark_Name", "Duration_MS", "Timestamp"])
        writer.writerow([name, duration_ms, time.strftime("%Y-%m-%d %H:%M:%S")])
    print(f"[DATA] Result saved to {filename}")

# ====================================================================
# CONFIGURATION
# ====================================================================
NRF_PROJECT_DIR = "/Users/vbalves/nordic/peripheral"
SRC_DIR = os.path.join(NRF_PROJECT_DIR, "src")
BUILD_DIR = os.path.join(NRF_PROJECT_DIR, "build")
NRF5340_SERIAL = "/dev/tty.usbmodem0010500327223"
NRF52840_SERIAL = "/dev/tty.usbmodem0010502058091"
default_board = ("nrf5340dk/nrf5340/cpuapp" if os.path.exists(NRF5340_SERIAL)
                 else "nrf52840dk/nrf52840")
default_serial = NRF5340_SERIAL if os.path.exists(NRF5340_SERIAL) else NRF52840_SERIAL
BOARD = os.environ.get("BOARD", default_board)
SERIAL_PORT = os.environ.get("SERIAL_PORT", default_serial)
DEVICE_CN = os.environ.get("DEVICE_CN", BOARD.replace("/", "_"))
BLE_PROXY = "/Users/vbalves/Library/Developer/Xcode/DerivedData/BLE_MQTT_Proxy-cngfofzxuvkznrbiaybihnftqwuz/Build/Products/Debug/BLE_MQTT_Proxy"
HANDSHAKE_TIMEOUT = int(os.environ.get("HANDSHAKE_TIMEOUT", "300"))
SERVER_BACKEND = os.environ.get("SERVER_BACKEND", "raspberry_pi")
MQTT_CMD_TOPIC = os.environ.get("MQTT_CMD_TOPIC", "nrf52840/cmd")

# Raspberry Pi server config
PI_USER = os.environ.get("PI_USER", "vini")
PI_HOST = os.environ.get("PI_HOST", "10.12.194.1")
PI_PASSWORD = os.environ.get("PI_PASSWORD", "rasppi")
PI_WORKDIR = os.environ.get("PI_WORKDIR", f"/home/{PI_USER}/pqc_ble_mqtt")
PI_MOSQUITTO = os.environ.get("PI_MOSQUITTO", "/usr/sbin/mosquitto")
PI_MOSQUITTO_PUB = os.environ.get("PI_MOSQUITTO_PUB", "/usr/bin/mosquitto_pub")
PI_OFFLINE_DEBS_DIR = os.environ.get(
    "PI_OFFLINE_DEBS_DIR",
    os.path.join(NRF_PROJECT_DIR, "raspberry_pi", "offline_debs"),
)
PI_ADAPTER = os.environ.get("PI_ADAPTER", "hci0")
BLE_DEVICE_NAME = os.environ.get("BLE_DEVICE_NAME", "PQC52840")
BLE_DEVICE_ADDR = os.environ.get("BLE_DEVICE_ADDR", "")
BLE_DEVICE_ADDR_TYPE = os.environ.get("BLE_DEVICE_ADDR_TYPE", "random")
L2CAP_PSM = os.environ.get("L2CAP_PSM", "0x0080")
BRIDGE_MTU = int(os.environ.get("BRIDGE_MTU", "672"))
PI_GATEWAY_IMPL = os.environ.get("PI_GATEWAY_IMPL", "legacy_c")
PI_DISABLE_WIFI_DURING_BLE = os.environ.get("PI_DISABLE_WIFI_DURING_BLE", "1") not in ("0", "false", "False", "no", "NO")
PUBLISH_DISCONNECT_AFTER_HANDSHAKE = os.environ.get("PUBLISH_DISCONNECT_AFTER_HANDSHAKE", "0") in ("1", "true", "True", "yes", "YES")

# Docker config
DOCKER_IMAGE = "pqc-openssl:3.5"
DOCKERFILE_DIR = os.path.join(NRF_PROJECT_DIR, "docker", "pqc-openssl")
CERT_CONTAINER_NAME = "pqc_auto_gen"
BROKER_CONTAINER_NAME = "mosquitto_pqc"

# Lock the output dir strictly to your peripheral folder
OUTPUT_DIR = os.path.join(NRF_PROJECT_DIR, "generated_certs")

KEMS = [
    {"name": "MLKEM512", "macro": "WOLFSSL_ML_KEM_512", "group": "MLKEM512"},
    {"name": "MLKEM768", "macro": "WOLFSSL_ML_KEM_768", "group": "MLKEM768"},
    {"name": "MLKEM1024", "macro": "WOLFSSL_ML_KEM_1024", "group": "MLKEM1024"},
]

SIGS = [
    # Classical Baseline Signatures
    {"name": "ECDSA-P-256", "key_gen": "ec:prime256v1", "ssl_group": "P-256"},
    # Post-Quantum Signatures
    {"name": "ML-DSA-44", "key_gen": "ML-DSA-44"},
    {"name": "ML-DSA-65", "key_gen": "ML-DSA-65"},
    {"name": "ML-DSA-87", "key_gen": "ML-DSA-87"},
    # Post-Quantum Signatures (Hash-Based - FIPS 205)
    # TLS has no standardized SLH-DSA CertificateVerify scheme. SLH-DSA signs
    # ECDSA leaf certificates, so both peers verify FIPS-205 chain signatures.
    {"name": "SLH-DSA-SHAKE-128s", "key_gen": "SLH-DSA-SHAKE-128s",
     "leaf_key_gen": "ec:prime256v1"},
    {"name": "SLH-DSA-SHAKE-192s", "key_gen": "SLH-DSA-SHAKE-192s",
     "leaf_key_gen": "ec:prime256v1"},
    {"name": "SLH-DSA-SHAKE-256s", "key_gen": "SLH-DSA-SHAKE-256s",
     "leaf_key_gen": "ec:prime256v1"},
]

# Generate the full matrix
BENCHMARK_SUITE = []
for kem in KEMS:
    for sig in SIGS:
        BENCHMARK_SUITE.append({
            "name": f"{kem['name']}_{sig['name']}",
            "macro": kem['macro'],
            "openssl_group": kem['group'],
            "issuer_key_type": sig['key_gen'],
            "leaf_key_type": sig.get('leaf_key_gen', sig['key_gen']),
        })

requested_benchmarks = os.environ.get("PQC_BENCHMARKS")
if requested_benchmarks:
    requested = {name.strip() for name in requested_benchmarks.split(",")}
    BENCHMARK_SUITE = [entry for entry in BENCHMARK_SUITE
                       if entry["name"] in requested]

# ====================================================================

def run_cmd(cmd, cwd=None, ignore_errors=False):
    print(f"\n[RUNNING] {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd)
    if result.returncode != 0 and not ignore_errors:
        print(f"[ERROR] Command failed with return code {result.returncode}")
        exit(1)
    return result

def run_password_cmd(cmd, ignore_errors=False, popen=False):
    """Run ssh/scp through expect when a password is configured."""
    if not PI_PASSWORD:
        if popen:
            return subprocess.Popen(cmd)
        result = subprocess.run(cmd)
        if result.returncode != 0 and not ignore_errors:
            print(f"[ERROR] Command failed with return code {result.returncode}")
            exit(1)
        return result

    def tcl_word(value):
        return "{" + value.replace("\\", "\\\\").replace("{", "\\{").replace("}", "\\}") + "}"

    tcl_cmd = " ".join(tcl_word(part) for part in cmd)
    expect_script = "set cmd [list " + tcl_cmd + r''']
set timeout -1
log_user 1
spawn {*}$cmd
expect {
    -re "(?i)are you sure.*yes/no.*" {
        send "yes\r"
        exp_continue
    }
    -re "(?i)password:" {
        send "$env(PI_PASSWORD)\r"
        exp_continue
    }
    eof
}
catch wait result
exit [lindex $result 3]
'''
    env = os.environ.copy()
    env["PI_PASSWORD"] = PI_PASSWORD
    wrapped = ["expect", "-c", expect_script]

    if popen:
        return subprocess.Popen(wrapped, env=env)

    result = subprocess.run(wrapped, env=env)
    if result.returncode != 0 and not ignore_errors:
        print(f"[ERROR] Command failed with return code {result.returncode}")
        exit(1)
    return result

def pi_ssh_cmd(remote_cmd):
    return [
        "ssh",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=4",
        f"{PI_USER}@{PI_HOST}",
        remote_cmd,
    ]

def run_pi_cmd(remote_cmd, ignore_errors=False):
    print(f"\n[PI RUNNING] ssh {PI_USER}@{PI_HOST} {remote_cmd}")
    return run_password_cmd(pi_ssh_cmd(remote_cmd), ignore_errors=ignore_errors)

def popen_pi_cmd(remote_cmd):
    print(f"\n[PI LAUNCHING] ssh {PI_USER}@{PI_HOST} {remote_cmd}")
    return run_password_cmd(pi_ssh_cmd(remote_cmd), popen=True)

def scp_to_pi(local_path, remote_path):
    print(f"\n[PI COPYING] {local_path} -> {PI_USER}@{PI_HOST}:{remote_path}")
    cmd = [
        "scp",
        "-o", "StrictHostKeyChecking=accept-new",
        "-r",
        local_path,
        f"{PI_USER}@{PI_HOST}:{remote_path}",
    ]
    return run_password_cmd(cmd)

def build_offline_pi_debs():
    """Build an arm64 .deb bundle when the Pi has no internet route."""
    print("\n[PI OFFLINE] Building arm64 Debian package bundle locally...")
    if os.path.exists(PI_OFFLINE_DEBS_DIR):
        shutil.rmtree(PI_OFFLINE_DEBS_DIR)
    os.makedirs(PI_OFFLINE_DEBS_DIR, exist_ok=True)

    package_list = "libbluetooth-dev mosquitto mosquitto-clients"
    run_cmd([
        "docker", "run", "--rm", "--platform", "linux/arm64",
        "-v", f"{PI_OFFLINE_DEBS_DIR}:/debs",
        "debian:trixie-slim",
        "sh", "-lc",
        "echo 'deb [trusted=yes] http://archive.raspberrypi.com/debian trixie main' "
        "> /etc/apt/sources.list.d/raspberrypi.list && "
        "apt-get update && "
        f"apt-get install --download-only -y {package_list} && "
        "cp /var/cache/apt/archives/*.deb /debs/"
    ])

def ensure_docker_running():
    """Checks if Docker is running, and auto-starts it on macOS if it isn't."""
    print("\n--- STEP 0: CHECKING DOCKER STATUS ---")
    result = subprocess.run(["docker", "info"], capture_output=True)
    if result.returncode == 0:
        print("[OK] Docker is already running.")
        return

    print("[INFO] Docker is not running. Attempting to start Docker Desktop...")
    if sys.platform == "darwin":  # macOS
        subprocess.run(["open", "-a", "Docker"])
    elif sys.platform.startswith("win"):  # Windows
        subprocess.run(["start", "Docker Desktop"], shell=True)
    else:
        print("[ERROR] Cannot auto-start Docker on Linux. Please start manually.")
        exit(1)

    print("Waiting for Docker daemon to initialize (this may take up to 60 seconds)...")
    timeout = 60
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        result = subprocess.run(["docker", "info"], capture_output=True)
        if result.returncode == 0:
            print("\n[OK] Docker daemon is up and ready!")
            return
        print(".", end="", flush=True)
        time.sleep(2)

    print("\n[ERROR] Timed out waiting for Docker to start.")
    exit(1)

def ensure_pqc_image():
    """Build the OpenSSL 3.5 image once and verify native SLH-DSA support."""
    result = subprocess.run(["docker", "image", "inspect", DOCKER_IMAGE],
                            capture_output=True)
    if result.returncode != 0:
        run_cmd(["docker", "build", "-t", DOCKER_IMAGE, DOCKERFILE_DIR])

    checks = (
        "openssl version && "
        "openssl list -signature-algorithms | "
        "grep -q SLH-DSA-SHAKE-256s"
    )
    run_cmd(["docker", "run", "--rm", DOCKER_IMAGE, "sh", "-c", checks])

def format_der_to_c_header(der_filepath, header_filepath, var_name, include_guard):
    """Reads a binary DER file and writes it as a C unsigned char array."""
    print(f"[FORMATTING] {der_filepath} -> {header_filepath}")
    with open(der_filepath, 'rb') as f:
        data = f.read()

    with open(header_filepath, 'w') as f:
        f.write(f"#ifndef {include_guard}\n")
        f.write(f"#define {include_guard}\n\n")
        f.write(f"const unsigned char {var_name}[] = {{\n")
        
        # Format the raw bytes as hex (e.g., 0x30, 0x82)
        hex_array = [f"0x{b:02x}" for b in data]
        
        # Wrap the text nicely at 12 bytes per line
        for i in range(0, len(hex_array), 12):
            f.write("    " + ", ".join(hex_array[i:i+12]))
            if i + 12 < len(hex_array):
                f.write(",")
            f.write("\n")
            
        f.write("};\n\n")
        f.write(f"const unsigned int {var_name}_len = {len(data)};\n\n")
        f.write(f"#endif\n")

def generate_certificates(algo_entry):
    if os.path.exists(OUTPUT_DIR):
        for f in os.listdir(OUTPUT_DIR):
            if f.endswith(('.crt', '.key', '.csr', '.der')):
                os.remove(os.path.join(OUTPUT_DIR, f))

    def make_key_args(key_type):
        if not key_type.startswith("ec:"):
            return ["-newkey", key_type]
        curve_name = key_type.split(":", 1)[1]
        return ["-newkey", "ec", "-pkeyopt",
                f"ec_paramgen_curve:{curve_name}"]

    issuer_key_args = make_key_args(algo_entry['issuer_key_type'])
    leaf_key_args = make_key_args(algo_entry['leaf_key_type'])

    if algo_entry['issuer_key_type'] != algo_entry['leaf_key_type']:
        print("[INFO] SLH-DSA signs ECDSA TLS leaf certificates; "
              "TLS CertificateVerify remains ECDSA.")

    print(f"\n--- STEP 1: GENERATING {algo_entry['name'].upper()} CERTIFICATES ---")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    run_cmd(["docker", "rm", "-f", CERT_CONTAINER_NAME], ignore_errors=True)
    run_cmd(["docker", "run", "-d", "--name", CERT_CONTAINER_NAME, DOCKER_IMAGE, "tail", "-f", "/dev/null"])
    
    try:
        print(f"Generating {algo_entry['name']} Certificates...")
        
        # CA
        run_cmd(["docker", "exec", CERT_CONTAINER_NAME, "openssl", "req", "-x509", "-new"] + issuer_key_args + [
                 "-keyout", "/tmp/ca.key", "-out", "/tmp/ca.crt", "-nodes", "-subj", "/CN=PQC_Root", "-days", "365"])
        # Client (Generates der for the CA signing process)
        run_cmd(["docker", "exec", CERT_CONTAINER_NAME, "openssl", "req", "-new"] + leaf_key_args + [
                 "-keyout", "/tmp/client.key", "-out", "/tmp/client.csr", "-nodes", "-subj", f"/CN={DEVICE_CN}"])
        run_cmd(["docker", "exec", CERT_CONTAINER_NAME, "openssl", "x509", "-req", "-in", "/tmp/client.csr", 
                 "-CA", "/tmp/ca.crt", "-CAkey", "/tmp/ca.key", "-CAcreateserial", "-out", "/tmp/client.crt", "-days", "365"])
        
        # --- THE FIX: Convert Client ders to DER format using the OQS Provider ---
        run_cmd(["docker", "exec", CERT_CONTAINER_NAME, "openssl", "x509", "-in", "/tmp/client.crt", "-outform", "DER", "-out", "/tmp/client_cert.der"])
        run_cmd(["docker", "exec", CERT_CONTAINER_NAME, "openssl", "pkey", "-in", "/tmp/client.key", "-outform", "DER", "-out", "/tmp/client_key.der"])
        run_cmd(["docker", "exec", CERT_CONTAINER_NAME, "openssl", "x509", "-in", "/tmp/ca.crt", "-outform", "DER", "-out", "/tmp/ca_cert.der"])

        # Server
        run_cmd(["docker", "exec", CERT_CONTAINER_NAME, "openssl", "req", "-new"] + leaf_key_args + [
                 "-keyout", "/tmp/server.key", "-out", "/tmp/server.csr", "-nodes", "-subj", "/CN=localhost"])
        run_cmd(["docker", "exec", CERT_CONTAINER_NAME, "openssl", "x509", "-req", "-in", "/tmp/server.csr", 
                 "-CA", "/tmp/ca.crt", "-CAkey", "/tmp/ca.key", "-CAcreateserial", "-out", "/tmp/server.crt", "-days", "365"])

        print("\nExtracting files to local directory...")
        # Include the new .der files in the extraction loop
        for ext in ["ca.crt", "client.crt", "client.key", "server.crt", "server.key",
                    "ca_cert.der", "client_cert.der", "client_key.der"]:
            run_cmd(["docker", "cp", f"{CERT_CONTAINER_NAME}:/tmp/{ext}", os.path.join(OUTPUT_DIR, ext)])

    finally:
        run_cmd(["docker", "rm", "-f", CERT_CONTAINER_NAME], ignore_errors=True)

def update_nrf_source():
    # Read the new DER files
    cert_der_path = os.path.join(OUTPUT_DIR, "client_cert.der")
    key_der_path = os.path.join(OUTPUT_DIR, "client_key.der")
    ca_der_path = os.path.join(OUTPUT_DIR, "ca_cert.der")
    
    cert_h_path = os.path.join(SRC_DIR, "client_cert.h")
    key_h_path = os.path.join(SRC_DIR, "client_key.h")
    ca_h_path = os.path.join(SRC_DIR, "ca_cert.h")
    
    # Write the binary hex arrays to the headers
    format_der_to_c_header(cert_der_path, cert_h_path, "client_der", "CLIENT_CERT_H")
    format_der_to_c_header(key_der_path, key_h_path, "client_key_der", "CLIENT_KEY_H")
    format_der_to_c_header(ca_der_path, ca_h_path, "ca_der", "CA_CERT_H")
    print(f"[SUCCESS] Updated {cert_h_path} and {key_h_path}")

def generate_openssl_conf(openssl_group_string):
    """Dynamically writes an openssl.cnf file to force Mosquitto to allow specific math."""
    conf_path = os.path.join(OUTPUT_DIR, "openssl.cnf")
    print(f"[CONFIG] Generating custom openssl.cnf for group: {openssl_group_string}")
    
    conf_content = f"""openssl_conf = openssl_init

[openssl_init]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
MinProtocol = TLSv1.3
Groups = {openssl_group_string}
"""
    with open(conf_path, "w") as f:
        f.write(conf_content)

def write_mosquitto_conf(config_dir, output_path):
    conf_content = f"""listener 8883
allow_anonymous false
password_file {config_dir}/passwd
cafile {config_dir}/ca.crt
certfile {config_dir}/server.crt
keyfile {config_dir}/server.key
require_certificate true
use_identity_as_username true
"""
    with open(output_path, "w") as f:
        f.write(conf_content)

def generate_mosquitto_confs():
    write_mosquitto_conf("/mosquitto/config",
                         os.path.join(OUTPUT_DIR, "mosquitto.conf"))
    write_mosquitto_conf(f"{PI_WORKDIR}/certs",
                         os.path.join(OUTPUT_DIR, "mosquitto.pi.conf"))

def start_local_mosquitto_broker():
    print("\n--- STEP 3: STARTING PQC MOSQUITTO BROKER ---")
    run_cmd(["docker", "rm", "-f", BROKER_CONTAINER_NAME], ignore_errors=True)
    
    run_cmd([
        "docker", "run", "-d", "--name", BROKER_CONTAINER_NAME,
        "-p", "8883:8883",
        
        # THE BACKDOOR: Tell OpenSSL where to find our custom rules
        "-e", "OPENSSL_CONF=/mosquitto/config/openssl.cnf",
        
        # Map all the standard certs PLUS our new openssl.cnf
        "-v", f"{os.path.join(OUTPUT_DIR, 'mosquitto.conf')}:/mosquitto/config/mosquitto.conf",
        "-v", f"{os.path.join(OUTPUT_DIR, 'passwd')}:/mosquitto/config/passwd",
        "-v", f"{os.path.join(OUTPUT_DIR, 'ca.crt')}:/mosquitto/config/ca.crt",
        "-v", f"{os.path.join(OUTPUT_DIR, 'server.crt')}:/mosquitto/config/server.crt",
        "-v", f"{os.path.join(OUTPUT_DIR, 'server.key')}:/mosquitto/config/server.key",
        "-v", f"{os.path.join(OUTPUT_DIR, 'openssl.cnf')}:/mosquitto/config/openssl.cnf",
        
        DOCKER_IMAGE,
        "mosquitto", "-c", "/mosquitto/config/mosquitto.conf", "-v"
    ])

def ensure_raspberry_pi_ready():
    print("\n--- STEP 2B: PREPARING RASPBERRY PI SERVER ---")
    q_workdir = shlex.quote(PI_WORKDIR)
    run_pi_cmd(f"mkdir -p {q_workdir}/certs {q_workdir}/logs")
    scp_to_pi(os.path.join(NRF_PROJECT_DIR, "raspberry_pi", "ble_mqtt_bridge.c"),
              f"{PI_WORKDIR}/ble_mqtt_bridge.c")
    scp_to_pi(os.path.join(NRF_PROJECT_DIR, "raspberry_pi", "setup_raspberry_pi.sh"),
              f"{PI_WORKDIR}/setup_raspberry_pi.sh")
    scp_to_pi(os.path.join(NRF_PROJECT_DIR, "scripts", "ble_l2cap_gateway.py"),
              f"{PI_WORKDIR}/ble_l2cap_gateway.py")
    setup_cmd = f"chmod +x {q_workdir}/setup_raspberry_pi.sh && cd {q_workdir} && ./setup_raspberry_pi.sh"
    result = run_pi_cmd(setup_cmd, ignore_errors=True)
    if result.returncode != 0:
        print("[PI OFFLINE] Online apt setup failed; trying offline .deb bundle.")
        build_offline_pi_debs()
        run_pi_cmd(f"rm -rf {q_workdir}/offline_debs && mkdir -p {q_workdir}/offline_debs")
        for deb_path in glob.glob(os.path.join(PI_OFFLINE_DEBS_DIR, "*.deb")):
            scp_to_pi(deb_path, f"{PI_WORKDIR}/offline_debs/")
        run_pi_cmd(
            f"cd {q_workdir}/offline_debs && "
            f"sudo dpkg -i ./*.deb || sudo apt-get -f install -y",
            ignore_errors=True,
        )
        run_pi_cmd(setup_cmd)

    run_pi_cmd(
        "sudo date -u -s "
        f"{shlex.quote(datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%d %H:%M:%S'))} "
        ">/dev/null && date -u"
    )

    run_pi_cmd(
        "sudo sed -i -E "
        "'s/^#?MinConnectionInterval=.*/MinConnectionInterval=12/; "
        "s/^#?MaxConnectionInterval=.*/MaxConnectionInterval=12/; "
        "s/^#?ConnectionLatency=.*/ConnectionLatency=0/; "
        "s/^#?ConnectionSupervisionTimeout=.*/ConnectionSupervisionTimeout=400/' "
        "/etc/bluetooth/main.conf && "
        "sudo systemctl restart bluetooth && "
        f"chmod +x {q_workdir}/ble_l2cap_gateway.py"
    )

def deploy_raspberry_pi_assets():
    print("\n--- STEP 3: DEPLOYING CERTS AND CONFIG TO RASPBERRY PI ---")
    cert_files = [
        "ca.crt",
        "client.crt",
        "client.key",
        "server.crt",
        "server.key",
        "openssl.cnf",
        "passwd",
    ]
    for filename in cert_files:
        scp_to_pi(os.path.join(OUTPUT_DIR, filename), f"{PI_WORKDIR}/certs/{filename}")
    scp_to_pi(os.path.join(OUTPUT_DIR, "mosquitto.pi.conf"),
              f"{PI_WORKDIR}/certs/mosquitto.conf")
    run_pi_cmd(
        f"chmod 600 {shlex.quote(PI_WORKDIR)}/certs/*.key && "
        f"ls -l {shlex.quote(PI_WORKDIR)}/certs"
    )

def stop_raspberry_pi_services():
    q_workdir = shlex.quote(PI_WORKDIR)
    mosquitto_conf_pattern = f"[/]{PI_WORKDIR.lstrip('/')}/certs/mosquitto.conf"
    wifi_restore_cmd = (
        "sudo nmcli radio wifi on 2>/dev/null || "
        "sudo ip link set wlan0 up 2>/dev/null || true"
    ) if PI_DISABLE_WIFI_DURING_BLE else "true"
    run_pi_cmd(
        f"if [ -f {q_workdir}/mosquitto.pid ]; then "
        f"sudo kill $(cat {q_workdir}/mosquitto.pid) || true; "
        f"rm -f {q_workdir}/mosquitto.pid; fi; "
        f"pkill -f '{PI_WORKDIR}/ble_mqtt_bridg[e]' 2>/dev/null || true; "
        f"pkill -f '{PI_WORKDIR}/ble_l2cap_gatewa[y].py' 2>/dev/null || true; "
        f"pids=$(pgrep -f {shlex.quote(mosquitto_conf_pattern)} || true); "
        "if [ -n \"$pids\" ]; then sudo kill $pids || true; fi; "
        f"{wifi_restore_cmd}",
        ignore_errors=True,
    )

def start_raspberry_pi_mosquitto():
    print("\n--- STEP 3B: STARTING RASPBERRY PI MOSQUITTO ---")
    stop_raspberry_pi_services()
    q_workdir = shlex.quote(PI_WORKDIR)
    run_pi_cmd(
        f"cd {q_workdir} && "
        f"setsid -f env OPENSSL_CONF={q_workdir}/certs/openssl.cnf "
        f"{shlex.quote(PI_MOSQUITTO)} -c {q_workdir}/certs/mosquitto.conf -v "
        f"> {q_workdir}/logs/mosquitto.log 2>&1 < /dev/null; "
        f"sleep 1; "
        f"pgrep -n -f 'mosquitto -c {PI_WORKDIR}/certs/mosquitto.conf' > {q_workdir}/mosquitto.pid || true; "
        f"tail -30 {q_workdir}/logs/mosquitto.log"
    )

def start_legacy_raspberry_pi_bridge():
    bridge_args = [
        f"--adapter {shlex.quote(PI_ADAPTER)}",
        f"--name {shlex.quote(BLE_DEVICE_NAME)}",
        f"--psm {shlex.quote(L2CAP_PSM)}",
        "--tcp-host 127.0.0.1",
        "--tcp-port 8883",
        f"--mtu {BRIDGE_MTU}",
        "--scan-timeout 2",
        "--forget-cache",
        "--no-acl-prime",
    ]
    if PI_DISABLE_WIFI_DURING_BLE:
        bridge_args.append("--disable-wifi")
    if BLE_DEVICE_ADDR:
        bridge_args.append(f"--addr {shlex.quote(BLE_DEVICE_ADDR)}")
        bridge_args.append(f"--addr-type {shlex.quote(BLE_DEVICE_ADDR_TYPE)}")

    q_workdir = shlex.quote(PI_WORKDIR)
    remote_cmd = (
        f"cd {q_workdir} && "
        f"sudo {q_workdir}/ble_mqtt_bridge {' '.join(bridge_args)}"
    )
    return popen_pi_cmd(remote_cmd)

def start_raspberry_pi_bridge():
    if PI_GATEWAY_IMPL == "legacy_c":
        return start_legacy_raspberry_pi_bridge()
    if PI_GATEWAY_IMPL != "python":
        raise ValueError(
            f"Unsupported PI_GATEWAY_IMPL={PI_GATEWAY_IMPL!r}; use 'python' or 'legacy_c'"
        )

    bridge_args = [
        f"--name {shlex.quote(BLE_DEVICE_NAME)}",
        f"--addr-type {shlex.quote(BLE_DEVICE_ADDR_TYPE)}",
        f"--psm {shlex.quote(L2CAP_PSM)}",
        "--broker-host 127.0.0.1",
        "--broker-port 8883",
        f"--l2cap-mtu {BRIDGE_MTU}",
        f"--ble-write-chunk {BRIDGE_MTU}",
        "--scan-seconds 8",
        "--retries 60",
        "--connect-timeout 10",
    ]
    if BLE_DEVICE_ADDR:
        bridge_args.append(f"--addr {shlex.quote(BLE_DEVICE_ADDR)}")

    q_workdir = shlex.quote(PI_WORKDIR)
    remote_cmd = (
        f"cd {q_workdir} && "
        f"sudo python3 -u {q_workdir}/ble_l2cap_gateway.py {' '.join(bridge_args)}"
    )
    return popen_pi_cmd(remote_cmd)

def publish_disconnect():
    if SERVER_BACKEND == "raspberry_pi":
        q_workdir = shlex.quote(PI_WORKDIR)
        run_pi_cmd(
            f"OPENSSL_CONF={q_workdir}/certs/openssl.cnf "
            f"{shlex.quote(PI_MOSQUITTO_PUB)} -h localhost -p 8883 "
            f"--cafile {q_workdir}/certs/ca.crt "
            f"--cert {q_workdir}/certs/client.crt "
            f"--key {q_workdir}/certs/client.key "
            f"-t {shlex.quote(MQTT_CMD_TOPIC)} -m disconnect",
            ignore_errors=True,
        )
        return

    run_cmd([
        "docker", "exec", BROKER_CONTAINER_NAME, "mosquitto_pub",
        "-h", "localhost", "-p", "8883",
        "--cafile", "/mosquitto/config/ca.crt",
        "--cert", "/mosquitto/config/server.crt",
        "--key", "/mosquitto/config/server.key",
        "-t", MQTT_CMD_TOPIC, "-m", "disconnect"
    ], ignore_errors=True)

def drain_serial_output(ser, seconds, reason="serial output"):
    print(f"\n[LOG] Draining {reason} for {seconds}s...")
    deadline = time.time() + seconds
    original_timeout = ser.timeout
    ser.timeout = 0.2
    try:
        while time.time() < deadline:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if line:
                print(f"[{BOARD}] {line}")
                if "Session ended. Re-arming for next connection" in line:
                    break
    except serial.SerialException:
        print("[-] Board disconnected while draining serial output.")
    finally:
        ser.timeout = original_timeout

def build_and_flash(pqc_macro):
    print("\n--- STEP 4: WEST BUILD & FLASH ---")
    if os.path.exists(BUILD_DIR):
        print("[CLEANING] Removing old build directory...")
        shutil.rmtree(BUILD_DIR)
    
    # Absolute paths for the Nordic SDK
    nordic_python = "/opt/nordic/ncs/toolchains/0c0f19d91c/opt/python@3.12/bin/python3.12"
    zephyr_base = "/opt/nordic/ncs/v3.3.0/zephyr"
    
    # We must inject ZEPHYR_BASE so both west and CMake know where the OS is
    env = os.environ.copy()
    env["ZEPHYR_BASE"] = zephyr_base
    env.setdefault("ZEPHYR_TOOLCHAIN_VARIANT", "zephyr")
    env.setdefault("ZEPHYR_SDK_INSTALL_DIR",
                   "/opt/nordic/ncs/toolchains/0c0f19d91c/opt/zephyr-sdk")
    toolchain_root = "/opt/nordic/ncs/toolchains/0c0f19d91c"
    env["PATH"] = os.pathsep.join([
        os.path.join(toolchain_root, "nrfutil", "bin"),
        os.path.join(toolchain_root, "bin"),
        env.get("PATH", ""),
    ])
    
    # ================================================================
    # DYNAMIC INJECTION LOGIC
    # ================================================================
    # 1. Start with the baseline macro
    extra_cflags = f"-DTARGET_PQC_GROUP={pqc_macro}"
    
    if "521" in pqc_macro:
        print("[INFO] Target is Level 5 Security. Injecting -DHAVE_ECC521...")
        extra_cflags += " -DHAVE_ECC521"
    elif "384" in pqc_macro:
        print("[INFO] Target is Level 3 Security. Injecting -DHAVE_ECC384...")
        extra_cflags += " -DHAVE_ECC384"        
    if "ed25519" in pqc_macro.lower():
        print("[INFO] Target is Ed25519. Injecting -DHAVE_ED25519...")
        extra_cflags += " -DHAVE_ED25519 -DHAVE_CURVE25519"
    # ================================================================
    
    build_cmd = [
        nordic_python, "-m", "west", "-z", zephyr_base, "build",
        "-p", "always",
        "-b", BOARD,
        "--sysbuild",
        "--", 
        f"-DEXTRA_CFLAGS={extra_cflags}" # Pass the fully constructed flag string
    ]
    
    print(f"\n[RUNNING] {' '.join(build_cmd)}")
    result = subprocess.run(build_cmd, cwd=NRF_PROJECT_DIR, env=env)
    if result.returncode != 0:
        print(f"[ERROR] Build failed with return code {result.returncode}")
        exit(1)
    
    print(f"\n[FLASHING] Uploading to {BOARD}...")
    flash_cmd = [nordic_python, "-m", "west", "-z", zephyr_base, "flash"]
    print(f"\n[RUNNING] {' '.join(flash_cmd)}")
    result = subprocess.run(flash_cmd, cwd=NRF_PROJECT_DIR, env=env)
    if result.returncode != 0:
        print(f"[ERROR] Flash failed with return code {result.returncode}")
        exit(1)

if __name__ == "__main__":
    ensure_docker_running()
    ensure_pqc_image()

    # Interrupted benchmark runs otherwise leave a proxy holding the BLE link.
    if SERVER_BACKEND == "raspberry_pi":
        ensure_raspberry_pi_ready()
        stop_raspberry_pi_services()
    else:
        subprocess.run(["pkill", "-f", BLE_PROXY], capture_output=True)

    # Ensure BENCHMARK_SUITE is a list of dictionaries
    for algo in BENCHMARK_SUITE:
        # Check if 'algo' is actually a dict
        if not isinstance(algo, dict):
            print(f"[CRITICAL ERROR] Loop item is not a dictionary: {type(algo)} -> {algo}")
            continue

        print(f"\n========================================================")
        print(f"🚀 RUNNING BENCHMARK: {algo['name']}")
        print(f"========================================================")
        
        generate_certificates(algo) 
        update_nrf_source()
        generate_openssl_conf(algo['openssl_group'])
        generate_mosquitto_confs()
        if SERVER_BACKEND == "raspberry_pi":
            deploy_raspberry_pi_assets()
            start_raspberry_pi_mosquitto()
        else:
            start_local_mosquitto_broker()
        build_and_flash(algo['macro'])
        
        # 1. THE USB BOUNCE DELAY
        # Give the board 5 seconds to boot Zephyr and re-mount its USB drive to macOS
        print(f"\n[WAITING] Allowing {BOARD} to boot and USB to enumerate...")
        time.sleep(5) 
        
        # 2. OPEN THE SERIAL PORT FIRST (Before starting the handshake!)
        ser = None
        for attempt in range(5):
            try:
                ser = serial.Serial(SERIAL_PORT, 115200, timeout=5)
                break 
            except serial.SerialException as e:
                print(f"[-] Serial port not ready, retrying in 2 seconds... ({e})")
                time.sleep(2)
                
        if not ser:
            print("[CRITICAL] Could not open serial port after 5 attempts. Skipping...")
            continue

        print("\n[BOOT LOG] Draining queued serial output before launching bridge...")
        drain_serial_output(ser, 2, "queued boot output")

        # 3. NOW LAUNCH THE GATEWAY TO START THE HANDSHAKE
        if SERVER_BACKEND == "raspberry_pi":
            print(f"[LAUNCHING] Starting Raspberry Pi BLE/L2CAP {PI_GATEWAY_IMPL} bridge...")
            gateway_proc = start_raspberry_pi_bridge()
        else:
            print("[LAUNCHING] Starting Swift BLE Proxy...")
            gateway_proc = subprocess.Popen([BLE_PROXY])

        # 4. CAPTURE THE RESULT
        print("\n[LISTENING] Waiting for Zephyr to finish the handshake...")
        handshake_time = "TIMEOUT/CRASH"
        start_wait = time.time()
        
        while time.time() - start_wait < HANDSHAKE_TIMEOUT:
            try:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                
                if line:
                    print(f"[{BOARD}] {line}")
                    
                # THE FIX: Match the exact string from your Zephyr C-Code
                if "Handshake_Time_MS:" in line: 
                    handshake_time = line.split(":")[1].strip()
                    break
                if "TLS Handshake Failed:" in line:
                    handshake_time = "TLS_FAILED_" + line.split(":", 1)[1].strip()
                    break
            except serial.SerialException:
                print("[-] Board disconnected mid-read! It likely suffered a HardFault.")
                break

        # 5. SAVE AND CLEANUP
        save_benchmark_result(algo['name'], handshake_time)

        if handshake_time.isdigit():
            if PUBLISH_DISCONNECT_AFTER_HANDSHAKE:
                print(f"\nSending graceful disconnect signal to {MQTT_CMD_TOPIC}...")
                publish_disconnect()
            else:
                print("\n[INFO] Board will close TLS itself after the benchmark result.")
            drain_serial_output(ser, 8, "board shutdown output")
        else:
            drain_serial_output(ser, 3, "failure output")

        ser.close()
        
        gateway_proc.terminate()
        try:
            gateway_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            gateway_proc.kill()
        if SERVER_BACKEND == "raspberry_pi":
            stop_raspberry_pi_services()
        
        print(f"✅ {algo['name']} Benchmark Complete.")
        
        print("Cooling down radio before next test...\n")
        time.sleep(8)
