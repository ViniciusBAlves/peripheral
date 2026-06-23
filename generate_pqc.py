import os
import subprocess
import shutil
import time
import sys
import serial
import csv

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

# Docker config
DOCKER_IMAGE = "pqc-openssl:3.5"
DOCKERFILE_DIR = os.path.join(NRF_PROJECT_DIR, "docker", "pqc-openssl")
CERT_CONTAINER_NAME = "pqc_auto_gen"
BROKER_CONTAINER_NAME = "mosquitto_pqc"

# Lock the output dir strictly to your peripheral folder
OUTPUT_DIR = os.path.join(NRF_PROJECT_DIR, "generated_certs")

KEMS = [
    #{"name": "MLKEM512", "macro": "WOLFSSL_ML_KEM_512", "group": "MLKEM512"},
    {"name": "MLKEM768", "macro": "WOLFSSL_ML_KEM_768", "group": "MLKEM768"},
    {"name": "MLKEM1024", "macro": "WOLFSSL_ML_KEM_1024", "group": "MLKEM1024"},
]

SIGS = [
    # Classical Baseline Signatures
    #{"name": "ECDSA-P-256", "key_gen": "ec:prime256v1", "ssl_group": "P-256"},
    # Post-Quantum Signatures
    #{"name": "ML-DSA-44", "key_gen": "ML-DSA-44"},
    #{"name": "ML-DSA-65", "key_gen": "ML-DSA-65"},
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

def start_mosquitto_broker():
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
        start_mosquitto_broker()
        build_and_flash(algo['macro'])
        
        # 1. THE USB BOUNCE DELAY
        # Give the board 5 seconds to boot Zephyr and re-mount its USB drive to macOS
        print("\n[WAITING] Allowing nRF52840 to boot and USB to enumerate...")
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

        # Clear any garbage binary from the boot sequence
        ser.reset_input_buffer()

        # 3. NOW LAUNCH THE MAC GATEWAY TO START THE HANDSHAKE
        print("[LAUNCHING] Starting Swift BLE Proxy...")
        xcode_app_proc = subprocess.Popen([BLE_PROXY])

        # 4. CAPTURE THE RESULT
        print("\n[LISTENING] Waiting for Zephyr to finish the handshake...")
        handshake_time = "TIMEOUT/CRASH"
        start_wait = time.time()
        
        while time.time() - start_wait < HANDSHAKE_TIMEOUT:
            try:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                
                if line:
                    print(f"[NRF52840] {line}")
                    
                # THE FIX: Match the exact string from your Zephyr C-Code
                if "Handshake_Time_MS:" in line: 
                    handshake_time = line.split(":")[1].strip()
                    break
            except serial.SerialException:
                print("[-] Board disconnected mid-read! It likely suffered a HardFault.")
                break

        # 5. SAVE AND CLEANUP
        save_benchmark_result(algo['name'], handshake_time)
        ser.close()

        print("\nSending disconnect signal to nRF52840...")
        run_cmd([
            "docker", "exec", BROKER_CONTAINER_NAME, "mosquitto_pub",
            "-h", "localhost", "-p", "8883",
            "--cafile", "/mosquitto/config/ca.crt",
            "--cert", "/mosquitto/config/server.crt",
            "--key", "/mosquitto/config/server.key",
            "-t", "nrf52840/cmd", "-m", "disconnect"
        ], ignore_errors=True)
        
        time.sleep(5) 
        xcode_app_proc.terminate()
        
        print(f"✅ {algo['name']} Benchmark Complete.")
        
        print("Cooling down radio before next test...\n")
        time.sleep(8)
