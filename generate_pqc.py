import os
import subprocess
import shutil
import time
import sys

# ====================================================================
# CONFIGURATION
# ====================================================================
NRF_PROJECT_DIR = "/Users/vbalves/nordic/peripheral"
SRC_DIR = os.path.join(NRF_PROJECT_DIR, "src")
BUILD_DIR = os.path.join(NRF_PROJECT_DIR, "build")

# Docker config
DOCKER_IMAGE = "openquantumsafe/curl:latest"
CERT_CONTAINER_NAME = "pqc_auto_gen"
BROKER_CONTAINER_NAME = "mosquitto_pqc"

# Lock the output dir strictly to your peripheral folder
OUTPUT_DIR = os.path.join(NRF_PROJECT_DIR, "generated_certs")

BENCHMARK_SUITE = [
    # The Control
    #{"name": "diag_1_control_768", "macro": "WOLFSSL_P384_ML_KEM_768", "openssl_group": "p384_mlkem768"}, 
    
    # The Pure P-521 Curve
    #{"name": "diag_2_pure_p521", "macro": "WOLFSSL_ECC_SECP521R1", "openssl_group": "P-521"},    
    
    # The Pure Level 5 KEM
    {"name": "diag_3_pure_kem1024", "macro": "WOLFSSL_ML_KEM_1024", "openssl_group": "mlkem1024"},   
    
    # The Pure Level 3 KEM
    #{"name": "diag_4_pure_kem768", "macro": "WOLFSSL_ML_KEM_768", "openssl_group": "mlkem768"}     
]

ALGO_CONFIG = {
    # Map all diagnostic tests to the known-working Level 2 Certificate
    "diag_1_control_768":  {"prefix": "diag1", "key_type": "mldsa44"},
    "diag_2_pure_p521":    {"prefix": "diag2", "key_type": "mldsa44"},
    "diag_3_pure_kem1024": {"prefix": "diag3", "key_type": "mldsa44"},
    "diag_4_pure_kem768":  {"prefix": "diag4", "key_type": "mldsa44"}
}


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

def format_pem_to_c_header(pem_filepath, header_filepath, var_name, include_guard):
    """Reads a PEM file and writes it as a null-terminated C-string header."""
    print(f"[FORMATTING] {pem_filepath} -> {header_filepath}")
    with open(pem_filepath, 'r') as f:
        lines = f.readlines()

    with open(header_filepath, 'w') as f:
        f.write(f"#ifndef {include_guard}\n")
        f.write(f"#define {include_guard}\n\n")
        f.write(f"const char {var_name}[] = \n")
        for line in lines:
            clean_line = line.strip()
            if clean_line:
                f.write(f'"{clean_line}\\n"\n')
        f.write(";\n\n#endif\n")

def generate_certificates(algo_name):
    # Lookup parameters

    if os.path.exists(OUTPUT_DIR):
        for f in os.listdir(OUTPUT_DIR):
            if f.endswith(('.crt', '.key', '.csr')):
                os.remove(os.path.join(OUTPUT_DIR, f))

    params = ALGO_CONFIG.get(algo_name)
    if not params:
        print(f"[ERROR] {algo_name} not found in ALGO_CONFIG!")
        exit(1)
        
    prefix = params['prefix']
    
    print(f"\n--- STEP 1: GENERATING {algo_name.upper()} CERTIFICATES ---")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    run_cmd(["docker", "rm", "-f", CERT_CONTAINER_NAME], ignore_errors=True)
    run_cmd(["docker", "run", "-d", "--name", CERT_CONTAINER_NAME, DOCKER_IMAGE, "tail", "-f", "/dev/null"])
    
    try:

        print(f"Generating {algo_name} Certificates...")
        # CA
        run_cmd(["docker", "exec", CERT_CONTAINER_NAME, "openssl", "req", "-x509", "-new", "-newkey", params['key_type'], 
                 "-keyout", "/tmp/ca.key", "-out", "/tmp/ca.crt", "-nodes", "-subj", "/CN=PQC_Root", "-days", "365"])
        # Client
        run_cmd(["docker", "exec", CERT_CONTAINER_NAME, "openssl", "req", "-new", "-newkey", params['key_type'], 
                 "-keyout", "/tmp/client.key", "-out", "/tmp/client.csr", "-nodes", "-subj", "/CN=nrf5340"])
        run_cmd(["docker", "exec", CERT_CONTAINER_NAME, "openssl", "x509", "-req", "-in", "/tmp/client.csr", 
                 "-CA", "/tmp/ca.crt", "-CAkey", "/tmp/ca.key", "-CAcreateserial", "-out", "/tmp/client.crt", "-days", "365"])
        # Server
        run_cmd(["docker", "exec", CERT_CONTAINER_NAME, "openssl", "req", "-new", "-newkey", params['key_type'], 
                 "-keyout", "/tmp/server.key", "-out", "/tmp/server.csr", "-nodes", "-subj", "/CN=localhost"])
        run_cmd(["docker", "exec", CERT_CONTAINER_NAME, "openssl", "x509", "-req", "-in", "/tmp/server.csr", 
                 "-CA", "/tmp/ca.crt", "-CAkey", "/tmp/ca.key", "-CAcreateserial", "-out", "/tmp/server.crt", "-days", "365"])

        print("\nExtracting files to local directory...")
        for ext in ["ca.crt", "client.crt", "client.key", "server.crt", "server.key"]:
            run_cmd(["docker", "cp", f"{CERT_CONTAINER_NAME}:/tmp/{ext}", os.path.join(OUTPUT_DIR, ext)])

    finally:
        run_cmd(["docker", "rm", "-f", CERT_CONTAINER_NAME], ignore_errors=True)

def update_nrf_source(algo_name):
    # Lookup prefix safely
    prefix = ALGO_CONFIG[algo_name]['prefix']
    
    cert_pem_path = os.path.join(OUTPUT_DIR, "client.crt")
    key_pem_path = os.path.join(OUTPUT_DIR, "client.key")
    cert_h_path = os.path.join(SRC_DIR, "client_cert.h")
    key_h_path = os.path.join(SRC_DIR, "client_key.h")
    
    format_pem_to_c_header(cert_pem_path, cert_h_path, "client_pem", "CLIENT_CERT_H")
    format_pem_to_c_header(key_pem_path, key_h_path, "client_key_pem", "CLIENT_KEY_H")
    print(f"[SUCCESS] Updated {cert_h_path} and {key_h_path} for {prefix}")

def generate_openssl_conf(openssl_group_string):
    """Dynamically writes an openssl.cnf file to force Mosquitto to allow specific math."""
    conf_path = os.path.join(OUTPUT_DIR, "openssl.cnf")
    print(f"[CONFIG] Generating custom openssl.cnf for group: {openssl_group_string}")
    
    conf_content = f"""openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
ssl_conf = ssl_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1

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
        
        "openquantumsafe/mosquitto", 
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
        "-b", "nrf5340dk/nrf5340/cpuapp",
        "--sysbuild",
        "--", 
        f"-DEXTRA_CONF_FILE=sysbuild/hci_ipc.conf",
        f"-DEXTRA_CFLAGS={extra_cflags}" # Pass the fully constructed flag string
    ]
    
    print(f"\n[RUNNING] {' '.join(build_cmd)}")
    result = subprocess.run(build_cmd, cwd=NRF_PROJECT_DIR, env=env)
    if result.returncode != 0:
        print(f"[ERROR] Build failed with return code {result.returncode}")
        exit(1)
    
    print("\n[FLASHING] Uploading to nRF5340...")
    flash_cmd = [nordic_python, "-m", "west", "-z", zephyr_base, "flash"]
    print(f"\n[RUNNING] {' '.join(flash_cmd)}")
    subprocess.run(flash_cmd, cwd=NRF_PROJECT_DIR, env=env)

if __name__ == "__main__":
    ensure_docker_running()
    
    # Ensure BENCHMARK_SUITE is a list of dictionaries
    for algo in BENCHMARK_SUITE:
        # Check if 'algo' is actually a dict
        if not isinstance(algo, dict):
            print(f"[CRITICAL ERROR] Loop item is not a dictionary: {type(algo)} -> {algo}")
            continue

        print(f"\n========================================================")
        print(f"🚀 RUNNING BENCHMARK: {algo['name']}")
        print(f"========================================================")
        
        generate_certificates(algo['name']) 
        update_nrf_source(algo['name'])
        generate_openssl_conf(algo['openssl_group'])
        start_mosquitto_broker()
        build_and_flash(algo['macro'])
        xcode_app_proc = subprocess.Popen(["/Users/vbalves/Library/Developer/Xcode/DerivedData/BLE_MQTT_Proxy-cngfofzxuvkznrbiaybihnftqwuz/Build/Products/Debug/BLE_MQTT_Proxy"])
        input(">>> Press ENTER to start the benchmark, or Ctrl+C to abort...")

        # Send the disconnect command to the nRF5340 via Mosquitto
        print("Sending disconnect signal to nRF5340...")
        run_cmd([
            "docker", "exec", BROKER_CONTAINER_NAME, "mosquitto_pub",
            "-h", "localhost", "-p", "8883",
            "--cafile", "/mosquitto/config/ca.crt",
            "--cert", "/mosquitto/config/server.crt",
            "--key", "/mosquitto/config/server.key",
            "-t", "nrf5340/cmd", "-m", "disconnect"
        ])
        time.sleep(5) # Give the board 5s to close the channel
        xcode_app_proc.terminate()
        print(f"✅ {algo['name']} Benchmark Complete.")