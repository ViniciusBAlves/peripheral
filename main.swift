import Foundation
import CoreBluetooth
import Network

class BLEGateway: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate, StreamDelegate {
    var centralManager: CBCentralManager!
    var nrfPeripheral: CBPeripheral?
    var l2capChannel: CBL2CAPChannel?
    
    // The TCP connection to Mosquitto
    var mqttConnection: NWConnection?
    
    let targetPSM: CBL2CAPPSM = 0x0080
    let bufferSize = 4096
    
    override init() {
        super.init()
        centralManager = CBCentralManager(delegate: self, queue: nil)
    }
    
    // MARK: - Bluetooth Discovery & Connection
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state == .poweredOn {
            print("[*] macOS Bluetooth Active. Scanning for nRF5340...")
            centralManager.scanForPeripherals(withServices: nil, options: nil)
        } else {
            print("[-] Bluetooth is not available or powered off.")
        }
    }
    
    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String : Any], rssi RSSI: NSNumber) {
        
        let advertisedName = advertisementData[CBAdvertisementDataLocalNameKey] as? String
        let deviceName = peripheral.name ?? advertisedName ?? "Unknown"
        
        print("Discovered: \(deviceName) | RSSI: \(RSSI)")
        
        if deviceName == "Zephyr" {
            print("[+] Found nRF5340! Attempting connection...")
            centralManager.stopScan()
            nrfPeripheral = peripheral
            nrfPeripheral?.delegate = self
            centralManager.connect(peripheral, options: nil)
        }
    } // <--- The extra '}' that caused the crash was here. It has been removed.
    
    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        print("[+] Connected to hardware. Opening L2CAP Channel on PSM 0x0080...")
        peripheral.openL2CAPChannel(targetPSM)
    }
    
    func peripheral(_ peripheral: CBPeripheral, didOpen channel: CBL2CAPChannel?, error: Error?) {
        if let error = error {
            print("[-] L2CAP Channel failed to open: \(error.localizedDescription)")
            return
        }
        guard let l2capChannel = channel else { return }
        self.l2capChannel = l2capChannel
        print("[+] L2CAP Channel Established! Bridging to Mosquitto...")
        
        setupMosquittoBridge()
    }
    
    func setupMosquittoBridge() {
        let params = NWParameters.tcp
        
        let endpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: 8883)
        mqttConnection = NWConnection(to: endpoint, using: params)
        
        mqttConnection?.stateUpdateHandler = { state in
            switch state {
            case .ready:
                print("[+] TCP Bridge to Mosquitto Active. Pumping data.")
                self.startStreams()
                self.readFromTCP()
            case .failed(let error):
                print("[-] TCP connection failed: \(error)")
            default:
                break
            }
        }
        mqttConnection?.start(queue: .global())
    }
    
    func startStreams() {
        guard let channel = l2capChannel else { return }
        
        channel.inputStream.delegate = self
        channel.inputStream.schedule(in: .main, forMode: .default)
        channel.inputStream.open()
        
        channel.outputStream.delegate = self
        channel.outputStream.schedule(in: .main, forMode: .default)
        channel.outputStream.open()
    }
    
    // MARK: - Bi-directional Forwarding
    // 1. Read from BLE, Send to TCP
    func stream(_ aStream: Stream, handle eventCode: Stream.Event) {
        if eventCode == .hasBytesAvailable, let inputStream = aStream as? InputStream {
            var buffer = [UInt8](repeating: 0, count: bufferSize)
            let bytesRead = inputStream.read(&buffer, maxLength: bufferSize)
            
            if bytesRead > 0 {
                let data = Data(buffer[0..<bytesRead])
                mqttConnection?.send(content: data, completion: .contentProcessed({ error in
                    if let error = error { print("[-] TCP Send Error: \(error)") }
                }))
            }
        }
    }
    
    // 2. Read from TCP, Send to BLE (With Drip-Feed Protection)
    func readFromTCP() {
        // Capped at 2000 bytes to align with the Zephyr RX MTU
        mqttConnection?.receive(minimumIncompleteLength: 1, maximumLength: 2000)
        {
            [weak self] data, _, isComplete, error in
            guard let self = self else { return }
            
            if let data = data, !data.isEmpty {
                var bytesWrittenTotal = 0
                
                // THE FIX: The Stream Integrity Loop
                // Keep trying to write until every single byte of the chunk is successfully pushed
                while bytesWrittenTotal < data.count {
                    let chunk = data.dropFirst(bytesWrittenTotal)
                    
                    let written = chunk.withUnsafeBytes { bufferPointer in
                        self.l2capChannel?.outputStream.write(bufferPointer.bindMemory(to: UInt8.self).baseAddress!, maxLength: chunk.count)
                    }
                    
                    if written ?? 0 < 0 {
                        print("[-] BLE Write Error")
                        break
                    }
                    
                    bytesWrittenTotal += (written ?? 0)
                    
                    // If the Mac's BLE buffer filled up mid-packet, pause for 20ms and try pushing the rest
                    if bytesWrittenTotal < data.count {
                        Thread.sleep(forTimeInterval: 0.02)
                    }
                }
                print("[Bridge] Pushed \(bytesWrittenTotal) bytes to BLE pipeline")
            }
            
            if !isComplete && error == nil {
                // Keep the 100ms overarching drip-feed so the Zephyr board has time to breathe
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
                    self.readFromTCP()
                }
            }
        }
    }
}
// Instantiate and keep the CLI alive
let gateway = BLEGateway()
RunLoop.main.run()
