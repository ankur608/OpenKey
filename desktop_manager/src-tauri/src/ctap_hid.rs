//! CTAPHID USB Transport Layer via HIDAPI and Serial CDC
//! Implements standard FIDO2 CTAPHID framing and CBOR transactions over raw 64-byte packets.

use hidapi::HidApi;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const OPENKEY_VID: u16 = 0x1209;
pub const OPENKEY_PID: u16 = 0x5070;
pub const OPENKEY_LEGACY_VID: u16 = 0x303A;
pub const OPENKEY_LEGACY_PID: u16 = 0x1002;

const CTAPHID_BROADCAST_CID: u32 = 0xFFFFFFFF;
const CTAPHID_INIT: u8 = 0x06;
const CTAPHID_PING: u8 = 0x01;
const CTAPHID_CBOR: u8 = 0x10;
const CTAPHID_MSG: u8 = 0x03;
const CTAPHID_WINK: u8 = 0x08;
const CTAPHID_ERROR: u8 = 0x3F;
const CTAPHID_KEEPALIVE: u8 = 0x3B;

const HID_PACKET_SIZE: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSummary {
    pub path: String,
    pub vendor_id: u16,
    pub product_id: u16,
    pub manufacturer: String,
    pub product: String,
    pub serial_number: String,
}

enum Transport {
    Hid(hidapi::HidDevice),
    Serial(Box<dyn serialport::SerialPort>),
}

impl Transport {
    fn write_packet(&mut self, packet_64: &[u8; HID_PACKET_SIZE]) -> Result<(), String> {
        match self {
            Transport::Hid(dev) => {
                let mut report = [0u8; HID_PACKET_SIZE + 1];
                report[1..].copy_from_slice(packet_64);
                dev.write(&report).map_err(|e| e.to_string())?;
                Ok(())
            }
            Transport::Serial(port) => {
                use std::io::Write;
                port.write_all(packet_64).map_err(|e| e.to_string())?;
                port.flush().map_err(|e| e.to_string())?;
                Ok(())
            }
        }
    }

    fn read_packet_timeout(&mut self, buf: &mut [u8; HID_PACKET_SIZE], timeout: Duration) -> Result<usize, String> {
        match self {
            Transport::Hid(dev) => {
                let millis = timeout.as_millis() as i32;
                dev.read_timeout(buf, millis).map_err(|e| e.to_string())
            }
            Transport::Serial(port) => {
                use std::io::Read;
                let start = Instant::now();
                let mut offset = 0;
                while offset < HID_PACKET_SIZE && start.elapsed() < timeout {
                    match port.read(&mut buf[offset..]) {
                        Ok(0) => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Ok(n) => {
                            offset += n;
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                            continue;
                        }
                        Err(e) => return Err(e.to_string()),
                    }
                }
                Ok(offset)
            }
        }
    }
}

pub struct CtapHidConnection {
    transport: Mutex<Transport>,
    pub cid: u32,
}

impl CtapHidConnection {
    /// Enumerate all connected FIDO / OpenKey devices
    pub fn enumerate_devices() -> Result<Vec<DeviceSummary>, String> {
        let mut list = Vec::new();
        let mut found_serial_ports = std::collections::HashSet::new();

        // 1. Scan Serial Ports (Primary for Windows due to OS fido.sys locking Usage Page 0xF1D0)
        if let Ok(ports) = serialport::available_ports() {
            for port in ports {
                let mut is_match = false;
                let mut vid = OPENKEY_VID;
                let mut pid = 0x822B;
                let mut manufacturer = "OpenKey Security".to_string();
                let mut product = "OpenKey ESP32-S3 Security Key".to_string();
                let mut serial = "OK-S30-00000001".to_string();

                match &port.port_type {
                    serialport::SerialPortType::UsbPort(usb) => {
                        vid = usb.vid;
                        pid = usb.pid;
                        if usb.vid == OPENKEY_VID || usb.vid == OPENKEY_LEGACY_VID {
                            is_match = true;
                            if let Some(m) = &usb.manufacturer {
                                manufacturer = m.clone();
                            }
                            if let Some(p) = &usb.product {
                                product = p.clone();
                            }
                            if let Some(s) = &usb.serial_number {
                                serial = s.clone();
                            }
                        }
                    }
                    _ => {}
                }

                if is_match {
                    found_serial_ports.insert(port.port_name.clone());
                    list.push(DeviceSummary {
                        path: format!("serial:{}", port.port_name),
                        vendor_id: vid,
                        product_id: pid,
                        manufacturer,
                        product,
                        serial_number: serial,
                    });
                }
            }
        }

        // 2. Scan HID Devices (macOS, Linux, or non-Windows-fido-locked devices)
        if let Ok(api) = HidApi::new() {
            for dev in api.device_list() {
                let is_openkey_vid = dev.vendor_id() == OPENKEY_VID || dev.vendor_id() == OPENKEY_LEGACY_VID;
                let is_fido_usage = dev.usage_page() == 0xF1D0;

                // On Windows, if we already detected the OpenKey via Serial CDC, avoid the OS-locked HID entry
                if is_openkey_vid && !found_serial_ports.is_empty() {
                    continue;
                }

                if is_openkey_vid || is_fido_usage {
                    list.push(DeviceSummary {
                        path: dev.path().to_string_lossy().to_string(),
                        vendor_id: dev.vendor_id(),
                        product_id: dev.product_id(),
                        manufacturer: dev.manufacturer_string().unwrap_or("Unknown").to_string(),
                        product: dev.product_string().unwrap_or("Security Key").to_string(),
                        serial_number: dev.serial_number().unwrap_or("N/A").to_string(),
                    });
                }
            }
        }

        Ok(list)
    }

    /// Open connection to device and execute CTAPHID_INIT handshake to allocate CID
    pub fn open(device_path: &str) -> Result<Self, String> {
        let transport = if device_path.starts_with("serial:") {
            let port_name = &device_path[7..];
            let port = serialport::new(port_name, 115200)
                .timeout(Duration::from_millis(500))
                .open()
                .map_err(|e| format!("Failed to open serial port {}: {}", port_name, e))?;
            Transport::Serial(port)
        } else if device_path.to_uppercase().starts_with("COM") {
            let port = serialport::new(device_path, 115200)
                .timeout(Duration::from_millis(500))
                .open()
                .map_err(|e| format!("Failed to open serial port {}: {}", device_path, e))?;
            Transport::Serial(port)
        } else {
            let api = HidApi::new().map_err(|e| e.to_string())?;
            let c_path = std::ffi::CString::new(device_path).map_err(|e| e.to_string())?;
            let device = api.open_path(&c_path).map_err(|e| e.to_string())?;
            Transport::Hid(device)
        };

        let mut conn = Self {
            transport: Mutex::new(transport),
            cid: 0,
        };
        conn.init_handshake()?;
        Ok(conn)
    }

    /// Send CTAPHID_INIT with random 8-byte nonce on broadcast CID 0xFFFFFFFF
    fn init_handshake(&mut self) -> Result<(), String> {
        let nonce = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let resp = self.send_cmd_raw(CTAPHID_BROADCAST_CID, CTAPHID_INIT, &nonce)?;

        if resp.len() < 17 {
            return Err("Invalid CTAPHID_INIT response length".into());
        }

        // Verify nonce echo
        if &resp[0..8] != &nonce {
            return Err("CTAPHID_INIT nonce mismatch".into());
        }

        // Extract allocated CID (4 bytes big-endian)
        self.cid = ((resp[8] as u32) << 24)
            | ((resp[9] as u32) << 16)
            | ((resp[10] as u32) << 8)
            | (resp[11] as u32);

        Ok(())
    }

    /// Send raw CTAPHID command with automatic 64-byte packet splitting & reassembly
    pub fn send_cmd_raw(&self, cid: u32, cmd: u8, payload: &[u8]) -> Result<Vec<u8>, String> {
        let total_len = payload.len();
        if total_len > 1280 {
            return Err("Payload exceeds CTAPHID limit".into());
        }

        // 1. Send INIT frame: CID (4B) || (cmd | 0x80) (1B) || BCNT (2B) || Data (up to 57B)
        let mut packet = [0u8; HID_PACKET_SIZE];

        packet[0] = (cid >> 24) as u8;
        packet[1] = (cid >> 16) as u8;
        packet[2] = (cid >> 8) as u8;
        packet[3] = cid as u8;
        packet[4] = cmd | 0x80;
        packet[5] = (total_len >> 8) as u8;
        packet[6] = total_len as u8;

        let mut sent = 0;
        let init_chunk = std::cmp::min(57, total_len);
        if init_chunk > 0 {
            packet[7..7 + init_chunk].copy_from_slice(&payload[0..init_chunk]);
            sent += init_chunk;
        }

        {
            let mut transport = self.transport.lock().unwrap();
            transport.write_packet(&packet)?;
        }

        // 2. Send CONT frames: CID (4B) || SEQ (1B) || Data (up to 59B)
        let mut seq: u8 = 0;
        while sent < total_len {
            packet.fill(0);
            packet[0] = (cid >> 24) as u8;
            packet[1] = (cid >> 16) as u8;
            packet[2] = (cid >> 8) as u8;
            packet[3] = cid as u8;
            packet[4] = seq;
            seq = (seq + 1) & 0x7F;

            let remaining = total_len - sent;
            let chunk = std::cmp::min(59, remaining);
            packet[5..5 + chunk].copy_from_slice(&payload[sent..sent + chunk]);
            sent += chunk;

            {
                let mut transport = self.transport.lock().unwrap();
                transport.write_packet(&packet)?;
            }
        }

        // 3. Receive Response with 16-second timeout (accommodating physical touch)
        self.receive_response(cid, cmd)
    }

    /// Read incoming 64-byte packets and reassemble response
    fn receive_response(&self, cid: u32, expected_cmd: u8) -> Result<Vec<u8>, String> {
        let start = Instant::now();
        let timeout = Duration::from_secs(16);

        let mut in_buf = [0u8; HID_PACKET_SIZE];
        let mut response = Vec::new();
        let mut expected_total: Option<usize> = None;
        let mut expected_seq: u8 = 0;

        let mut transport = self.transport.lock().unwrap();

        while start.elapsed() < timeout {
            let res = transport.read_packet_timeout(&mut in_buf, Duration::from_millis(500));
            match res {
                Ok(bytes_read) if bytes_read >= 7 => {
                    let pkt_cid = ((in_buf[0] as u32) << 24)
                        | ((in_buf[1] as u32) << 16)
                        | ((in_buf[2] as u32) << 8)
                        | (in_buf[3] as u32);

                    if pkt_cid != cid {
                        continue; // Packet for another channel
                    }

                    let cmd_or_seq = in_buf[4];

                    if cmd_or_seq & 0x80 != 0 {
                        // INIT FRAME
                        let resp_cmd = cmd_or_seq & 0x7F;

                        if resp_cmd == CTAPHID_KEEPALIVE {
                            // Hardware is waiting for physical user presence touch - reset timer
                            continue;
                        }

                        if resp_cmd == CTAPHID_ERROR {
                            return Err(format!("CTAPHID device returned error: 0x{:02X}", in_buf[7]));
                        }

                        let bcnt = ((in_buf[5] as usize) << 8) | (in_buf[6] as usize);
                        expected_total = Some(bcnt);

                        let chunk = std::cmp::min(57, bcnt);
                        response.extend_from_slice(&in_buf[7..7 + chunk]);

                        if response.len() >= bcnt {
                            return Ok(response);
                        }
                    } else {
                        // CONT FRAME
                        if let Some(total) = expected_total {
                            if cmd_or_seq != expected_seq {
                                return Err(format!("Sequence mismatch: expected {}, got {}", expected_seq, cmd_or_seq));
                            }
                            expected_seq = (expected_seq + 1) & 0x7F;

                            let remaining = total - response.len();
                            let chunk = std::cmp::min(59, remaining);
                            response.extend_from_slice(&in_buf[5..5 + chunk]);

                            if response.len() >= total {
                                return Ok(response);
                            }
                        }
                    }
                }
                Ok(_) => continue,
                Err(e) => return Err(e.to_string()),
            }
        }

        Err("Device response timed out (User presence not confirmed within 15 seconds)".into())
    }

    /// Trigger visual NeoPixel wink
    pub fn wink(&self) -> Result<(), String> {
        self.send_cmd_raw(self.cid, CTAPHID_WINK, &[])?;
        Ok(())
    }

    /// Send CTAP2 CBOR command
    pub fn send_cbor(&self, ctap2_cmd: u8, payload: &[u8]) -> Result<Vec<u8>, String> {
        let mut msg = Vec::with_capacity(payload.len() + 1);
        msg.push(ctap2_cmd);
        msg.extend_from_slice(payload);

        let resp = self.send_cmd_raw(self.cid, CTAPHID_CBOR, &msg)?;
        if resp.is_empty() {
            return Err("Empty CTAP2 response".into());
        }

        let status = resp[0];
        if status != 0x00 {
            return Err(format!("CTAP2 command failed with status: 0x{:02X}", status));
        }

        Ok(resp[1..].to_vec())
    }

    /// Send U2F/ISO APDU over CTAPHID_MSG
    pub fn send_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>, String> {
        self.send_cmd_raw(self.cid, CTAPHID_MSG, apdu)
    }

    /// Send OpenKey Vendor Command (subcmd + payload) over CTAPHID_VENDOR_OPENKEY (0x41)
    pub fn send_vendor_cmd(&self, subcmd: u8, payload: &[u8]) -> Result<Vec<u8>, String> {
        let mut msg = Vec::with_capacity(payload.len() + 1);
        msg.push(subcmd);
        msg.extend_from_slice(payload);
        self.send_cmd_raw(self.cid, 0x41, &msg)
    }
}
