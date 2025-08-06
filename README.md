# O-RAN WG11 11.1.3.2 Security Test Suite

This Python script implements the O-RAN Working Group 11 specification 11.1.3.2 test for SSH connection security verification between O-RU (O-RAN Radio Unit) and O-DU (O-RAN Distributed Unit) components.

## Overview

The test suite verifies three critical security aspects:

1. **Confidentiality Verification**: Ensures all data transmitted over SSH connections is properly encrypted
2. **Integrity Protection Verification**: Confirms that the system detects and discards modified packets
3. **Replay Protection Verification**: Validates that the system prevents replay attacks

## Features

- Support for customer-provided SSH private keys, public keys, and certificates
- Real-time packet capture and analysis using Scapy
- Comprehensive test reporting with pass/fail assessments
- Detailed evidence collection for each test
- Configurable test parameters
- Professional logging and output

## Requirements

- Python 3.7 or higher
- Root/administrator privileges for packet capture
- Network access to the target O-RU/O-DU device
- SSH credentials (private key, public key, and/or certificate)

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Ensure you have the necessary privileges for packet capture:
```bash
# On Linux/macOS, you may need to run with sudo
# On Windows, run as Administrator
```

## Configuration

Create a configuration file (see `config.json` example) with the following parameters:

### Required Parameters

- `target_host`: IP address or hostname of the target device
- `ssh_private_key_path`: Path to your SSH private key file
- `ssh_username`: SSH username for authentication

### Optional Parameters

- `target_port`: SSH port (default: 22)
- `ssh_public_key_path`: Path to SSH public key file
- `ssh_certificate_path`: Path to SSH certificate file
- `ssh_password`: SSH password (if not using key-based auth)
- `test_data_size`: Size of test data in bytes (default: 1024)
- `capture_interface`: Network interface for packet capture (default: auto-detect)
- `capture_timeout`: Packet capture timeout in seconds (default: 30)
- `replay_delay`: Delay before replay attack in seconds (default: 1.0)
- `output_dir`: Directory for test results (default: ./test_results)
- `log_level`: Logging level (INFO, DEBUG, WARNING, ERROR)

### Example Configuration

```json
{
    "target_host": "192.168.1.100",
    "target_port": 22,
    "ssh_private_key_path": "/path/to/your/private_key.pem",
    "ssh_public_key_path": "/path/to/your/public_key.pub",
    "ssh_certificate_path": "/path/to/your/certificate.crt",
    "ssh_username": "root",
    "test_data_size": 1024,
    "capture_interface": "eth0",
    "output_dir": "./test_results"
}
```

## Usage

### Basic Usage

```bash
python oran_wg11_security_test.py --config config.json
```

### Verbose Mode

```bash
python oran_wg11_security_test.py --config config.json --verbose
```

### Running with Elevated Privileges (for packet capture)

```bash
# Linux/macOS
sudo python oran_wg11_security_test.py --config config.json

# Windows (run as Administrator)
python oran_wg11_security_test.py --config config.json
```

## Test Descriptions

### 1. Confidentiality Verification

**Purpose**: Verify that all sensitive data transmitted over the SSH connection is encrypted.

**Process**:
1. Establishes SSH connection using provided credentials
2. Starts packet capture on the network interface
3. Transmits test data over the SSH connection
4. Analyzes captured packets for plaintext data exposure
5. Assesses encryption effectiveness

**Pass Criteria**: No sensitive data found in plaintext; all traffic is properly encrypted.

**Expected Result**: All sensitive data transmitted over the OFH M-Plane interface is encrypted, with no data exposed in clear text.

### 2. Integrity Protection Verification

**Purpose**: Confirm that the system detects and discards packets that have been modified in transit.

**Process**:
1. Establishes SSH connection and starts packet capture
2. Transmits data over the connection
3. Captures packets and creates modified versions
4. Attempts to inject modified packets into the connection
5. Monitors SSH connection health and response

**Pass Criteria**: SSH connection detects modified packets and either rejects them or terminates the connection.

**Expected Result**: The DUT detects and discards altered packets, ensuring the data has not been tampered with.

### 3. Replay Protection Verification

**Purpose**: Validate that the system prevents replay attacks by detecting and discarding replayed packets.

**Process**:
1. Establishes SSH connection and captures legitimate traffic
2. Stores captured packets for replay
3. Waits for a delay period
4. Replays previously captured packets
5. Monitors system response to replayed traffic

**Pass Criteria**: System detects and ignores or rejects replayed packets, maintaining connection security.

**Expected Result**: The DUT detects and discards replayed packets, preventing replay attacks.

## Output

The test suite generates several outputs:

### Console Output
- Real-time test progress and results
- Summary of pass/fail status for each test
- Final assessment against expected results

### Log Files
- Detailed execution logs in `test_results/` directory
- Timestamped log files with DEBUG level information
- Error tracking and troubleshooting information

### Test Reports
- Comprehensive test report with detailed results
- Evidence collection for each test case
- Assessment against O-RAN WG11 expected results
- JSON format evidence for further analysis

### Example Report Structure

```
O-RAN WG11 11.1.3.2 Security Test Report
==================================================
Test Date: 2024-01-15 14:30:00
Target: 192.168.1.100:22

Test Results Summary:
------------------------------
PASS: 3
FAIL: 0
ERROR: 0
TOTAL: 3

Expected Results Assessment:
------------------------------

1. Confidentiality:
   Status: PASS
   Expected: All sensitive data transmitted over the OFH M-Plane interface is encrypted, with no data exposed in clear text.
   Assessment: PASS: All data appears to be encrypted. Captured 45 encrypted packets, no plaintext data found.

2. Integrity Protection:
   Status: PASS
   Expected: The DUT detects and discards altered packets, ensuring the data has not been tampered with.
   Assessment: PASS: SSH connection detected and rejected modified packets, demonstrating integrity protection.

3. Replay Protection:
   Status: PASS
   Expected: The DUT detects and discards replayed packets, preventing replay attacks.
   Assessment: PASS: Replayed packets were ignored by SSH connection, demonstrating replay protection.
```

## Security Considerations

- This tool requires network packet capture capabilities, which may require elevated privileges
- The test involves generating potentially malicious network traffic (modified/replayed packets)
- Ensure you have proper authorization before testing against any network infrastructure
- Run tests in isolated network environments when possible
- Be aware that some tests may temporarily disrupt SSH connections

## Troubleshooting

### Common Issues

1. **Permission Denied for Packet Capture**
   - Solution: Run with elevated privileges (sudo/Administrator)
   - Alternative: Configure capabilities on Linux: `sudo setcap cap_net_raw=eip python3`

2. **SSH Connection Failures**
   - Check network connectivity to target host
   - Verify SSH credentials and paths
   - Ensure target SSH service is running and accessible

3. **No Packets Captured**
   - Verify network interface name in configuration
   - Check if traffic filtering is blocking SSH traffic
   - Ensure capture interface has traffic flowing

4. **Module Import Errors**
   - Install required dependencies: `pip install -r requirements.txt`
   - Ensure Python version compatibility (3.7+)

### Debug Mode

Enable verbose logging for detailed troubleshooting:

```bash
python oran_wg11_security_test.py --config config.json --verbose
```

## License

This tool is provided for O-RAN compliance testing purposes. Ensure compliance with local laws and regulations regarding network security testing.

## Support

For issues related to O-RAN WG11 specifications, refer to the official O-RAN documentation. For tool-specific issues, check the log files in the output directory for detailed error information. 