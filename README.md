# O-RAN WG11 11.1.3.2 Security Test Suite

This Python script implements the O-RAN WG11 11.1.3.2 security test for O-RU and O-DU components, focusing on:

1. **Confidentiality verification** - Ensures SSH encryption of sensitive data
2. **Integrity protection verification** - Tests packet modification detection
3. **Replay protection verification** - Validates replay attack prevention

## Features

- ✅ **Full SSH certificate support** using asyncssh
- ✅ **Passphrase-protected private keys** support
- ✅ **Packet capture and analysis** using scapy
- ✅ **Comprehensive test reporting** with detailed evidence
- ✅ **Async/await architecture** for better performance
- ✅ **Configurable test parameters** via JSON configuration

## Requirements

- Python 3.7+
- asyncssh >= 2.13.0
- scapy >= 2.4.0

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

Create a `config.json` file with your test parameters:

```json
{
    "target_host": "192.168.9.152",
    "target_port": 2277,
    "ssh_private_key_path": "/path/to/private/key",
    "ssh_private_key_passphrase": "your_passphrase",
    "ssh_certificate_path": "/path/to/certificate.pub",
    "ssh_username": "root",
    "ssh_password": null,
    "test_data_size": 1024,
    "capture_interface": "enp3s0",
    "capture_timeout": 30,
    "replay_delay": 1.0,
    "output_dir": "./test_results",
    "log_level": "INFO"
}
```

### Configuration Options

| Parameter | Description | Required |
|-----------|-------------|----------|
| `target_host` | Target host IP address | Yes |
| `target_port` | SSH port (default: 22) | No |
| `ssh_private_key_path` | Path to private key file | Yes* |
| `ssh_private_key_passphrase` | Passphrase for private key | No |
| `ssh_certificate_path` | Path to SSH certificate | No |
| `ssh_username` | SSH username | Yes |
| `ssh_password` | SSH password (alternative to key) | No |
| `test_data_size` | Size of test data in bytes | No |
| `capture_interface` | Network interface for packet capture | Yes |
| `capture_timeout` | Packet capture timeout in seconds | No |
| `replay_delay` | Delay before replay attack simulation | No |
| `output_dir` | Directory for test results | No |
| `log_level` | Logging level (DEBUG, INFO, WARNING, ERROR) | No |

*Either `ssh_private_key_path` or `ssh_password` is required.

## Usage

### Basic Usage

```bash
python oran_wg11_security_test.py --config config.json
```

### Verbose Output

```bash
python oran_wg11_security_test.py --config config.json --verbose
```

### Test Connection First

Before running the full test suite, you can test the SSH connection:

```bash
python test_asyncssh_connection.py config.json
```

## Test Details

### 1. Confidentiality Verification

- Establishes SSH connection using provided credentials
- Transmits test data over the connection
- Captures and analyzes network traffic
- Verifies that sensitive data is encrypted (not in plaintext)

**Expected Result**: All sensitive data should be encrypted with no plaintext exposure.

### 2. Integrity Protection Verification

- Generates predictable network traffic during SSH session
- Captures packets and modifies them in-flight
- Injects modified packets back into the network
- Verifies that the DUT detects and discards modified packets

**Expected Result**: The DUT should detect and discard altered packets.

### 3. Replay Protection Verification

- Captures legitimate SSH traffic
- Replays previously captured packets
- Verifies that the DUT detects and discards replayed packets

**Expected Result**: The DUT should detect and discard replayed packets.

## Output

The script generates:

1. **Console output** with real-time test progress
2. **Detailed log file** in the output directory
3. **Comprehensive test report** with results and evidence
4. **Exit codes**:
   - `0`: All tests passed
   - `1`: One or more tests failed
   - `2`: One or more tests had errors

## Example Output

```
2025-08-07 15:30:00,123 - oran_wg11_test - INFO - Starting O-RAN WG11 11.1.3.2 Security Test Suite
2025-08-07 15:30:00,456 - oran_wg11_test - INFO - Establishing SSH connection to 192.168.9.152:2277
2025-08-07 15:30:01,789 - oran_wg11_test - INFO - SSH connection established successfully
2025-08-07 15:30:01,790 - oran_wg11_test - INFO - === Starting Confidentiality Test ===
2025-08-07 15:30:04,123 - oran_wg11_test - INFO - Confidentiality test completed: PASS
2025-08-07 15:30:04,124 - oran_wg11_test - INFO - === Starting Integrity Protection Test ===
2025-08-07 15:30:12,456 - oran_wg11_test - INFO - Integrity protection test completed: PASS
2025-08-07 15:30:12,457 - oran_wg11_test - INFO - === Starting Replay Protection Test ===
2025-08-07 15:30:18,789 - oran_wg11_test - INFO - Replay protection test completed: PASS
```

## Troubleshooting

### SSH Connection Issues

1. **Authentication failed**: Verify your private key and passphrase
2. **Certificate issues**: Ensure your SSH certificate is valid and properly formatted
3. **Host key verification**: The script disables host key checking for testing

### Packet Capture Issues

1. **No packets captured**: Check your network interface name
2. **Permission denied**: Run with sudo for packet capture
3. **Interface not found**: Verify the interface exists and is active

### Test Failures

1. **Confidentiality FAIL**: Check if your SSH is properly configured for encryption
2. **Integrity FAIL**: Modern SSH may silently drop modified packets rather than terminating
3. **Replay FAIL**: Verify that your SSH server has replay protection enabled

## Security Notes

- This script is designed for testing purposes only
- It disables host key verification for automated testing
- Packet modification is performed in a controlled environment
- Always test in a safe, isolated network environment

## License

This script is provided as-is for O-RAN security testing purposes. 