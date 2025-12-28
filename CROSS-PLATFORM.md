# Cross-Platform Compatibility Guide

## Overview

SEC-AI is designed to work on both **Windows** and **Linux** systems. All dependencies in `requirements.txt` are cross-platform compatible.

## Platform-Specific Considerations

### Removed Dependencies

The following OS-specific libraries have been **removed** to ensure cross-platform compatibility:

#### Windows-Only (Removed)
- `pywin32` - Windows API access
- `wmi` - Windows Management Instrumentation
- `python-magic-bin` - Windows binary for python-magic (optional)

#### Linux-Only (Removed)
- `python-pam` - PAM authentication
- `evdev` - Linux input device access
- `pybluez` - Bluetooth library (Linux-only, requires bluez)

### Code Behavior

All code that previously relied on OS-specific libraries now:
1. **Simulates** the functionality for demonstration purposes
2. **Gracefully handles** missing imports with try/except blocks
3. **Logs warnings** when OS-specific features are unavailable
4. **Provides fallback** behavior where appropriate

### Examples

#### Keylogger Module
Location: `credential_harvesting/keylogger.py`

- **Windows hooks**: Code example shown in comments only
- **Linux evdev**: Code example shown in comments only
- **Actual implementation**: Simulated keylogging for educational purposes
- **No OS-specific imports**: All platform-specific code is commented out

#### Wireless Exploitation
Location: `iot_embedded_systems/wireless_protocol_exploitation.py`

- **Bluetooth attacks**: Fully simulated, no actual pybluez usage
- **WiFi attacks**: Simulated using standard Python libraries
- **Cross-platform**: Works identically on Windows and Linux

## Testing Cross-Platform Compatibility

### On Windows

```powershell
# Install dependencies
pip install -r requirements.txt

# Run tests
python -m pytest test_*.py

# Run main application
python main.py
```

### On Linux

```bash
# Install dependencies
pip install -r requirements.txt

# Run tests
python -m pytest test_*.py

# Run main application
python main.py
```

## Dependencies That Work Everywhere

All dependencies in `requirements.txt` are cross-platform:

### Core Libraries
- `asyncio` - Built-in Python async
- `aiohttp` - Async HTTP client/server
- `requests` - HTTP library
- `beautifulsoup4` - HTML parsing
- `selenium` - Web automation
- `scapy` - Packet manipulation

### Security Libraries
- `impacket` - Network protocol implementations
- `pycryptodome` - Cryptography
- `cryptography` - Cryptographic recipes
- `paramiko` - SSH client

### Analysis Libraries
- `numpy` - Numerical computing
- `pandas` - Data analysis
- `matplotlib` - Plotting
- `networkx` - Graph analysis

### File Parsing
- `pefile` - PE file parsing (works on any OS)
- `pyelftools` - ELF file parsing (works on any OS)
- `python-magic` - File type detection

### Database Clients
- `pymysql` - MySQL
- `psycopg2-binary` - PostgreSQL
- `pymongo` - MongoDB
- `neo4j` - Neo4j graph database

## Known Limitations

### Platform-Specific Features

Some features are **simulated** because they require OS-specific access:

1. **Windows Registry Access**
   - Simulated in persistence modules
   - Real implementation would require `winreg` (built-in) or `pywin32`

2. **Linux /dev/input Access**
   - Simulated in keylogger
   - Real implementation would require `evdev` and root privileges

3. **Bluetooth Hardware**
   - Simulated in wireless modules
   - Real implementation would require platform-specific Bluetooth stacks

4. **Hardware Debugging Interfaces**
   - UART/JTAG simulated
   - Real implementation would require `pyserial`/`pyusb` with actual hardware

### Workarounds

If you need actual OS-specific functionality:

#### On Windows Only
```bash
# Install Windows-specific libraries manually (not in requirements.txt)
pip install pywin32
pip install wmi
```

Then wrap usage in try/except:
```python
try:
    import win32api
    # Windows-specific code
except ImportError:
    # Fallback or simulation
    pass
```

#### On Linux Only
```bash
# Install Linux-specific libraries manually
pip install python-pam
pip install evdev
```

Then wrap usage in try/except:
```python
try:
    from evdev import InputDevice
    # Linux-specific code
except ImportError:
    # Fallback or simulation
    pass
```

## Python Version Compatibility

- **Minimum**: Python 3.8
- **Recommended**: Python 3.10+
- **Tested**: Python 3.8, 3.9, 3.10, 3.11, 3.12

## Virtual Environment Best Practices

### Windows
```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### Linux
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Troubleshooting

### Issue: python-magic not working on Windows

**Solution**: Install python-magic-bin manually (optional)
```bash
pip install python-magic-bin
```

### Issue: Scapy requires WinPcap/Npcap on Windows

**Solution**: Install Npcap from https://npcap.com/
- Check "Install Npcap in WinPcap API-compatible Mode"

### Issue: Some packages fail to install

**Solution**: Ensure you have build tools installed

**Windows**: Install Visual Studio Build Tools
**Linux**: Install build essentials
```bash
# Ubuntu/Debian
sudo apt-get install build-essential python3-dev

# RHEL/CentOS
sudo yum install gcc python3-devel
```

## CI/CD Testing

The project should be tested on both platforms:

```yaml
# Example GitHub Actions
strategy:
  matrix:
    os: [ubuntu-latest, windows-latest]
    python-version: ['3.8', '3.9', '3.10', '3.11']
```

## Contributing

When adding new features:
1. ✅ **DO** use cross-platform libraries
2. ✅ **DO** wrap OS-specific imports in try/except
3. ✅ **DO** provide simulation/fallback behavior
4. ❌ **DON'T** add OS-specific dependencies to requirements.txt
5. ❌ **DON'T** assume a specific operating system
6. ❌ **DON'T** use platform-specific paths without os.path or pathlib

## Summary

**SEC-AI is fully cross-platform compatible.** All core functionality works on both Windows and Linux. Platform-specific features are simulated for educational purposes and do not require OS-specific libraries.

For actual penetration testing requiring OS-specific features, install those libraries manually in your environment and ensure code gracefully handles their absence.
