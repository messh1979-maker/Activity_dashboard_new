import hashlib
import platform
import re
import socket
import uuid

import psutil


def _normalize_mac(mac: str) -> str:
    """Normalize MAC address to uppercase with colon separator."""
    return mac.upper().replace("-", ":").replace(".", ":").strip()


def get_primary_mac() -> tuple(str | None, str):
    """
    Get the primary MAC address of the system.
    
    Returns:
        tuple of (mac_address, source) where source is one of:
        - 'psutil': from psutil net_if_addrs (preferred)
        - 'uuid_getnode': from uuid.getnode() fallback
        - 'unavailable': if no MAC could be determined
    """
    # Try to find a non-virtual, active network interface with a local IP
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            local_ip = s.getsockname()[0]
    except (OSError, socket.error):
        local_ip = None

    stats = psutil.net_if_stats()
    # First pass: find interface that has the local IP and is up
    for name, addrs in psutil.net_if_addrs().items():
        st = stats.get(name)
        if not st or not st.isup:
            continue
        if local_ip and any(a.address == local_ip for a in addrs):
            mac = next(
                (a.address for a in addrs if a.family == psutil.AF_LINK),
                None
            )
            if mac and mac != "00:00:00:00:00:00":
                return _normalize_mac(mac), "psutil"

    # Second pass: fallback to any up interface (avoiding virtual ones)
    for name, addrs in psutil.net_if_addrs().items():
        if name.lower() in ("loopback", "vmware", "virtualbox",
                           "hyper-v", "docker", "vethernet"):
            continue
        st = stats.get(name)
        if not st or not st.isup:
            continue
        mac = next(
            (a.address for a in addrs if a.family == psutil.AF_LINK),
            None
        )
        if mac and mac != "00:00:00:00:00:00":
            return _normalize_mac(mac), "psutil"

    # Fallback: uuid.getnode()
    node = uuid.getnode()
    # Check that the MAC bit is global/unicast (bit 40 = 0)
    if (node >> 40) % 2 == 0:
        mac = ":".join(f"{(node >> e) & 0xFF:02X}" for e in range(40, -8, -8))
        return _normalize_mac(mac), "uuid_getnode"

    # Last resort: return None (MAC randomization or VM environment)
    return None, "unavailable"


def get_system_fingerprint() -> str:
    """
    Generate a stable system fingerprint based on multiple hardware/software attributes.
    
    This fingerprint is more stable than MAC alone (which can change with
    network randomization) and is used as the primary device identity.
    
    Returns:
        SHA-256 hex digest string representing the system fingerprint.
    """
    mac, _ = get_primary_mac()
    parts = [
        platform.node(),
        platform.machine(),
        platform.system(),
        platform.processor(),
        str(psutil.cpu_count(logical=False)),
        _machine_guid(),
        (mac or "no-mac"),
    ]
    normalized = "|".join(filter(None, parts))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _machine_guid() -> str:
    """
    Read the Machine GUID from Windows registry (HKLM\Software\Microsoft\Cryptography).
    
    This is a more stable identifier than MAC as it persists across
    network changes and VM snapshots.
    """
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography"
        ) as key:
            machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        return machine_guid
    except (WindowsError, ImportError, FileNotFoundError):
        # Fallback to a hash of system info if registry not accessible
        import hashlib
        import platform
        data = f"{platform.node()}|{platform.machine()}|{platform.system()}"
        return hashlib.sha256(data.encode("utf-8")).hexdigest()[:8]


def is_valid_mac_format(mac: str) -> bool:
    """
    Validate that a MAC address string has the correct format.
    
    Accepted formats: 00:1A:2B:3C:4D:5E or 00-1A-2B-3C-4D-5E
    """
    pattern = r'^([0-9A-F]{2}[:\-]){5}[0-9A-F]{2}$'
    return bool(re.match(pattern, mac.upper())) and mac.upper() not in (
        "00:00:00:00:00:00",
        "FF:FF:FF:FF:FF:FF",
    )