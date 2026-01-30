"""Constants used throughout HomeGuard."""

# Timeouts
SOCKET_TIMEOUT_SECONDS = 1.0
HTTP_TIMEOUT_SECONDS = 60.0
BANNER_GRAB_TIMEOUT_SECONDS = 2.0
LLM_TIMEOUT_SECONDS = 60.0

# Scan limits
MAX_SCAN_ITERATIONS = 25
MAX_PORT_SCAN_THREADS = 100
MAX_BANNER_LENGTH = 1024
MAX_HTTP_RESPONSE_SIZE = 1024 * 1024  # 1MB
MAX_DEVICES_PER_SCAN = 254

# Network
DEFAULT_BACKEND_URL = "http://5.223.45.191:8000"

# Vendor name mappings for threat intel search
VENDOR_MAPPINGS = {
    "tp-link": "tp-link",
    "beijing xiaomi": "xiaomi",
    "xiaomi": "xiaomi",
    "gree electric": "gree",
    "asustek": "asus",
    "asus": "asus",
    "apple": "apple",
    "bsh hausgeraete": "bosch",
    "huawei": "huawei",
    "samsung": "samsung",
    "netgear": "netgear",
    "d-link": "dlink",
    "ubiquiti": "ubiquiti",
    "hikvision": "hikvision",
    "dahua": "dahua",
    "synology": "synology",
    "qnap": "qnap",
    "cisco": "cisco",
    "linksys": "linksys",
    "zyxel": "zyxel",
    "mikrotik": "mikrotik",
    "ring": "ring",
    "nest": "nest",
    "philips": "philips",
    "sonos": "sonos",
    "roku": "roku",
    "amazon": "amazon",
}
