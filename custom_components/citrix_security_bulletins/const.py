"""Constants for the Citrix Security Bulletins integration."""

from __future__ import annotations

from datetime import timedelta
from typing import Final

DOMAIN: Final = "citrix_security_bulletins"

CONF_PRODUCTS: Final = "products"

# Polling interval (Home Assistant guidelines: not user-configurable).
UPDATE_INTERVAL: Final = timedelta(hours=1)

# NVD CVE API 2.0
NVD_CVE_API_URL: Final = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DETAIL_URL: Final = "https://nvd.nist.gov/vuln/detail/{cve_id}"
# Direct link to a Citrix knowledge base / security bulletin article.
CITRIX_ARTICLE_URL: Final = "https://support.citrix.com/external/article/{bulletin_id}"
NVD_RESULTS_PER_PAGE: Final = 2000
# The NVD API rejects date ranges longer than 120 consecutive days.
NVD_MAX_RANGE: Final = timedelta(days=120)
# Recommended pause between requests (5 req/30 s without key, 50 req/30 s with key).
NVD_DELAY_WITHOUT_KEY: Final = 6.0
NVD_DELAY_WITH_KEY: Final = 1.0
NVD_REQUEST_TIMEOUT: Final = 60

PRODUCT_NETSCALER_ADC: Final = "netscaler_adc"
PRODUCT_NETSCALER_GATEWAY: Final = "netscaler_gateway"

# Product key -> CPE match string (full 13-part form with wildcards, as used by NVD).
PRODUCT_CPES: Final[dict[str, str]] = {
    PRODUCT_NETSCALER_ADC: "cpe:2.3:a:citrix:netscaler_application_delivery_controller:*:*:*:*:*:*:*:*",
    PRODUCT_NETSCALER_GATEWAY: "cpe:2.3:a:citrix:netscaler_gateway:*:*:*:*:*:*:*:*",
}

PRODUCT_NAMES: Final[dict[str, str]] = {
    PRODUCT_NETSCALER_ADC: "NetScaler ADC",
    PRODUCT_NETSCALER_GATEWAY: "NetScaler Gateway",
}

DEFAULT_PRODUCTS: Final[list[str]] = [PRODUCT_NETSCALER_ADC, PRODUCT_NETSCALER_GATEWAY]

EVENT_TYPE_NEW_BULLETIN: Final = "new_bulletin"

STORAGE_VERSION: Final = 1
STORAGE_KEY: Final = f"{DOMAIN}.cache"

# Number of bulletins exposed in the sensor's "recent_bulletins" attribute.
RECENT_BULLETINS: Final = 5

SEVERITY_LEVELS: Final[list[str]] = ["none", "low", "medium", "high", "critical"]
