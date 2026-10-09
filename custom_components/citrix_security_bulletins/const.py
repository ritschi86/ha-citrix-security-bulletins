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

# NVD sourceIdentifier of the NetScaler CNA (= assignerOrgId in the CVE record).
# Querying by source finds new CVEs immediately; CPE data is only added later
# by NVD analysts (status "Received"/"Awaiting Analysis" has no CPEs).
NETSCALER_CNA_SOURCE: Final = "50a63c94-1ea7-4568-8c11-eb79e7c5a2b5"

# Keywords to map a CNA description to a product (lowercase).
PRODUCT_KEYWORDS: Final[dict[str, tuple[str, ...]]] = {
    PRODUCT_NETSCALER_ADC: ("netscaler adc", "citrix adc", "application delivery controller"),
    PRODUCT_NETSCALER_GATEWAY: ("netscaler gateway", "citrix gateway"),
}
# Other NetScaler products of the same CNA that are not monitored.
OTHER_PRODUCT_KEYWORDS: Final[tuple[str, ...]] = (
    "netscaler console",
    "netscaler adm",
    "application delivery management",
    "netscaler sdx",
    "netscaler agent",
    "netscaler bot",
)

# Only bulletins published within this period trigger an event. Prevents a flood
# of events for old bulletins after a re-sync, while still catching late ones.
MAX_EVENT_AGE: Final = timedelta(days=7)

# Bump when the set of NVD queries changes: forces a full re-sync while keeping
# the list of already reported bulletins, so missed bulletins are reported.
CACHE_SCHEMA: Final = 2

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
