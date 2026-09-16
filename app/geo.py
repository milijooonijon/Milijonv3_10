"""
Geo IP, Country Flags, and Region Detection
"""
from typing import List, Dict, Any

def get_country_flag_emoji(country_code: str) -> str:
    if not country_code or len(country_code) != 2:
        return "🌐"
    try:
        return "".join(chr(127397 + ord(c)) for c in country_code.upper())
    except Exception:
        return "🌐"

DEFAULT_LOCATIONS: List[Dict[str, Any]] = [
    {"code": "DE", "name": "Germany", "flag": "🇩🇪", "active": True},
    {"code": "NL", "name": "Netherlands", "flag": "🇳🇱", "active": True},
    {"code": "US", "name": "United States", "flag": "🇺🇸", "active": True},
    {"code": "GB", "name": "United Kingdom", "flag": "🇬🇧", "active": True},
    {"code": "FR", "name": "France", "flag": "🇫🇷", "active": True},
    {"code": "FI", "name": "Finland", "flag": "🇫🇮", "active": True},
    {"code": "SE", "name": "Sweden", "flag": "🇸🇪", "active": True},
    {"code": "TR", "name": "Turkey", "flag": "🇹🇷", "active": True},
    {"code": "JP", "name": "Japan", "flag": "🇯🇵", "active": True},
    {"code": "SG", "name": "Singapore", "flag": "🇸🇬", "active": True},
    {"code": "AE", "name": "United Arab Emirates", "flag": "🇦🇪", "active": True},
    {"code": "CH", "name": "Switzerland", "flag": "🇨🇭", "active": True},
    {"code": "CA", "name": "Canada", "flag": "🇨🇦", "active": True},
    {"code": "IR", "name": "Iran", "flag": "🇮🇷", "active": True}
]

COUNTRY_KEYWORDS = [
    ("GERMANY", "DE"), ("FRANKFURT", "DE"), ("BERLIN", "DE"), ("DE-", "DE"), ("-DE", "DE"),
    ("NETHERLANDS", "NL"), ("AMSTERDAM", "NL"), ("NL-", "NL"), ("-NL", "NL"),
    ("UNITED STATES", "US"), ("AMERICA", "US"), ("NEW YORK", "US"), ("LOS ANGELES", "US"), ("US-", "US"), ("-US", "US"),
    ("UNITED KINGDOM", "GB"), ("LONDON", "GB"), ("UK-", "GB"), ("-UK", "GB"), ("GB-", "GB"),
    ("FRANCE", "FR"), ("PARIS", "FR"), ("FR-", "FR"), ("-FR", "FR"),
    ("FINLAND", "FI"), ("HELSINKI", "FI"), ("FI-", "FI"), ("-FI", "FI"),
    ("SWEDEN", "SE"), ("STOCKHOLM", "SE"), ("SE-", "SE"), ("-SE", "SE"),
    ("TURKEY", "TR"), ("ISTANBUL", "TR"), ("TR-", "TR"), ("-TR", "TR"),
    ("JAPAN", "JP"), ("TOKYO", "JP"), ("JP-", "JP"), ("-JP", "JP"),
    ("SINGAPORE", "SG"), ("SG-", "SG"), ("-SG", "SG"),
    ("DUBAI", "AE"), ("UAE", "AE"), ("AE-", "AE"),
    ("SWITZERLAND", "CH"), ("ZURICH", "CH"), ("CH-", "CH"),
    ("CANADA", "CA"), ("TORONTO", "CA"), ("CA-", "CA"),
    ("IRAN", "IR"), ("TEHRAN", "IR"), ("IR-", "IR")
]

def infer_country_code(name: str, host: str) -> str:
    upper = f"{name} {host}".upper()
    for kw, code in COUNTRY_KEYWORDS:
        if kw in upper:
            return code
    return "UN"
