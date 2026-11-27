"""What kind of thing a vulnerability affects, for the icon strip on watch rows, briefs, CVE pages and trends.

Deterministic: CISA KEV vendor/product names, GitHub advisory ecosystems and vendor advisory sources are
matched against the rules below. No model decides a category; anything the rules do not cover is "other",
never a guess. tests/test_pipeline.py checks coverage against the full KEV catalog.
"""
from __future__ import annotations

import re

# id, label (shown next to the icon and in the watch filter)
CATEGORIES = {
    "os": "Operating system",
    "network": "Network device",
    "remote": "VPN & remote access",
    "web": "Web & app server",
    "browser": "Browser",
    "desktop": "Desktop & office app",
    "email": "Email & collaboration",
    "identity": "Identity & access",
    "database": "Database",
    "virtual": "Virtualisation & containers",
    "cloud": "Cloud & SaaS",
    "mobile": "Mobile & chipsets",
    "ics": "Industrial (ICS/OT)",
    "itops": "IT management & backup",
    "dev": "Code & CI/CD",
    "ai": "AI & LLM tooling",
    "security": "Security software",
    "other": "Other",
}

# Ordered: the first rule that matches "vendor product title" (lower case) wins. Product-specific rules come
# before vendor-wide ones (Microsoft Exchange is email, Microsoft Windows is an operating system).
RULES: list[tuple[str, str]] = [
    ("ai", r"\b(langflow|litellm|llama|ollama|openai|anthropic|langchain|llamaindex|mcp server|model context|"
           r"comfyui|gradio|hugging ?face|vllm|ray (dashboard|cluster)|mlflow|anything-?llm|open ?webui|n8n|"
           r"gpustack|monai|triton inference|kserve|bentoml)\b"),
    ("ics", r"\b(danfoss|siemens|schneider|rockwell|mitsubishi electric|honeywell|ge (vernova|digital)|abb|"
            r"emerson|yokogawa|unitronics|delta electronics|moxa|hitachi energy|scada|plc|hmi|ics advisory|"
            r"modbus|codesys|iconics|wago|phoenix contact|advantech|optigo|openplc|scadabr|delmia|apriso)\b"),
    ("email", r"\b(exchange|zimbra|roundcube|outlook|exim|thunderbird|sharepoint|confluence|smartermail|"
              r"zcs|webmail|mailenable|teams|horde|postfix|sendmail|mdaemon|kerio connect|zoho mail|"
              r"micollab|mivoice|telemessage|trueconf|freeswitch|voip|collabora|ircd|openwave|webtop)\b"),
    ("browser", r"\b(chrom(e|ium)|v8|firefox|safari|webkit|internet explorer|edge|opera|skia|angle|"
                r"blink|mshtml|jscript|vbscript)\b"),
    ("remote", r"\b(pulse (connect )?secure|connect secure|policy secure|global ?protect|sma ?\d+|sonicwall sma|"
               r"screenconnect|simplehelp|teamviewer|anydesk|remote desktop|rd gateway|rdp|netscaler gateway|"
               r"citrix (gateway|adc)|netscaler|anyconnect|forticlient|ssl ?vpn|vpn|bomgar|beyondtrust|"
               r"remote (support|access)|cleo|ivanti (connect|policy)|array networks|pptp)\b"),
    ("virtual", r"\b(vcenter|esxi|vsphere|vmware|xen|hyper-?v|docker|kubernetes|containerd|runc|openshift|"
                r"proxmox|virtualbox|citrix hypervisor|workstation|fusion|cloud foundry|nutanix)\b"),
    ("identity", r"\b(active directory|kerberos|ntlm|netlogon|adfs|okta|ping ?(identity|federate)|keycloak|"
                 r"entra|azure ad|sso|single sign-on|duo|cyberark|thycotic|secret server|identity|ldap|"
                 r"privilege management|password ?state|saml)\b"),
    ("database", r"\b(sql server|mysql|mariadb|postgres(ql)?|oracle database|mongodb|redis|elasticsearch|"
                 r"cassandra|couchdb|sqlite|db2|influxdb|clickhouse|neo4j)\b"),
    ("itops", r"\b(solarwinds|serv-u|manageengine|endpoint manager|epmm|mobileiron|n-able|n-central|kaseya|"
              r"papercut|veeam|backup|commvault|arcserve|nakivo|connectwise automate|landesk|sccm|"
              r"configuration manager|zabbix|nagios|prtg|ivanti (epm|endpoint)|whatsup gold|moveit|"
              r"gocanywhere|goanywhere|crushftp|wing ftp|file transfer|filezilla|web help desk|service desk|"
              r"helpdesk|jira service|syncro|atera|kace|bigfix|tanium|lansweeper|wsus|accellion|fta|kiteworks|"
              r"centrestack|triofox|gladinet|salt(stack)?|puppet|ansible|minio|unraid|ahsay|sysaid|"
              r"truenas|nas)\b"),
    ("dev", r"\b(jenkins|gitlab|github|teamcity|bamboo|artifactory|nexus|sonarqube|jfrog|bitbucket|gogs|gitea|"
            r"npm|pypi|maven|nuget|rubygems|crates|composer|go module|pip|log4j|spring|struts|"
            r"jackson|xstream|commons|apache ofbiz|apache activemq|activemq|rocketmq|kafka|airflow|"
            r"laravel|symfony|rails|django|node\.?js|php|python|java se|\.net|asp\.net|visual studio|"
            r"imagemagick|archive_tar|pear|telerik|anticsrf|starlette|fastapi|flask|express)\b"),
    ("security", r"\b(defender|antivirus|anti-?malware|trend micro|sophos|symantec|mcafee|trellix|kaspersky|"
                 r"eset|bitdefender|crowdstrike|sentinelone|apex one|officescan|endpoint security|"
                 r"malware protection|secure email gateway|barracuda esg|email security)\b"),
    ("network", r"\b(pan-?os|panos|fortios|fortigate|fortiproxy|fortiweb|fortimanager|fortianalyzer|fortiswitch|"
                r"adaptive security appliance|asa|firepower|ftd|ios xe|ios xr|nx-?os|ios software|"
                r"cisco ios|junos|srx|session smart|routeros|router|firewall|switch|gateway|sd-?wan|"
                r"load balancer|big-?ip|f5|arista|aruba|edgeos|draytek|vigor|zyxel|d-link|netgear|tp-link|"
                r"tenda|linksys|ubiquiti|mikrotik|sonicos|check point|quantum|palo alto|wlan controller|"
                r"access point|catalyst|meraki|smart install|dns|dhcp|bind|unbound|snmp|brocade|fabric os|"
                r"watchguard|firebox|gpon|camera|nvr|dvr|geovision|ptzoptics|hikvision|dahua)\b"),
    ("web", r"\b(apache http|httpd|tomcat|nginx|iis|weblogic|websphere|jboss|wildfly|coldfusion|"
            r"glassfish|drupal|wordpress|joomla|magento|liferay|sitecore|adobe commerce|vbulletin|"
            r"tastyigniter|craft ?cms|dotnetnuke|dnn|geoserver|grafana|metabase|qlik|pentaho|jasperreports|"
            r"control web panel|cyberpanel|redcap|web experimentation|optimizely|cms|web ?server|application server|fusion middleware|e-business suite|netweaver|"
            r"peoplesoft|jd edwards|oracle (weblogic|fusion)|php-?fpm|cgi|struts|plex|media server|"
            r"web (interface|portal|application)|portal)\b"),
    ("mobile", r"\b(ios|ipados|watchos|android|pixel|samsung mobile|mobile devices|galaxy|qualcomm|"
               r"chipsets?|mali|arm gpu|mediatek|exynos|unisoc|baseband|kernel driver)\b"),
    ("cloud", r"\b(aws|amazon|azure|google cloud|gcp|cloudflare|salesforce|servicenow|workday|snowflake|"
              r"microsoft 365|office 365|m365|copilot|power (platform|apps|automate)|dynamics 365|"
              r"saas|cloud service|kiro|bedrock|s3|ecs|lambda)\b"),
    ("desktop", r"\b(office|word|excel|powerpoint|visio|publisher|access|acrobat|reader|flash player|winrar|"
                r"7-?zip|java|jre|quicktime|itunes|vlc|media player|wordpad|paint|notepad\+\+|"
                r"foxit|libreoffice|openoffice|zoom|webex|skype|slack|whatsapp|telegram desktop)\b"),
    ("os", r"\b(windows|win32k|microsoft windows|ntfs|smb(v[123])?|clfs|common log file|print spooler|"
           r"kernel|linux|ubuntu|debian|red hat|rhel|centos|suse|fedora|macos|os x|mac os|freebsd|openbsd|"
           r"solaris|aix|hp-?ux|unix|glibc|sudo|polkit|systemd|openssh|ssh|bash|busybox|gnu)\b"),
]

# Vendor-wide fallbacks when no product rule matched.
VENDOR: dict[str, str] = {
    "microsoft": "os", "apple": "mobile", "google": "browser", "adobe": "desktop", "oracle": "web",
    "apache": "web", "linux": "os", "cisco": "network", "fortinet": "network", "citrix": "remote",
    "ivanti": "remote", "palo alto networks": "network", "sonicwall": "network", "juniper": "network",
    "vmware": "virtual", "broadcom": "virtual", "synacor": "email", "android": "mobile", "samsung": "mobile",
    "qualcomm": "mobile", "arm": "mobile", "atlassian": "dev", "sap": "web", "ibm": "web", "red hat": "os",
    "progress": "itops", "zoho": "itops", "f5": "network", "netgear": "network", "d-link": "network",
    "tp-link": "network", "zyxel": "network", "draytek": "network", "mikrotik": "network", "qnap": "itops",
    "synology": "itops", "western digital": "itops", "mozilla": "browser", "mitel": "email",
    "trend micro": "security", "sophos": "security", "check point": "network", "solarwinds": "itops",
    "n-able": "itops", "kaseya": "itops", "connectwise": "remote", "beyondtrust": "remote",
    "jetbrains": "dev", "jenkins": "dev", "gitlab": "dev", "jfrog": "dev", "langflow": "ai",
    "berriai": "ai", "rarlab": "desktop", "exim": "email", "roundcube": "email", "wordpress": "web",
    "drupal": "web", "veeam": "itops", "papercut": "itops", "sangoma": "email", "arista": "network",
    "vates": "virtual", "danfoss": "ics", "siemens": "ics", "schneider electric": "ics",
    "rockwell automation": "ics", "gnu": "os", "plex": "web", "gigabyte": "os", "hikvision": "network",
    "dahua": "network", "tenda": "network", "linksys": "network", "ubiquiti": "network", "aruba": "network",
    "hpe": "network", "hp": "desktop", "dell": "itops", "lenovo": "os", "intel": "os", "nvidia": "os",
    "amd": "os", "vmware tanzu": "virtual", "kubernetes": "virtual", "docker": "virtual",
    "elastic": "database", "mongodb": "database", "postgresql": "database", "craft cms": "web",
    "simplehelp": "remote", "teamviewer": "remote", "anydesk": "remote", "nakivo": "itops",
    "commvault": "itops", "crushftp": "itops", "fortra": "itops", "cleo": "remote", "wing ftp": "itops",
    "zimbra": "email", "smartertools": "email", "array networks": "remote", "barracuda": "security",
    "trellix": "security", "barracuda networks": "security", "mcafee": "security", "symantec": "security", "sitecore": "web",
    "liferay": "web", "magento": "web", "telerik": "dev", "openai": "ai", "ollama": "ai",
    "notepad++": "desktop", "eyesofnetwork": "itops", "wso2": "identity", "strapi": "web", "onlyoffice": "desktop",
}

ECOSYSTEM = {"npm": "dev", "pip": "dev", "pypi": "dev", "maven": "dev", "nuget": "dev", "rubygems": "dev",
             "go": "dev", "composer": "dev", "crates.io": "dev", "rust": "dev", "pub": "dev", "swift": "dev",
             "actions": "dev", "erlang": "dev", "hex": "dev"}

SOURCE = {"cisco": "network", "fortinet": "network", "palo alto": "network", "msrc": "os", "microsoft": "os",
          "aws": "cloud", "cisa ics": "ics", "ics advisories": "ics", "oracle": "web"}

_RULES = [(cat, re.compile(rx, re.I)) for cat, rx in RULES]
OS_LABEL = [("Windows", re.compile(r"\b(windows|win32k|clfs|print spooler|ntfs|smb)\b", re.I)),
            ("macOS", re.compile(r"\b(macos|os x|mac os)\b", re.I)),
            ("Linux", re.compile(r"\b(linux|ubuntu|debian|red hat|rhel|centos|suse|fedora|glibc|polkit|systemd)\b", re.I)),
            ("iOS", re.compile(r"\b(ios|ipados)\b(?! xe| xr| software)", re.I)),
            ("Android", re.compile(r"\b(android|pixel)\b", re.I))]


def _match(text: str) -> str | None:
    return next((cat for cat, rx in _RULES if rx.search(text)), None)


def classify(vendor: str = "", product: str = "", title: str = "", ecosystem: str | None = None,
             source: str | None = None) -> str:
    """Vendor and product first, then the vendor's usual category, then the title (titles carry words like
    "access" or "word" that would mislead if matched first)."""
    name = f"{vendor} {product}".lower()
    full = f"{name} {title}".lower()
    if ecosystem and ecosystem.lower() in ECOSYSTEM and _match(full) != "ai":
        return ECOSYSTEM[ecosystem.lower()]
    if (cat := _match(name)):
        return cat
    v = vendor.lower().strip()
    if v in VENDOR:
        return VENDOR[v]
    if (cat := _match(title.lower())):
        return cat
    s = (source or "").lower()
    for k, cat in SOURCE.items():
        if k in s:
            return cat
    return "other"


def platforms(text: str) -> list[str]:
    """Operating-system names mentioned (shown as text next to the OS icon)."""
    return [name for name, rx in OS_LABEL if rx.search(text)]


def tag(vendor: str = "", product: str = "", title: str = "", ecosystem: str | None = None,
        source: str | None = None) -> dict:
    cat = classify(vendor, product, title, ecosystem, source)
    out = {"category": cat, "label": CATEGORIES[cat]}
    name = " ".join(x for x in (vendor, product) if x and x.lower() != "multiple products").strip()
    if name:
        out["product"] = name
    if (os_names := platforms(f"{product} {title}")):
        out["platforms"] = os_names
    return out


def for_cves(cves: list[str], kev: dict, title: str = "", source: str | None = None,
             ecosystem: str | None = None, package: str | None = None) -> list[dict]:
    """Affected things for a watch row or brief item: one per distinct KEV vendor/product, else one from
    the row's own title/source/ecosystem."""
    seen, out = set(), []
    for c in cves or []:
        k = kev.get(c)
        if not k:
            continue
        t = tag(k.get("vendorProject", ""), k.get("product", ""), k.get("vulnerabilityName", ""))
        key = (t["category"], t.get("product"))
        if key not in seen:
            seen.add(key)
            out.append(t)
    if not out:
        t = tag(product=package or "", title=title, ecosystem=ecosystem, source=source)
        if package:
            t["product"] = package
        out.append(t)
    return out[:6]


def write_map(kev: dict, extra: dict[str, list[dict]], out) -> int:
    """data/affected.json: CVE id -> affected tags, for every KEV entry plus watch rows outside KEV. The site
    build reads it so every page (briefs, CVE pages, trends) shows the same tags without network access."""
    import json  # noqa: PLC0415
    m = {cid: [tag(v.get("vendorProject", ""), v.get("product", ""), v.get("vulnerabilityName", ""))]
         for cid, v in kev.items()}
    for cid, tags in extra.items():
        m.setdefault(cid, tags)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(m, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n")
    return len(m)
