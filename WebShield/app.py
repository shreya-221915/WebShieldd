import json
import os
import socket
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import streamlit as st

APP_TITLE = "WebShield"
TIMEOUT_SECONDS = 8

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "purpose": "Helps browsers use HTTPS for future visits.",
        "recommendation": "For HTTPS sites, configure an appropriate Strict-Transport-Security policy."
    },
    "Content-Security-Policy": {
        "purpose": "Restricts which sources a browser may load content from.",
        "recommendation": "Create a Content-Security-Policy suited to the site's resources; test it before enforcement."
    },
    "X-Content-Type-Options": {
        "purpose": "Helps prevent MIME-type sniffing.",
        "recommendation": "Set X-Content-Type-Options: nosniff."
    },
    "X-Frame-Options": {
        "purpose": "Can help reduce clickjacking risk in older browsers.",
        "recommendation": "Set X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors."
    },
    "Referrer-Policy": {
        "purpose": "Controls how much referrer information browsers send.",
        "recommendation": "Set a policy such as strict-origin-when-cross-origin where appropriate."
    },
    "Permissions-Policy": {
        "purpose": "Controls access to selected browser features.",
        "recommendation": "Set a Permissions-Policy that disables features the site does not need."
    },
}

def allowed_hosts():
    """Comma-separated exact hostnames explicitly authorized by the operator."""
    raw = os.getenv("WEBSHIELD_ALLOWED_HOSTS", "")
    return {h.strip().lower().rstrip(".") for h in raw.split(",") if h.strip()}

def is_loopback_host(host):
    host = (host or "").lower().rstrip(".")
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False

def validate_target(raw_url):
    raw_url = raw_url.strip()
    if not raw_url:
        return False, "Enter a URL, such as http://127.0.0.1:8000."
    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"}:
        return False, "Only HTTP and HTTPS URLs are supported."
    if not parsed.hostname:
        return False, "That URL does not contain a valid hostname."
    if parsed.username or parsed.password:
        return False, "URLs containing usernames or passwords are not allowed."
    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        return False, "The URL contains an invalid port."

    host = parsed.hostname.lower().rstrip(".")
    authorized = is_loopback_host(host) or host in allowed_hosts()
    if not authorized:
        configured = ", ".join(sorted(allowed_hosts())) or "(none configured)"
        return False, (
            "Target blocked. WebShield only scans localhost/loopback addresses and exact "
            f"hostnames listed in WEBSHIELD_ALLOWED_HOSTS. Configured hostnames: {configured}."
        )

    # For allowlisted hostnames, reject DNS answers that point outside private/loopback
    # address space. This conservative restriction keeps the starter project local/private.
    if not is_loopback_host(host):
        try:
            answers = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
            ips = {ipaddress.ip_address(item[4][0]) for item in answers}
            if not ips or any(not (ip.is_private or ip.is_loopback or ip.is_link_local) for ip in ips):
                return False, "Target blocked: allowlisted hostname must resolve only to private, loopback, or link-local IP addresses."
        except (socket.gaierror, ValueError):
            return False, "Could not resolve the allowlisted hostname."
    return True, raw_url

def severity_for_missing_header(name, is_https):
    if name == "Strict-Transport-Security" and not is_https:
        return "Info"
    if name in {"Content-Security-Policy", "Strict-Transport-Security"}:
        return "Medium"
    return "Low"

def scan_target(raw_url):
    valid, result = validate_target(raw_url)
    if not valid:
        raise ValueError(result)
    url = result

    # Redirects are deliberately disabled so a permitted local URL cannot redirect
    # the scanner to an unrelated host.
    try:
        response = requests.get(
            url,
            timeout=TIMEOUT_SECONDS,
            allow_redirects=False,
            headers={"User-Agent": "WebShield-Student-Scanner/1.0"},
            verify=True,
        )
    except requests.exceptions.SSLError:
        raise RuntimeError("TLS certificate validation failed. For this local demo, use http://127.0.0.1:8000.")
    except requests.exceptions.Timeout:
        raise RuntimeError(f"The target did not respond within {TIMEOUT_SECONDS} seconds.")
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"Could not connect to the target: {exc.__class__.__name__}.")

    parsed = urlparse(url)
    is_https = parsed.scheme == "https"
    headers = {k.lower(): v for k, v in response.headers.items()}
    findings = []

    if is_https:
        findings.append({
            "check": "HTTPS",
            "status": "Pass",
            "severity": "Info",
            "details": "The supplied URL uses HTTPS. This check does not independently audit TLS configuration."
        })
    else:
        findings.append({
            "check": "HTTPS",
            "status": "Review",
            "severity": "Medium",
            "details": "The supplied URL uses HTTP, so transport encryption is not provided by this connection."
        })

    for header, info in SECURITY_HEADERS.items():
        value = headers.get(header.lower())
        if value:
            findings.append({
                "check": header,
                "status": "Present",
                "severity": "Info",
                "details": f"Header is present: {value[:300]}"
            })
        else:
            severity = severity_for_missing_header(header, is_https)
            findings.append({
                "check": header,
                "status": "Missing",
                "severity": severity,
                "details": info["recommendation"]
            })

    set_cookie = response.headers.get("Set-Cookie", "")
    if set_cookie:
        cookie_flags = set_cookie.lower()
        missing = []
        if "secure" not in cookie_flags:
            missing.append("Secure")
        if "httponly" not in cookie_flags:
            missing.append("HttpOnly")
        if "samesite" not in cookie_flags:
            missing.append("SameSite")
        if missing:
            findings.append({
                "check": "Cookie security flags",
                "status": "Review",
                "severity": "Low" if not is_https else "Medium",
                "details": "Cookie response appears to be missing or not show these flags: " + ", ".join(missing)
            })
        else:
            findings.append({
                "check": "Cookie security flags",
                "status": "Present",
                "severity": "Info",
                "details": "The Set-Cookie response includes Secure, HttpOnly, and SameSite text. Multiple cookies should be reviewed individually in a fuller implementation."
            })
    else:
        findings.append({
            "check": "Cookie security flags",
            "status": "Not observed",
            "severity": "Info",
            "details": "The response did not include a Set-Cookie header."
        })

    if response.status_code in {301, 302, 303, 307, 308}:
        findings.append({
            "check": "Redirect",
            "status": "Review",
            "severity": "Info",
            "details": "The target returned a redirect. WebShield does not follow redirects; inspect the Location header manually before scanning the destination."
        })

    counts = {
        "Pass / Present": sum(1 for f in findings if f["status"] in {"Pass", "Present"}),
        "Review / Missing": sum(1 for f in findings if f["status"] in {"Review", "Missing"}),
        "Medium": sum(1 for f in findings if f["severity"] == "Medium"),
        "Low": sum(1 for f in findings if f["severity"] == "Low"),
    }
    return {
        "project": APP_TITLE,
        "scan_time_utc": datetime.now(timezone.utc).isoformat(),
        "target": url,
        "scope": "Authorized localhost/loopback or explicitly allowlisted private host",
        "http_status": response.status_code,
        "server_header": response.headers.get("Server", "Not disclosed"),
        "content_type": response.headers.get("Content-Type", "Not disclosed"),
        "findings": findings,
        "summary": counts,
        "limitations": [
            "This is a beginner educational checker, not a full vulnerability scanner or penetration test.",
            "A present header does not prove a site is secure; a missing header is not by itself proof of an exploitable vulnerability.",
            "Redirects are not followed. Only scan systems you own or have explicit permission to test."
        ],
    }

st.set_page_config(page_title="WebShield Security Scanner", page_icon="🛡️", layout="wide")
st.title("🛡️ WebShield")
st.caption("Beginner-friendly web security header checker • Authorized targets only")

with st.sidebar:
    st.header("About this project")
    st.write("WebShield checks basic HTTP response protections and produces a JSON report.")
    st.markdown("**Allowed targets**")
    st.write("• localhost / loopback IPs\n• exact hostnames configured in `WEBSHIELD_ALLOWED_HOSTS` that resolve only to private addresses")
    st.markdown("**Not a penetration-testing tool**")
    st.write("It does not exploit vulnerabilities, brute-force accounts, or follow redirects.")

st.info("For your first test, run the included demo site and scan http://127.0.0.1:8000. Only scan systems you own or have explicit permission to test.")
url = st.text_input("Target URL", value="http://127.0.0.1:8000", help="Example: http://127.0.0.1:8000")
scan = st.button("Run security checks", type="primary")

if scan:
    with st.spinner("Checking the authorized target..."):
        try:
            report = scan_target(url)
            st.session_state["webshield_report"] = report
        except (ValueError, RuntimeError) as exc:
            st.error(str(exc))

report = st.session_state.get("webshield_report")
if report:
    st.subheader("Scan summary")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("HTTP status", report["http_status"])
    c2.metric("Pass / Present", report["summary"]["Pass / Present"])
    c3.metric("Review / Missing", report["summary"]["Review / Missing"])
    c4.metric("Medium findings", report["summary"]["Medium"])

    st.write(f"**Target:** `{report['target']}`")
    st.write(f"**Scan time (UTC):** {report['scan_time_utc']}")
    st.write(f"**Server:** {report['server_header']}  •  **Content type:** {report['content_type']}")

    st.subheader("Findings")
    for finding in report["findings"]:
        with st.expander(f"{finding['status']} — {finding['check']} ({finding['severity']})", expanded=True):
            st.write(finding["details"])

    st.subheader("Recommendations")
    st.write("1. Add and test missing security headers appropriate to the application.")
    st.write("2. Use HTTPS for production sites and configure HSTS only after HTTPS is working correctly.")
    st.write("3. Review cookies individually and use Secure, HttpOnly, and an appropriate SameSite value where applicable.")
    st.write("4. Re-run checks after making changes and document before/after results.")

    report_json = json.dumps(report, indent=2)
    st.download_button(
        "Download JSON report",
        data=report_json,
        file_name="webshield_report.json",
        mime="application/json"
    )

    with st.expander("Project limitations"):
        for item in report["limitations"]:
            st.write(f"• {item}")
