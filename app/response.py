"""Response actions: suggested firewall commands per platform.

Watchtail never touches the host firewall itself; it renders the exact
command an operator can review and run, and records the suggestion in
the audit log. This keeps the tool useful in locked-down environments
where automated blocking is not acceptable.
"""

from .models import AuditEntry, utcnow

PLATFORM_COMMANDS = {
    "linux-ufw": ("ufw deny from {ip} comment 'watchtail'", "Linux (ufw)"),
    "linux-nftables": (
        "nft add rule inet filter input ip saddr {ip} drop",
        "Linux (nftables)",
    ),
    "linux-iptables": (
        "iptables -A INPUT -s {ip} -j DROP",
        "Linux (iptables)",
    ),
    "windows": (
        "netsh advfirewall firewall add rule name=\"watchtail {ip}\" "
        "dir=in action=block remoteip={ip}",
        "Windows Firewall",
    ),
    "freebsd": ("pfctl -t watchtail -T add {ip}", "FreeBSD (pf)"),
    "docker": (
        "iptables -I DOCKER-USER -s {ip} -j DROP",
        "Docker (DOCKER-USER chain)",
    ),
}


def build_commands(ip: str) -> list[dict]:
    """All platform suggestions for one address."""
    return [
        {"platform": key, "label": label, "command": template.format(ip=ip)}
        for key, (template, label) in PLATFORM_COMMANDS.items()
    ]


def record_action(session, actor: str, action: str, ip: str,
                  platform=None, command=None, detail=None):
    """Append to the audit trail inside the caller's transaction."""
    session.add(
        AuditEntry(
            ts=utcnow(),
            actor=actor or "system",
            action=action,
            target_ip=ip,
            platform=platform,
            command=command,
            detail=detail,
        )
    )


def recent_actions(session, limit=50):
    """Newest audit entries for the response page."""
    return (
        session.query(AuditEntry)
        .order_by(AuditEntry.ts.desc(), AuditEntry.id.desc())
        .limit(limit)
        .all()
    )
