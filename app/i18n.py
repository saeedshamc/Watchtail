"""Minimal bilingual string table (English + Persian).

No external i18n framework: the UI strings that matter live in one
dictionary, ``tr()`` picks the language from the session (default
English), and the nav offers a toggle. Persian strings are authored
for the dashboard chrome; dynamic log data stays untranslated.
"""

from flask import session

STRINGS = {
    "nav.dashboard": {"en": "Dashboard", "fa": "داشبورد"},
    "nav.events": {"en": "Events", "fa": "رویدادها"},
    "nav.sources": {"en": "Sources", "fa": "منابع"},
    "nav.respond": {"en": "Respond", "fa": "پاسخ"},
    "nav.suppressions": {"en": "Suppressions", "fa": "سکوت‌ها"},
    "nav.cases": {"en": "Cases", "fa": "پرونده‌ها"},
    "nav.settings": {"en": "Settings", "fa": "تنظیمات"},
    "nav.logout": {"en": "Log out", "fa": "خروج"},
    "stats.events": {"en": "events (24h)", "fa": "رویداد (۲۴ ساعت)"},
    "stats.alerts": {"en": "alerts (24h)", "fa": "هشدار (۲۴ ساعت)"},
    "stats.flagged": {"en": "flagged IPs", "fa": "IP پرچم‌دار"},
    "stats.sources": {"en": "sources tailing", "fa": "منبع فعال"},
    "panel.highest_risk": {"en": "Highest risk", "fa": "بالاترین خطر"},
    "panel.flagged": {"en": "Flagged IPs", "fa": "IPهای پرچم‌دار"},
    "panel.latest": {"en": "Latest events", "fa": "آخرین رویدادها"},
    "panel.traffic": {"en": "Traffic & 4xx errors (last hour, UTC)", "fa": "ترافیک و خطاهای 4xx (یک ساعت اخیر، UTC)"},
    "flagged.none": {"en": "No IPs flagged right now.", "fa": "در حال حاضر IP پرچم‌داری وجود ندارد."},
    "risk.none": {"en": "No scored threats yet.", "fa": "هنوز تهدید امتیازداری وجود ندارد."},
    "events.waiting": {"en": "Waiting for log lines…", "fa": "در انتظار لاگ…"},
    "state.live": {"en": "live", "fa": "زنده"},
    "state.connecting": {"en": "connecting…", "fa": "در حال اتصال…"},
    "state.reconnecting": {"en": "reconnecting…", "fa": "اتصال مجدد…"},
    "state.unavailable": {"en": "live updates unavailable", "fa": "به‌روزرسانی زنده در دسترس نیست"},
    "review.mark": {"en": "review", "fa": "بررسی"},
    "review.dismiss": {"en": "dismiss", "fa": "رد"},
    "review.none": {"en": "no recorded alerts", "fa": "هشدار ثبت‌شده‌ای وجود ندارد"},
    "table.time": {"en": "time (UTC)", "fa": "زمان (UTC)"},
    "table.kind": {"en": "kind", "fa": "نوع"},
    "table.ip": {"en": "ip", "fa": "IP"},
    "table.request": {"en": "request", "fa": "درخواست"},
    "table.status": {"en": "status", "fa": "وضعیت"},
    "export.csv": {"en": "download CSV", "fa": "دانلود CSV"},
    "export.api": {"en": "JSON API", "fa": "JSON API"},
    "filter.apply": {"en": "Filter", "fa": "فیلتر"},
    "filter.reset": {"en": "reset", "fa": "بازنشانی"},
}

SUPPORTED = ("en", "fa")


def current_language() -> str:
    try:
        lang = session.get("lang")
    except RuntimeError:
        return "en"  # outside a request context (tests, CLI)
    return lang if lang in SUPPORTED else "en"


def set_language(lang: str) -> None:
    if lang in SUPPORTED:
        session["lang"] = lang


def tr(key: str) -> str:
    if key not in STRINGS:
        return key
    entry = STRINGS[key]
    return entry.get(current_language()) or entry["en"]
