"""Process-wide handle to the running TailManager.

run.py (and wsgi.py) own the manager; the web layer needs to reconcile
tail workers when an operator adds, pauses or removes a source from
the dashboard, so the reference is parked here for both sides.
"""

import threading

_manager = None
_lock = threading.Lock()


def set_manager(manager):
    """Register (or, with None, unregister) the process tail manager."""
    global _manager
    with _lock:
        _manager = manager


def get_manager():
    with _lock:
        return _manager


def resync_tailing():
    """Reconcile tail workers with the current source rows.

    Best-effort: returns False when no manager is registered (tests,
    tooling), so routes can simply ignore the outcome. Endpoint
    sources (udp://, tcp://) are reconciled through the registry parked
    on ``manager.listeners`` when present.
    """
    manager = get_manager()
    if manager is None:
        return False
    from .database import session_scope
    from .models import LogSource

    with session_scope() as session:
        sources = session.query(LogSource).all()
    manager.sync(sources)
    listeners = getattr(manager, "listeners", None)
    if listeners is not None:
        listeners.sync(sources)
    return True
