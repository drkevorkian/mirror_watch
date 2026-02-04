# /mirror_watch.py
"""
Mirror Watch (no UI)
- Watches a source folder and mirrors changes into a destination folder.
- Full sync on startup (including soft-deleting extras in destination).
- Remembers last folders across restarts via ~/.mirror_watch/config.json
- Continuously verifies/corrects drift via an MD5 scanning thread.
- Ignores paths via gitignore-style rules (built-in list below).
- Soft delete: moves removed/extra/ignored items into UPDATE/.bak/<YYYY-MM-DD>/<HHMMSS>/...
- Styled console output:
  - COPY green
  - SOFT_DELETE orange
  - soft delete failures / errors red
  - file paths white
  - folder paths light brown
- Log file is always plain (no color codes).
- Locked-file suppression:
  - Writes locked paths to locked.log with timestamps
  - Per-path 12-hour hold before attempting/logging again to avoid console spam

Usage
  pip install watchdog pathspec colorama
  python mirror_watch.py
  python mirror_watch.py --monitor "/src" --update "/dst" --scan-interval 10
"""

from __future__ import annotations

import argparse
import datetime as dt
import errno
import hashlib
import json
import logging
import shutil
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from pathspec import PathSpec
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

try:
    from colorama import init as colorama_init  # type: ignore
except Exception:  # pragma: no cover
    colorama_init = None

APP_DIR = Path.home() / ".mirror_watch"
CONFIG_PATH = APP_DIR / "config.json"

LOCK_HOLD_HOURS = 12

GITIGNORE_PATTERNS = [
    # Environment files
    ".env",
    ".env.local",
    ".env.*.local",
    # PHP
    "/vendor/",
    "composer.lock",
    "*.log",
    "logs/",
    "*.cache",
    # File storage (contains user data)
    "storage/queue/*.json",
    "storage/queue/*.tmp",
    # Node.js
    "node_modules/",
    "npm-debug.log*",
    "yarn-debug.log*",
    "yarn-error.log*",
    "dist/",
    "build/",
    ".npm",
    ".eslintcache",
    # Python
    "__pycache__/",
    "*.py[cod]",
    "*$py.class",
    "*.so",
    ".Python",
    "venv/",
    "env/",
    "ENV/",
    ".venv",
    "*.egg-info/",
    ".pytest_cache/",
    # IDE
    ".idea/",
    ".vscode/",
    "*.swp",
    "*.swo",
    "*~",
    ".DS_Store",
    # Database
    "*.sqlite",
    "*.db",
    # Logs
    "*.log",
    "logs/",
    # OS
    "Thumbs.db",
    ".DS_Store",
    # Build artifacts
    "*.o",
    "*.a",
    "*.so",
    # Coverage reports
    "coverage/",
    ".nyc_output/",
    # Temporary files
    "tmp/",
    "temp/",
    "*.tmp",
]


# -------------------------
# Console styling
# -------------------------

class Ansi:
    RESET = "\x1b[0m"
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    ORANGE = "\x1b[38;5;208m"
    WHITE = "\x1b[97m"
    LIGHT_BROWN = "\x1b[33m"


ACTION_COLORS = {
    "COPY": Ansi.GREEN,
    "SOFT_DELETE": Ansi.ORANGE,
    "MKDIR": Ansi.LIGHT_BROWN,
    "MOVE": Ansi.LIGHT_BROWN,
    "DELETE": Ansi.LIGHT_BROWN,
    "RMDIR": Ansi.LIGHT_BROWN,
}


def _supports_color(stream) -> bool:
    try:
        return hasattr(stream, "isatty") and stream.isatty()
    except Exception:
        return False


class ColorizingFormatter(logging.Formatter):
    def __init__(self, use_color: bool, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        if not self.use_color:
            return base

        action = getattr(record, "action", None)
        is_dir = getattr(record, "is_dir", None)
        path_text = getattr(record, "path_text", None)

        if record.levelno >= logging.ERROR:
            return f"{Ansi.RED}{base}{Ansi.RESET}"

        if action:
            action_color = ACTION_COLORS.get(action, "")
            if action == "SOFT_DELETE_FAIL":
                action_color = Ansi.RED
            elif action.startswith("SOFT_DELETE") and action_color == "":
                action_color = Ansi.ORANGE

            if action in base:
                base = base.replace(action, f"{action_color}{action}{Ansi.RESET}", 1)

        if path_text and path_text in base:
            pcolor = Ansi.LIGHT_BROWN if is_dir else Ansi.WHITE
            base = base.replace(path_text, f"{pcolor}{path_text}{Ansi.RESET}")

        return base


def _today_log_name(prefix: str = "mirror") -> str:
    return f"{prefix}_{dt.date.today().isoformat()}.log"


def setup_logger(log_dir: Path) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / _today_log_name()

    logger = logging.getLogger("mirror_watch")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if logger.handlers:
        return logger

    if colorama_init:
        colorama_init()

    fmt = "%(asctime)s | %(levelname)s | %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(logging.Formatter(fmt=fmt, datefmt=datefmt))
    fh.setLevel(logging.INFO)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(ColorizingFormatter(use_color=_supports_color(sys.stdout), fmt=fmt, datefmt=datefmt))

    logger.addHandler(fh)
    logger.addHandler(ch)

    logger.info("Logging to: %s", log_path)
    return logger


def log_action(
    logger: logging.Logger,
    action: str,
    message: str,
    path: Optional[Path] = None,
    is_dir: Optional[bool] = None,
    level: int = logging.INFO,
) -> None:
    extra = {"action": action}
    if path is not None:
        extra["path_text"] = str(path)
        extra["is_dir"] = bool(is_dir) if is_dir is not None else (path.exists() and path.is_dir())
    logger.log(level, f"{action} | {message}", extra=extra)


# -------------------------
# Locked suppression
# -------------------------

def _is_win_locked_error(exc: Exception) -> bool:
    winerror = getattr(exc, "winerror", None)
    if winerror == 32:  # ERROR_SHARING_VIOLATION
        return True
    err = getattr(exc, "errno", None)
    return err in {errno.EACCES, errno.EPERM}


class LockedFileTracker:
    """
    Tracks locked paths and suppresses repeated attempts/logs per-path for a hold window.
    Writes to locked.log on first lock and each re-try that is still locked.
    """

    def __init__(self, locked_log_path: Path, hold_hours: int = LOCK_HOLD_HOURS):
        self.locked_log_path = locked_log_path
        self.hold = dt.timedelta(hours=hold_hours)
        self._next_attempt: dict[str, dt.datetime] = {}
        self._guard = threading.Lock()
        self.locked_log_path.parent.mkdir(parents=True, exist_ok=True)

    def should_attempt(self, path: Path) -> bool:
        key = str(path)
        now = dt.datetime.now()
        with self._guard:
            nxt = self._next_attempt.get(key)
            if nxt is None or now >= nxt:
                return True
            return False

    def mark_locked(self, path: Path) -> None:
        key = str(path)
        now = dt.datetime.now()
        with self._guard:
            self._next_attempt[key] = now + self.hold

    def write_locked_log(self, path: Path, reason: str, error: Exception) -> None:
        ts = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"{ts} | {reason} | {path} | {error}\n"
        try:
            with self.locked_log_path.open("a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass

    def maybe_report_locked(
        self,
        logger: logging.Logger,
        action: str,
        path: Path,
        reason: str,
        error: Exception,
        is_dir: bool,
    ) -> None:
        """
        If hold expired for this path, log + write locked.log and extend hold.
        Otherwise, stay silent.
        """
        if not self.should_attempt(path):
            return

        self.write_locked_log(path, reason, error)
        self.mark_locked(path)
        log_action(
            logger,
            action,
            f"SKIP locked ({reason}) {path} | {error}",
            path=path,
            is_dir=is_dir,
            level=logging.WARNING,
        )


# -------------------------
# Config / CLI
# -------------------------

@dataclass(frozen=True)
class AppConfig:
    monitor_dir: Path
    update_dir: Path
    log_dir: Path
    scan_interval_sec: float


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Mirror changes from one folder to another.")
    p.add_argument("--monitor", type=str, default=None, help="Folder to monitor (source).")
    p.add_argument("--update", type=str, default=None, help="Folder to update (destination).")
    p.add_argument("--log-dir", type=str, default=None, help="Directory for log files.")
    p.add_argument("--scan-interval", type=float, default=None, help="Seconds between MD5 scan passes.")
    return p.parse_args(argv)


def prompt_for_path(label: str, default: Optional[Path] = None) -> Path:
    while True:
        hint = f" [{default}]" if default else ""
        raw = input(f"{label}{hint}: ").strip().strip('"')
        if not raw and default:
            return default
        if raw:
            return Path(raw)
        print("Please enter a non-empty path.")


def load_config_file() -> dict:
    try:
        if CONFIG_PATH.exists():
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def save_config_file(monitor: Path, update: Path, log_dir: Path, scan_interval: float) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "monitor": str(monitor),
        "update": str(update),
        "log_dir": str(log_dir),
        "scan_interval_sec": scan_interval,
    }
    CONFIG_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _is_subpath(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except Exception:
        return False


def validate_paths(monitor: Path, update: Path) -> tuple[Path, Path]:
    monitor = monitor.expanduser().resolve()
    update = update.expanduser().resolve()

    if not monitor.exists() or not monitor.is_dir():
        raise ValueError(f"Monitor folder does not exist or is not a folder: {monitor}")
    if monitor == update:
        raise ValueError("Monitor and update folders must be different.")
    if _is_subpath(update, monitor):
        raise ValueError("Update folder must NOT be inside monitor folder (would cause loops).")
    if _is_subpath(monitor, update):
        raise ValueError("Monitor folder must NOT be inside update folder (would cause confusion).")

    update.mkdir(parents=True, exist_ok=True)
    return monitor, update


def build_effective_config(args: argparse.Namespace) -> AppConfig:
    saved = load_config_file()

    saved_monitor = Path(saved["monitor"]) if "monitor" in saved else None
    saved_update = Path(saved["update"]) if "update" in saved else None
    saved_log = Path(saved["log_dir"]) if "log_dir" in saved else None
    saved_interval = float(saved.get("scan_interval_sec", 10.0))

    monitor = Path(args.monitor) if args.monitor else saved_monitor
    update = Path(args.update) if args.update else saved_update
    log_dir = Path(args.log_dir) if args.log_dir else (saved_log or Path("."))
    scan_interval = float(args.scan_interval) if args.scan_interval is not None else saved_interval

    if monitor is None:
        monitor = prompt_for_path("Monitor folder", saved_monitor)
    if update is None:
        update = prompt_for_path("Update folder", saved_update)

    return AppConfig(monitor_dir=monitor, update_dir=update, log_dir=log_dir, scan_interval_sec=scan_interval)


# -------------------------
# Ignore + filesystem helpers
# -------------------------

class IgnoreMatcher:
    def __init__(self, monitor_root: Path, patterns: list[str]):
        self.monitor_root = monitor_root.resolve()
        self.spec = PathSpec.from_lines("gitwildmatch", patterns)

    def is_ignored(self, path: Path, is_dir: Optional[bool] = None) -> bool:
        try:
            rel = path.resolve().relative_to(self.monitor_root)
        except Exception:
            return True
        rel_posix = rel.as_posix()
        if is_dir is True and not rel_posix.endswith("/"):
            rel_posix += "/"
        if is_dir is None and path.exists() and path.is_dir() and not rel_posix.endswith("/"):
            rel_posix += "/"
        return self.spec.match_file(rel_posix)


def dst_for(monitor_root: Path, update_root: Path, src: Path) -> Path:
    rel = src.resolve().relative_to(monitor_root)
    return (update_root / rel).resolve()


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def md5_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.md5()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def files_probably_equal(src: Path, dst: Path) -> bool:
    try:
        s1 = src.stat()
        s2 = dst.stat()
    except FileNotFoundError:
        return False
    if s1.st_size != s2.st_size:
        return False
    return abs(s1.st_mtime - s2.st_mtime) <= 1.0


def copy2_logged(
    logger: logging.Logger,
    locked: LockedFileTracker,
    src: Path,
    dst: Path,
    reason: str,
) -> None:
    if not src.exists() or not src.is_file():
        log_action(logger, "COPY", f"SKIP ({reason}) src missing/not file: {src}", path=src, is_dir=False)
        return
    ensure_parent(dst)
    try:
        shutil.copy2(src, dst)
        log_action(logger, "COPY", f"({reason}) {src} -> {dst}", path=dst, is_dir=False)
    except Exception as e:
        if _is_win_locked_error(e):
            locked.maybe_report_locked(logger, "COPY", dst, f"copy ({reason})", e, is_dir=False)
            return
        log_action(logger, "COPY", f"ERROR ({reason}) {src} -> {dst} | {e}", path=dst, is_dir=False, level=logging.ERROR)


# -------------------------
# Soft delete
# -------------------------

def bak_root(update_root: Path, when: dt.datetime) -> Path:
    return update_root / ".bak" / when.strftime("%Y-%m-%d") / when.strftime("%H%M%S")


def soft_delete(
    logger: logging.Logger,
    locked: LockedFileTracker,
    update_root: Path,
    dst_path: Path,
    reason: str,
    when: Optional[dt.datetime] = None,
) -> None:
    if not dst_path.exists():
        return

    try:
        rel = dst_path.resolve().relative_to(update_root.resolve())
    except Exception:
        log_action(logger, "SOFT_DELETE", f"SKIP outside update: {dst_path}", path=dst_path, is_dir=dst_path.is_dir())
        return

    if rel.parts and rel.parts[0] == ".bak":
        return

    when = when or dt.datetime.now()
    target = bak_root(update_root, when) / rel
    ensure_parent(target)

    try:
        shutil.move(str(dst_path), str(target))
        log_action(logger, "SOFT_DELETE", f"({reason}) {dst_path} -> {target}", path=dst_path, is_dir=dst_path.is_dir())
        return
    except Exception as e:
        if _is_win_locked_error(e):
            locked.maybe_report_locked(logger, "SOFT_DELETE", dst_path, f"soft_delete ({reason})", e, is_dir=dst_path.is_dir())
            return

        log_action(logger, "SOFT_DELETE_FAIL", f"move failed ({reason}) {dst_path} | {e}", path=dst_path, is_dir=dst_path.is_dir(), level=logging.ERROR)

    if dst_path.is_dir():
        target.mkdir(parents=True, exist_ok=True)

        for child in sorted(dst_path.rglob("*"), key=lambda p: len(p.parts), reverse=True):
            try:
                child_rel = child.resolve().relative_to(dst_path.resolve())
                child_target = target / child_rel

                if child.is_dir():
                    child_target.mkdir(parents=True, exist_ok=True)
                    continue

                ensure_parent(child_target)
                try:
                    shutil.move(str(child), str(child_target))
                    log_action(logger, "SOFT_DELETE", f"item ({reason}) {child} -> {child_target}", path=child, is_dir=False)
                except Exception as e:
                    if _is_win_locked_error(e):
                        locked.maybe_report_locked(logger, "SOFT_DELETE", child, f"soft_delete item ({reason})", e, is_dir=False)
                        continue
                    log_action(logger, "SOFT_DELETE_FAIL", f"item move failed ({reason}) {child} | {e}", path=child, is_dir=False, level=logging.ERROR)
            except Exception as e:
                log_action(logger, "SOFT_DELETE_FAIL", f"dir traversal error ({reason}) {child} | {e}", path=child, is_dir=child.is_dir(), level=logging.ERROR)

        # remove empty dirs (leave if locked items remain)
        try:
            for d in sorted([p for p in dst_path.rglob("*") if p.is_dir()], key=lambda p: len(p.parts), reverse=True):
                try:
                    d.rmdir()
                except OSError:
                    pass
            try:
                dst_path.rmdir()
                log_action(logger, "SOFT_DELETE", f"dir done ({reason}) {dst_path}", path=dst_path, is_dir=True)
            except OSError:
                # don't spam: treat as "still locked" hold on the directory itself
                locked.maybe_report_locked(
                    logger,
                    "SOFT_DELETE",
                    dst_path,
                    f"soft_delete dir partial ({reason})",
                    OSError("directory not empty (locked items remain)"),
                    is_dir=True,
                )
        except Exception as e:
            log_action(logger, "SOFT_DELETE_FAIL", f"dir cleanup error ({reason}) {dst_path} | {e}", path=dst_path, is_dir=True, level=logging.ERROR)
        return

    # file fallback: copy+unlink unless locked
    try:
        shutil.copy2(dst_path, target)
        try:
            dst_path.unlink()
            log_action(logger, "SOFT_DELETE", f"fallback copy+unlink ({reason}) {dst_path} -> {target}", path=dst_path, is_dir=False)
        except Exception as e:
            if _is_win_locked_error(e):
                locked.maybe_report_locked(logger, "SOFT_DELETE", dst_path, f"soft_delete unlink ({reason})", e, is_dir=False)
                return
            raise
    except Exception as e:
        if _is_win_locked_error(e):
            locked.maybe_report_locked(logger, "SOFT_DELETE", dst_path, f"soft_delete fallback ({reason})", e, is_dir=False)
            return
        log_action(logger, "SOFT_DELETE_FAIL", f"fallback failed ({reason}) {dst_path} | {e}", path=dst_path, is_dir=False, level=logging.ERROR)


# -------------------------
# Full sync
# -------------------------

def full_sync(
    monitor_root: Path,
    update_root: Path,
    ignore: IgnoreMatcher,
    logger: logging.Logger,
    locked: LockedFileTracker,
) -> None:
    logger.info("FULL SYNC: start")

    for src_path in monitor_root.rglob("*"):
        try:
            is_dir = src_path.is_dir()
            if ignore.is_ignored(src_path, is_dir=is_dir):
                continue

            if is_dir:
                dst_dir = dst_for(monitor_root, update_root, src_path)
                dst_dir.mkdir(parents=True, exist_ok=True)
                log_action(logger, "MKDIR", f"(full_sync) {dst_dir}", path=dst_dir, is_dir=True)
                continue

            if not src_path.is_file():
                continue

            dst_path = dst_for(monitor_root, update_root, src_path)
            if not dst_path.exists():
                copy2_logged(logger, locked, src_path, dst_path, "full_sync create")
                continue

            if files_probably_equal(src_path, dst_path):
                continue

            try:
                if md5_file(src_path) != md5_file(dst_path):
                    copy2_logged(logger, locked, src_path, dst_path, "full_sync update")
            except Exception as e:
                log_action(logger, "COPY", f"md5 compare error, fallback update: {src_path} | {e}", path=dst_path, is_dir=False, level=logging.WARNING)
                copy2_logged(logger, locked, src_path, dst_path, "full_sync fallback update")

        except Exception as e:
            log_action(logger, "COPY", f"full_sync processing error: {src_path} | {e}", path=src_path, is_dir=src_path.is_dir(), level=logging.ERROR)

    when = dt.datetime.now()
    for dst_path in sorted(update_root.rglob("*"), reverse=True):
        try:
            rel = dst_path.resolve().relative_to(update_root.resolve())
            if rel.parts and rel.parts[0] == ".bak":
                continue

            src_equiv = (monitor_root / rel).resolve()
            if src_equiv.exists():
                is_dir = src_equiv.is_dir()
                if not ignore.is_ignored(src_equiv, is_dir=is_dir):
                    continue

            soft_delete(logger, locked, update_root, dst_path, "full_sync extra/ignored", when=when)
        except Exception as e:
            log_action(logger, "SOFT_DELETE_FAIL", f"full_sync cleanup error: {dst_path} | {e}", path=dst_path, is_dir=dst_path.is_dir(), level=logging.ERROR)

    logger.info("FULL SYNC: done")


# -------------------------
# Watchdog mirroring
# -------------------------

class MirrorHandler(FileSystemEventHandler):
    def __init__(
        self,
        monitor_root: Path,
        update_root: Path,
        ignore: IgnoreMatcher,
        logger: logging.Logger,
        locked: LockedFileTracker,
    ):
        self.monitor_root = monitor_root
        self.update_root = update_root
        self.ignore = ignore
        self.logger = logger
        self.locked = locked
        self._locks: dict[Path, threading.Lock] = {}
        self._locks_guard = threading.Lock()

    def _lock_for(self, dst: Path) -> threading.Lock:
        with self._locks_guard:
            lk = self._locks.get(dst)
            if lk is None:
                lk = threading.Lock()
                self._locks[dst] = lk
            return lk

    def on_created(self, event):
        src = Path(event.src_path)
        if self.ignore.is_ignored(src, is_dir=bool(event.is_directory)):
            return

        try:
            dst = dst_for(self.monitor_root, self.update_root, src)
        except Exception:
            return

        if event.is_directory:
            try:
                dst.mkdir(parents=True, exist_ok=True)
                log_action(self.logger, "MKDIR", f"(created) {dst}", path=dst, is_dir=True)
            except Exception as e:
                log_action(self.logger, "MKDIR", f"ERROR mkdir: {dst} | {e}", path=dst, is_dir=True, level=logging.ERROR)
            return

        with self._lock_for(dst):
            copy2_logged(self.logger, self.locked, src, dst, "created")

    def on_modified(self, event):
        if event.is_directory:
            return
        src = Path(event.src_path)
        if self.ignore.is_ignored(src, is_dir=False):
            return

        try:
            dst = dst_for(self.monitor_root, self.update_root, src)
        except Exception:
            return

        with self._lock_for(dst):
            copy2_logged(self.logger, self.locked, src, dst, "modified")

    def on_deleted(self, event):
        src = Path(event.src_path)
        try:
            dst = dst_for(self.monitor_root, self.update_root, src)
        except Exception:
            return

        with self._lock_for(dst):
            soft_delete(self.logger, self.locked, self.update_root, dst, "watch deleted")

    def on_moved(self, event):
        src = Path(event.src_path)
        dest = Path(event.dest_path)

        dest_ignored = self.ignore.is_ignored(dest, is_dir=bool(event.is_directory))

        try:
            dst_src = dst_for(self.monitor_root, self.update_root, src)
            dst_dest = dst_for(self.monitor_root, self.update_root, dest)
        except Exception:
            return

        when = dt.datetime.now()

        if dest_ignored:
            with self._lock_for(dst_dest):
                soft_delete(self.logger, self.locked, self.update_root, dst_dest, "watch moved->ignored", when=when)
                soft_delete(self.logger, self.locked, self.update_root, dst_src, "watch moved->ignored cleanup old", when=when)
            return

        with self._lock_for(dst_dest):
            try:
                ensure_parent(dst_dest)
                if dst_src.exists():
                    shutil.move(str(dst_src), str(dst_dest))
                    log_action(self.logger, "MOVE", f"{dst_src} -> {dst_dest}", path=dst_dest, is_dir=dst_dest.is_dir())
                else:
                    if dest.exists() and dest.is_file():
                        copy2_logged(self.logger, self.locked, dest, dst_dest, "moved fallback copy")
            except Exception as e:
                if _is_win_locked_error(e):
                    self.locked.maybe_report_locked(self.logger, "MOVE", dst_dest, "move", e, is_dir=dst_dest.is_dir())
                    return
                log_action(self.logger, "MOVE", f"ERROR move: {dst_src} -> {dst_dest} | {e}", path=dst_dest, is_dir=dst_dest.is_dir(), level=logging.ERROR)
                if dest.exists() and dest.is_file():
                    copy2_logged(self.logger, self.locked, dest, dst_dest, "moved fallback copy")


# -------------------------
# MD5 scan thread
# -------------------------

class Md5Scanner(threading.Thread):
    def __init__(
        self,
        monitor_root: Path,
        update_root: Path,
        ignore: IgnoreMatcher,
        interval_sec: float,
        logger: logging.Logger,
        stop_event: threading.Event,
        locked: LockedFileTracker,
    ):
        super().__init__(daemon=True)
        self.monitor_root = monitor_root
        self.update_root = update_root
        self.ignore = ignore
        self.interval_sec = max(1.0, float(interval_sec))
        self.logger = logger
        self.stop_event = stop_event
        self.locked = locked
        self._last_md5: dict[Path, str] = {}

    def run(self) -> None:
        self.logger.info("MD5 SCAN: started (interval=%.1fs)", self.interval_sec)
        while not self.stop_event.is_set():
            start = time.time()
            try:
                self._scan_once()
            except Exception as e:
                log_action(self.logger, "SOFT_DELETE_FAIL", f"MD5 SCAN loop error: {e}", level=logging.ERROR)

            elapsed = time.time() - start
            self.stop_event.wait(max(0.0, self.interval_sec - elapsed))
        self.logger.info("MD5 SCAN: stopped")

    def _scan_once(self) -> None:
        for src in self.monitor_root.rglob("*"):
            if self.stop_event.is_set():
                return
            try:
                if not src.exists():
                    continue
                is_dir = src.is_dir()
                if self.ignore.is_ignored(src, is_dir=is_dir):
                    continue
                if is_dir or not src.is_file():
                    continue

                dst = dst_for(self.monitor_root, self.update_root, src)
                ensure_parent(dst)

                if not dst.exists():
                    copy2_logged(self.logger, self.locked, src, dst, "md5_scan create")
                    self._last_md5[src] = md5_file(src)
                    continue

                if files_probably_equal(src, dst) and src in self._last_md5:
                    continue

                src_md5 = md5_file(src)
                last = self._last_md5.get(src)
                if last == src_md5 and files_probably_equal(src, dst):
                    continue

                try:
                    dst_md5 = md5_file(dst)
                except Exception:
                    dst_md5 = ""

                if src_md5 != dst_md5:
                    copy2_logged(self.logger, self.locked, src, dst, "md5_scan update")

                self._last_md5[src] = src_md5
            except Exception as e:
                log_action(self.logger, "COPY", f"MD5 SCAN file error: {src} | {e}", path=src, is_dir=False, level=logging.ERROR)

        when = dt.datetime.now()
        for dst in sorted(self.update_root.rglob("*"), reverse=True):
            if self.stop_event.is_set():
                return
            try:
                rel = dst.resolve().relative_to(self.update_root.resolve())
                if rel.parts and rel.parts[0] == ".bak":
                    continue

                src_equiv = (self.monitor_root / rel).resolve()
                if src_equiv.exists():
                    is_dir = src_equiv.is_dir()
                    if not self.ignore.is_ignored(src_equiv, is_dir=is_dir):
                        continue

                soft_delete(self.logger, self.locked, self.update_root, dst, "md5_scan extra/ignored", when=when)
            except Exception as e:
                log_action(self.logger, "SOFT_DELETE_FAIL", f"MD5 SCAN cleanup error: {dst} | {e}", path=dst, is_dir=dst.is_dir(), level=logging.ERROR)


# -------------------------
# Main
# -------------------------

def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    cfg = build_effective_config(args)

    logger = setup_logger(cfg.log_dir)

    try:
        monitor, update = validate_paths(cfg.monitor_dir, cfg.update_dir)
        logger.info("Monitor: %s", monitor)
        logger.info("Update : %s", update)
    except Exception as e:
        logger.error("Config error: %s", e)
        return 2

    try:
        save_config_file(monitor, update, cfg.log_dir.expanduser().resolve(), float(cfg.scan_interval_sec))
        logger.info("Saved config: %s", CONFIG_PATH)
    except Exception as e:
        logger.error("Could not save config: %s", e)

    locked = LockedFileTracker((cfg.log_dir.expanduser().resolve()) / "locked.log", hold_hours=LOCK_HOLD_HOURS)
    ignore = IgnoreMatcher(monitor_root=monitor, patterns=GITIGNORE_PATTERNS)

    full_sync(monitor, update, ignore, logger, locked)

    handler = MirrorHandler(monitor, update, ignore, logger, locked)
    observer = Observer()
    observer.schedule(handler, str(monitor), recursive=True)

    stop_event = threading.Event()
    scanner = Md5Scanner(
        monitor_root=monitor,
        update_root=update,
        ignore=ignore,
        interval_sec=cfg.scan_interval_sec,
        logger=logger,
        stop_event=stop_event,
        locked=locked,
    )

    logger.info("Starting watcher... (Ctrl+C to stop)")
    observer.start()
    scanner.start()

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        logger.info("Stopping...")
    finally:
        stop_event.set()
        observer.stop()
        observer.join(timeout=10)
        scanner.join(timeout=10)
        logger.info("Stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
