#!/usr/bin/env python3


'''
Author: Security Research Team TRURisk Mitigate
Mitigation: Harden PHP session upload-progress handling for the affected
application only, across every configuration location PHP honours.

Vulnerability:
PHP's session upload-progress feature tracks the state of in-flight file
uploads inside the user's session. When it is enabled the upload path can be
abused (session data growth / manipulation of session state driven purely by
unauthenticated multipart uploads). Disabling the feature and forcing session
identifiers to be carried only in cookies removes the exposed surface.

Settings enforced:
    session.upload_progress.enabled -> disabled (Off)   [session, per-directory]
    session.use_only_cookies        -> enabled  (On)    [session, per-directory]
    memory_limit                    -> -1               [engine, php.ini + pool]
    expose_php                      -> 0                [engine, php.ini + pool]
    fatal_error_backtraces          -> 0                [engine, php.ini + pool]
    post_max_size                   -> <= 32M           [engine, php.ini + pool]
                                       (above 32M, 0 = unlimited, or malformed
                                        is rewritten to 32M; 30M stays 30M)
    upload_max_filesize             -> < post_max_size  [per runtime + pool]
                                       (lowered to 1M under post_max_size)

Where they are applied:
    1. php.ini files (shared SAPI baseline) get the session directives plus
       the engine directives. conf.d drop-ins load after php.ini and override
       it, so every scan directory is found (php --ini, php-fpm -i for each
       build, PHP_INI_SCAN_DIR/PHPRC of running masters, known layouts) and
       any drop-in line that sets an enforced directive to a non-compliant
       value is rewritten in place with a revert marker. Drop-ins that do not
       mention an enforced directive are never touched. Debian conf.d entries
       are symlinks into mods-available, so the shared target is edited.
    2. The affected PHP-FPM pool only (selected by --PORT matching the pool
       'listen'); flags use php_admin_flag, values use php_admin_value.
    3. Existing per-directory files under the affected pool's document root get
       only the per-directory-valid session directives:
           .user.ini : session.upload_progress.enabled = Off
                       session.use_only_cookies = On
           .htaccess : php_flag session.upload_progress.enabled Off
                       php_flag session.use_only_cookies On
       .user.ini / .htaccess are never created, only edited. A .htaccess is only
       touched when it already carries php_* directives, and new lines are placed
       inside the same <IfModule> block as the existing php_* directives so they
       never become unguarded. Symlinked per-directory files are skipped.

Scoping:
    Pool and per-directory changes are restricted to the pool whose 'listen'
    matches --PORT. --SERVICE is accepted for compatibility and ignored.

Service restart:
    Before any restart every running php-fpm master and every Apache master
    with mod_php loaded is config-tested (php-fpm -t / apachectl configtest).
    A failed test during mitigation restores the original files and leaves the
    services untouched. Active systemd units are restarted; masters outside a
    restarted unit are signalled directly (php-fpm: SIGUSR2, Apache: SIGHUP)
    through a pidfd where available, after re-validating the process identity.
    Success requires that every PHP worker on the host started after the
    restart; any older worker means stale state remains and the run FAILS.

Backup model:
    A single backup manifest is written to /root/ capturing the exact original
    bytes (base64) of every file about to be modified. It is written atomically
    and flagged immutable (best effort, chattr +i). Rollback restores from the
    manifest; if the manifest is missing or unreadable it falls back to the
    inline revert markers. Rollback runs whenever a backup or markers exist,
    including after a partial or failed mitigation.

Concurrency and file safety:
    mitigate and rollback hold an exclusive lock for the whole run. Every file
    write goes to a temporary file in the same directory (owner, mode and
    extended attributes copied), is fsync'd and renamed into place, so readers
    never see a partial file. A file that changed since it was read is not
    overwritten. Line endings and non-UTF-8 bytes are preserved.

Usage:
    phpdisupldprogress_rollback.py   (no arguments; runs the rollback and exits)
'''

import argparse
import base64
import errno
import fcntl
import glob
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from functools import lru_cache


SUCCESS = 0
FAILURE = 1
SKIP = 101
UNMITIGATE = 201
EXISTS = 33

# Internal (never used as exit codes).
CORRUPT = -1           # backup manifest unreadable -> fall back to markers
CONFIG_INVALID = -2    # config test failed -> nothing was restarted


# --------------------- MITIGATION DEFINITION ---------------------
# post_max_size: any value in (0, POST_MAX_CAP] is compliant (advisory: 8M
# without uploads, 32M with). Values above the cap, 0 (= unlimited) or
# unparseable are rewritten to the cap.
POST_MAX_CAP = "32M"
# upload_max_filesize must stay below the post_max_size in force; when it is
# not, it is lowered to 1M under that value (PHP default when unset: 2M).
UPLOAD_KEY = "upload_max_filesize"
PHP_DEFAULT_UPLOAD = "2M"
INI_GROUPS = []   # per PHP runtime: [php.ini, drop-ins...] in load order (set by discovery)

# Each directive is (key, value_to_write, mode, desired_bool).
#   mode "bool"  -> state compared with _norm_bool() against desired_bool
#   mode "exact" -> value compared literally; desired_bool is unused (None)
_SESSION_INI = [
    ("session.upload_progress.enabled", "Off", "bool", False),
    ("session.use_only_cookies", "On", "bool", True),
]
_ENGINE_INI = [
    ("memory_limit", "-1", "exact", None),
    ("expose_php", "0", "exact", None),
    ("fatal_error_backtraces", "0", "exact", None),
    ("post_max_size", POST_MAX_CAP, "max_bytes", None),
]

INI_DIRECTIVES = _SESSION_INI + _ENGINE_INI
USERINI_DIRECTIVES = _SESSION_INI

POOL_DIRECTIVES = [
    ("php_admin_flag[session.upload_progress.enabled]", "off", "bool", False),
    ("php_admin_flag[session.use_only_cookies]", "on", "bool", True),
    ("php_admin_value[memory_limit]", "-1", "exact", None),
    ("php_admin_value[expose_php]", "0", "exact", None),
    ("php_admin_value[fatal_error_backtraces]", "0", "exact", None),
    ("php_admin_value[post_max_size]", POST_MAX_CAP, "max_bytes", None),
]

HTACCESS_DIRECTIVES = _SESSION_INI   # .htaccess carries the same two session flags
HTACCESS_KEYWORDS = ("php_flag", "php_value", "php_admin_flag", "php_admin_value")

BACKUP_PATH = "/root/phpdisupldprogress.qlys.bak"
BACKUP_VERSION = 2

LOCK_NAME = "phpdisupldprogress.qlys.lock"
LOCK_DIRS = ("/run/lock", "/run", "/var/lock")
LOCK_TIMEOUT = 120          # seconds to wait for another run to finish

CMD_TIMEOUT = 60            # default timeout for external commands
RESTART_TIMEOUT = 180       # systemctl restart can wait on process_control_timeout
WORKER_FRESH_TIMEOUT = 90   # time allowed for every worker to be replaced
START_SLACK = 0.5           # seconds of clock slack when comparing start times

# Inline revert markers. A marker always sits directly above the directive it
# governs. New ADDED markers carry the key ("QLYS_UPLDPROG_ADDED:<key>") so the
# governed line can be validated on revert; legacy key-less markers still work.
TAG_MODIFIED = "QLYS_UPLDPROG_ORIG:"
TAG_ADDED = "QLYS_UPLDPROG_ADDED"

PHP_INI_NAME = "php.ini"
HIGH_PRIORITY_GLOBS = [
    "/etc/php.ini",
    "/etc/php/*/fpm/php.ini",
    "/etc/php/*/apache2/php.ini",
    "/etc/php/*/cli/php.ini",
    "/etc/php/*/php.ini",
    "/etc/php*/php.ini",
    "/usr/local/etc/php/php.ini",
    "/usr/local/lib/php.ini",
    "/opt/remi/*/root/etc/php.ini",
]
FALLBACK_TOP_DIRS = ["/etc", "/usr/local", "/opt", "/srv", "/app"]
EXCLUDED_DIRS = {"proc", "sys", "dev", "run", ".git", "node_modules",
                 "vendor", "__pycache__", "site-packages"}

# conf.d scan directories (in addition to what the PHP binaries report)
SCAN_DIR_GLOBS = [
    "/etc/php/*/*/conf.d",
    "/etc/php.d",
    "/etc/php*/conf.d",
    "/usr/local/etc/php/conf.d",
    "/opt/remi/*/root/etc/php.d",
    "/etc/opt/remi/*/php.d",
]
FPM_BIN_GLOBS = [
    "/usr/sbin/php-fpm*",
    "/usr/local/sbin/php-fpm*",
    "/opt/remi/*/root/usr/sbin/php-fpm",
]

POOL_GLOBS = [
    "/etc/php/*/fpm/pool.d/*.conf",
    "/etc/php/fpm/pool.d/*.conf",
    "/etc/php-fpm.d/*.conf",
    "/etc/php*/php-fpm.d/*.conf",
    "/usr/local/etc/php-fpm.d/*.conf",
    "/usr/local/etc/php/php-fpm.d/*.conf",
]

USER_INI_NAME = ".user.ini"
HTACCESS_NAME = ".htaccess"

DOCROOT_DENY = {"/", "/usr", "/bin", "/sbin", "/etc", "/var", "/lib", "/lib64",
                "/proc", "/sys", "/dev", "/run", "/boot", "/opt", "/srv", "/home",
                "/root", "/tmp", "/mnt", "/media"}

_SECTION_RE = re.compile(r'^\s*\[([^\]]+)\]\s*$')
_LINE_RE = re.compile(r'[^\n]*\n|[^\n]+\Z')
_KEY_RE = re.compile(r'^\s*(?:php_(?:admin_)?(?:flag|value)\s+)?([^\s=]+)', re.IGNORECASE)
_IFMOD_OPEN_RE = re.compile(r'^\s*<IfModule\b', re.IGNORECASE)
_IFMOD_CLOSE_RE = re.compile(r'^\s*</IfModule\s*>', re.IGNORECASE)
_HT_PHP_RE = re.compile(r'^\s*(' + "|".join(HTACCESS_KEYWORDS) + r')\s+', re.IGNORECASE)

# Process identification by executable (via /proc/<pid>/exe, not argv text).
FPM_EXE_RE = re.compile(r'^php[\d.]*-fpm[\d.]*$', re.IGNORECASE)
APACHE_EXE_RE = re.compile(r'^(httpd|apache2)(\.\w+)?$', re.IGNORECASE)
_FPM_CONF_RE = re.compile(r'master process \(([^)]+)\)')
_FPM_CONF_ARG_RE = re.compile(r'(?:--fpm-config|\s-y)\s+(\S+)')

try:
    _CLK_TCK = os.sysconf("SC_CLK_TCK")
except (AttributeError, ValueError, OSError):
    _CLK_TCK = 100

TARGET_SERVICE = None   # accepted for compatibility; not used for scoping
AFFECTED_PORT = None
_LOCK_FD = None


# --------------------- LOGGING FUNCTION ---------------------
_LOG_SYMBOLS = {0: "[x]", 1: "[+]", 2: "[!]", 3: "[i]"}
_LOG_LOCK = threading.Lock()   # discovery logs from worker threads; one write per line


def log_enh(status_code, function_name, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    symbol = _LOG_SYMBOLS.get(status_code, "[-]")
    message = " ".join(str(message).split())
    if not message:
        return
    line = f"[{timestamp}] Function Name: {function_name} | Msg: {symbol} {message}\n"
    with _LOG_LOCK:
        sys.stdout.write(line)
        sys.stdout.flush()


def _run_parallel(fn, items, limit=8):
    '''map(fn, items) on a thread pool, results in input order.'''
    items = list(items)
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=min(limit, len(items))) as pool:
        return list(pool.map(fn, items))


# --------------------- COMMAND HELPER ---------------------
def run_cmd(cmd, timeout=CMD_TIMEOUT):
    '''Runs a command and returns (returncode, stdout, stderr). Never raises.'''
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, timeout=timeout)
        return result.returncode, (result.stdout or "").strip(), (result.stderr or "").strip()
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"
    except Exception as e:
        return 1, "", str(e)


# --------------------- Check Root Permission ---------------------
def check_root():
    _fn = "check_root"
    try:
        log_enh(3, _fn, "Checking root permission")
        if not hasattr(os, "geteuid"):
            log_enh(2, _fn, "os.geteuid() unavailable on this platform; skipping root check")
            return SUCCESS
        if os.geteuid() != 0:
            log_enh(0, _fn, "This script must be run as root")
            return FAILURE
        log_enh(1, _fn, "Script is running with root privilege")
        return SUCCESS
    except Exception as e:
        log_enh(0, _fn, f"Error checking root permission: {str(e)}")
        return FAILURE


# --------------------- RUN LOCK ---------------------
def acquire_lock(timeout=LOCK_TIMEOUT):
    '''Take an exclusive flock for the whole run so concurrent mitigate/rollback
    invocations cannot interleave their read-modify-write cycles. The lock is
    released by the kernel when the process exits.'''
    global _LOCK_FD
    _fn = "acquire_lock"
    lock_dir = next((d for d in LOCK_DIRS if os.path.isdir(d)), None)
    if lock_dir is None:
        log_enh(0, _fn, f"No lock directory available (tried {', '.join(LOCK_DIRS)})")
        return FAILURE
    path = os.path.join(lock_dir, LOCK_NAME)
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600)
    except OSError as e:
        log_enh(0, _fn, f"Cannot open lock file {path}: {str(e)}")
        return FAILURE
    deadline = time.monotonic() + timeout
    waited = False
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if not waited:
                log_enh(2, _fn, f"Another run holds {path}; waiting up to {timeout}s")
                waited = True
            if time.monotonic() >= deadline:
                log_enh(0, _fn, f"Timed out waiting for lock {path}")
                os.close(fd)
                return FAILURE
            time.sleep(1)
        except OSError as e:
            log_enh(0, _fn, f"Cannot lock {path}: {str(e)}")
            os.close(fd)
            return FAILURE
    try:
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode("ascii"))
    except OSError:
        pass  # PID in the lock file is diagnostic only
    _LOCK_FD = fd
    log_enh(1, _fn, f"Acquired run lock {path}")
    return SUCCESS


# --------------------- ENVIRONMENT INFO (single line) ---------------------
def _os_pretty_name():
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except Exception:
        pass
    return "Unknown"


_CLI_CACHE = {}


def _cli_query(args):
    '''Result of a fixed php CLI query. `php -v` and `php --ini` run together
    in one parallel batch the first time either is needed.'''
    if not _CLI_CACHE:
        cmds = (("php", "-v"), ("php", "--ini"))
        for c, r in zip(cmds, _run_parallel(run_cmd, [list(c) for c in cmds])):
            _CLI_CACHE[c] = r
    return _CLI_CACHE[tuple(args)]


def _php_version():
    rc, out, _ = _cli_query(("php", "-v"))
    if rc == 0 and out:
        return " ".join(out.splitlines()[0].strip().split())
    return "not-detected"


def print_environment():
    _fn = "print_environment"
    parts = [f"OS={_os_pretty_name()}"]
    try:
        u = os.uname()
        parts.append(f"Kernel={u.sysname} {u.release}")
        parts.append(f"Arch={u.machine}")
        parts.append(f"Host={u.nodename}")
    except Exception:
        try:
            import socket
            parts.append(f"Host={socket.gethostname()}")
        except Exception:
            pass
    parts.append(f"PHP={_php_version()}")
    if TARGET_SERVICE:
        parts.append(f"Service={TARGET_SERVICE}(ignored)")
    if AFFECTED_PORT:
        parts.append(f"Port={AFFECTED_PORT}")
    log_enh(3, _fn, "Environment: " + " | ".join(parts))


# --------------------- SAFE FILE I/O ---------------------
def _read_raw(path):
    '''Read a regular file without following a final symlink.
    Returns (bytes, stat_result). Raises OSError.'''
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EINVAL, "not a regular file", path)
        return f.read(), st


def _split_lines(text):
    '''Split into lines that keep their own line ending, so joining them gives
    the original bytes back. A missing final newline is added so lines can be
    appended safely. A UTF-8 BOM (which PHP strips before parsing) is kept as
    its own leading element so the first real line still matches.
    Returns (lines, newline_used_for_new_lines).'''
    bom = ""
    if text.startswith("﻿"):
        bom, text = "﻿", text[1:]
    lines = _LINE_RE.findall(text)
    nl = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += nl
    if bom:
        lines.insert(0, bom)
    return lines, nl


def _read_lines(path):
    '''Returns (lines, newline, stat_result). Undecodable bytes survive the
    round trip via surrogateescape. Raises OSError.'''
    data, st = _read_raw(path)
    lines, nl = _split_lines(data.decode("utf-8", "surrogateescape"))
    return lines, nl, st


def _copy_xattrs(src, dst_fd):
    '''Copy extended attributes (SELinux label, ACLs) onto the replacement file.'''
    if not hasattr(os, "listxattr"):
        return
    try:
        names = os.listxattr(src, follow_symlinks=False)
    except OSError:
        return
    for name in names:
        try:
            os.setxattr(dst_fd, name, os.getxattr(src, name, follow_symlinks=False))
        except OSError as e:
            log_enh(2, "_copy_xattrs", f"Could not copy xattr {name} for {src}: {str(e)}")


def _atomic_write(path, data, expected=None, new_mode=0o644):
    '''Replace path with data atomically: temp file in the same directory,
    owner/mode/xattrs copied, fsync, rename, fsync directory.
    Refuses symlinks and non-regular files. When expected (a stat_result from
    the read) is given, refuses to overwrite a file that changed since.'''
    _fn = "_atomic_write"
    directory = os.path.dirname(os.path.abspath(path))
    try:
        cur = os.lstat(path)
    except FileNotFoundError:
        cur = None
    except OSError as e:
        log_enh(0, _fn, f"Cannot stat {path}: {str(e)}")
        return FAILURE
    if cur is not None and not stat.S_ISREG(cur.st_mode):
        log_enh(0, _fn, f"Refusing to write {path}: not a regular file (symlink or special)")
        return FAILURE
    if expected is not None and (cur is None or
                                 (cur.st_ino, cur.st_size, cur.st_mtime_ns) !=
                                 (expected.st_ino, expected.st_size, expected.st_mtime_ns)):
        log_enh(0, _fn, f"Refusing to write {path}: it changed after it was read")
        return FAILURE
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(prefix=".qlys-", suffix=".tmp", dir=directory)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            if cur is not None:
                os.fchown(f.fileno(), cur.st_uid, cur.st_gid)   # before chmod: chown clears setid bits
                os.fchmod(f.fileno(), stat.S_IMODE(cur.st_mode))
                _copy_xattrs(path, f.fileno())
            else:
                os.fchmod(f.fileno(), new_mode)
            os.fsync(f.fileno())
        os.replace(tmp, path)
        tmp = None
        dfd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        return SUCCESS
    except Exception as e:
        log_enh(0, _fn, f"Error writing {path}: {str(e)}")
        return FAILURE
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _write_lines(path, lines, expected):
    _fn = "_write_lines"
    rc = _atomic_write(path, "".join(lines).encode("utf-8", "surrogateescape"), expected)
    if rc == SUCCESS:
        log_enh(1, _fn, f"Updated {path}")
    return rc


# --------------------- VALUE / INI HELPERS ---------------------
def _norm_bool(value):
    v = value.strip().strip('"').strip("'").lower()
    if v in ("1", "on", "true", "yes"):
        return True
    if v in ("0", "off", "false", "no", ""):
        return False
    return None


_BYTES_RE = re.compile(r'^(\d+)\s*([kmg]?)$')
_BYTE_UNITS = {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30}


def _php_bytes(value):
    '''Parse PHP shorthand byte notation (8M, 8192K, 8388608). None when
    absent or malformed.'''
    if value is None:
        return None
    m = _BYTES_RE.match(value.strip().strip('"').strip("'").lower())
    return int(m.group(1)) * _BYTE_UNITS[m.group(2)] if m else None


def _fmt_bytes(n):
    if n % (1 << 20) == 0:
        return f"{n >> 20}M"
    if n % (1 << 10) == 0:
        return f"{n >> 10}K"
    return str(n)


def _below(limit):
    '''A value 1M under limit (half of it for limits of 2M or less).'''
    return limit - (1 << 20) if limit > (2 << 20) else max(1, limit // 2)


def _wval(val, mode, desired):
    '''Value written for a directive: for max_bytes, desired may carry a
    specific compliant value to write instead of the cap itself.'''
    return desired if mode == "max_bytes" and desired else val


def _dir_ok(eff, val, mode, desired):
    '''True when an effective value satisfies a directive.
       bool      -> boolean equals desired
       exact     -> string equals val
       max_bytes -> 0 < bytes <= val          (val in shorthand, e.g. 32M)
       lt_bytes  -> 0 < bytes < desired       (desired in bytes)'''
    if eff is None:
        return False
    if mode == "bool":
        return _norm_bool(eff) == desired
    if mode == "max_bytes":
        b = _php_bytes(eff)
        return b is not None and 0 < b <= _php_bytes(val)
    if mode == "lt_bytes":
        b = _php_bytes(eff)
        return b is not None and 0 < b < desired
    return eff.strip().strip('"').strip("'").lower() == str(val).strip().lower()


def _is_comment(line, hash_only=False):
    '''Blank or comment line: ";" or "#" for ini/pool files, "#" only for .htaccess.'''
    s = line.strip()
    return not s or s.startswith("#") or (not hash_only and s.startswith(";"))


@lru_cache(maxsize=None)
def _key_regex(key):
    return re.compile(r'^\s*' + re.escape(key) + r'\s*=(.*)$')


def _compile(directives):
    return [(key, val, mode, desired, _key_regex(key)) for key, val, mode, desired in directives]


def _effective_value(lines, key):
    '''Return the effective (last uncommented) value string for key, else None.'''
    pat = _key_regex(key)
    value = None
    for line in lines:
        if _is_comment(line):
            continue
        m = pat.match(line)
        if m:
            value = m.group(1).split(";", 1)[0].strip()
    return value


def _pool_sections(lines):
    '''Return a list of (name, start_idx, end_idx_exclusive) for each section.'''
    sections = []
    name = None
    start = None
    for i, line in enumerate(lines):
        m = _SECTION_RE.match(line)
        if m:
            if name is not None:
                sections.append((name, start, i))
            name = m.group(1)
            start = i + 1
    if name is not None:
        sections.append((name, start, len(lines)))
    return sections


@lru_cache(maxsize=None)
def _htaccess_regex(setting):
    return re.compile(r'^(\s*)(' + "|".join(HTACCESS_KEYWORDS) + r')\s+'
                      + re.escape(setting) + r'\s+(\S+)\s*$', re.IGNORECASE)


def _htaccess_effective(lines, setting):
    '''Return effective boolean for a php setting in .htaccess, else None.'''
    pat = _htaccess_regex(setting)
    value = None
    for line in lines:
        if _is_comment(line, hash_only=True):
            continue
        m = pat.match(line)
        if m:
            value = m.group(3)
    if value is None:
        return None
    return _norm_bool(value)


def _htaccess_has_php(lines):
    return any(_HT_PHP_RE.match(line) for line in lines if not _is_comment(line, hash_only=True))


def _htaccess_insert_point(lines):
    '''Locate where new php_* lines must go so they share the guard of the
    first existing php_* directive. Returns (index, indent): insert before
    lines[index]; index None means append at end of file (the existing php_*
    directives are unguarded, so mod_php is already required).'''
    stack = []
    target = None
    indent = ""
    for idx, line in enumerate(lines):
        if _is_comment(line, hash_only=True):
            continue
        if _IFMOD_OPEN_RE.match(line):
            stack.append(idx)
            continue
        if _IFMOD_CLOSE_RE.match(line):
            opened = stack.pop() if stack else None
            if target is not None and opened == target:
                return idx, indent
            continue
        if target is None and _HT_PHP_RE.match(line):
            indent = line[:len(line) - len(line.lstrip())]
            if not stack:
                return None, indent
            target = stack[-1]
    return None, indent


# --------------------- DISCOVERY: php.ini + conf.d scan dirs ---------------------
def _report_value(line):
    '''Value part of a `php --ini` ("Key: value") or `php-fpm -i` ("Key => value") line.'''
    if "=>" in line:
        val = line.split("=>", 1)[1]
    elif ":" in line:
        val = line.split(":", 1)[1]
    else:
        return None
    val = val.strip()
    return None if not val or val.lower() == "(none)" else val


def _parse_ini_report(text):
    '''Extract (loaded_php_ini, [scan_dirs]) from `php --ini` / `php-fpm -i` output.'''
    loaded, scans = None, []
    for line in text.splitlines():
        low = line.lower()
        if "loaded configuration file" in low:
            loaded = _report_value(line)
        elif "scan for additional .ini files in" in low or "scan this dir for additional .ini files" in low:
            val = _report_value(line)
            if val:
                scans.extend(d for d in val.split(os.pathsep) if d)
    return loaded, scans


def _proc_environ(pid):
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            raw = f.read()
    except OSError:
        return {}
    env = {}
    for item in raw.split(b"\0"):
        k, sep, v = item.partition(b"=")
        if sep:
            env[k.decode("utf-8", "replace")] = v.decode("utf-8", "replace")
    return env


def _ini_sources(masters):
    '''Ask every PHP binary (CLI and each php-fpm build) which php.ini it loads
    and which directories it scans for additional .ini files, and read
    PHP_INI_SCAN_DIR / PHPRC from the environment of every running PHP master.
    Binaries are queried in parallel.
    Returns (php_inis, scan_dirs, source_of, reports) where reports is a list
    of (loaded_php_ini, [scan_dirs], is_fpm) per binary.'''
    _fn = "_ini_sources"
    bins = set()
    for pattern in FPM_BIN_GLOBS:
        for b in glob.glob(pattern):
            if FPM_EXE_RE.match(os.path.basename(b)) and os.access(b, os.X_OK):
                bins.add(os.path.realpath(b))
    for m in masters:
        if m["family"] == "fpm" and os.path.isfile(m["exe"]):
            bins.add(os.path.realpath(m["exe"]))
    fpm_cmds = [[b, "-i"] for b in sorted(bins)]
    cmds = [["php", "--ini"]] + fpm_cmds
    results = [_cli_query(("php", "--ini"))] + _run_parallel(run_cmd, fpm_cmds)

    inis, scans, source_of = [], [], {}

    def _keep(lst, path, src):
        if path and path not in lst:
            lst.append(path)
            source_of.setdefault(path, src)

    reports = []
    for cmd, (rc, out, _err) in zip(cmds, results):
        if rc != 0 or not out:
            continue
        loaded, dirs = _parse_ini_report(out)
        reports.append((loaded, dirs, cmd[-1] == "-i"))   # "-i" = a php-fpm build
        src = " ".join(cmd)
        _keep(inis, loaded, src)
        for d in dirs:
            _keep(scans, d, src)
    for m in masters:
        env = _proc_environ(m["pid"])
        src = f"environment of {m['family']} master PID {m['pid']}"
        for d in env.get("PHP_INI_SCAN_DIR", "").split(os.pathsep):
            _keep(scans, d, src)
        rc_path = env.get("PHPRC")
        if rc_path:
            _keep(inis, os.path.join(rc_path, PHP_INI_NAME) if os.path.isdir(rc_path) else rc_path, src)
    for d in scans:
        log_enh(3, _fn, f"PHP scans {d} for additional .ini files ({source_of[d]})")
    return inis, scans, source_of, reports


def _mentions_directive(path, compiled):
    '''True when path sets any of the directives on an uncommented line.'''
    try:
        lines, _nl, _st = _read_lines(path)
    except OSError as e:
        log_enh(2, "_mentions_directive", f"Could not read {path}: {str(e)}")
        return False
    return any(c[-1].match(line) for line in lines if not _is_comment(line) for c in compiled)


def find_dropins(scan_dirs, php_inis):
    '''Return conf.d drop-in files (realpaths) that set any enforced directive.
    PHP loads them after php.ini, so a non-compliant value in one of them wins
    over php.ini. Directories come from the binaries/environments queried in
    _ini_sources(), the known layout globs, and a conf.d beside each php.ini.
    Debian conf.d entries are symlinks into mods-available (shared by every
    SAPI); the shared target file is what gets edited.'''
    _fn = "find_dropins"
    dirs = list(scan_dirs)
    for pattern in SCAN_DIR_GLOBS:
        dirs.extend(glob.glob(pattern))
    dirs.extend(os.path.join(os.path.dirname(p), "conf.d") for p in php_inis)

    # upload_max_filesize counts too: a drop-in that sets only it can break the
    # upload_max_filesize < post_max_size rule and must be backed up / fixable.
    compiled = _compile(INI_DIRECTIVES + [(UPLOAD_KEY, "", "exact", None)])
    exclude = set(php_inis)
    seen_dirs, found = set(), []
    for d in dirs:
        rd = os.path.realpath(d)
        if rd in seen_dirs or not os.path.isdir(rd):
            continue
        seen_dirs.add(rd)
        try:
            names = sorted(os.listdir(rd))     # PHP loads drop-ins in this order
        except OSError as e:
            log_enh(2, _fn, f"Cannot list {rd}: {str(e)}")
            continue
        for name in names:
            if not name.endswith(".ini"):
                continue
            link = os.path.join(rd, name)
            rp = os.path.realpath(link)
            if rp in exclude or rp in found or not os.path.isfile(rp):
                continue
            if _mentions_directive(rp, compiled):
                found.append(rp)
                log_enh(1, _fn, f"Drop-in sets an enforced directive: {link}"
                                + ("" if rp == link else f" -> {rp}"))
    return found


def _add_real(found, path):
    '''Add realpath(path) to the ordered map when it is a new regular file.
    Returns the realpath when added, else None.'''
    try:
        rp = os.path.realpath(path)
    except Exception:
        rp = path
    if os.path.isfile(rp) and rp not in found:
        found[rp] = True
        return rp
    return None


def _walk_tree(top):
    '''One pass over a config tree collecting php.ini files and pool.d /
    php-fpm.d *.conf files, in walk order.'''
    _fn = "_walk_tree"
    inis, pools = [], []
    if not os.path.isdir(top):
        return inis, pools
    try:
        for root, dirs, files in os.walk(top):
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
            if PHP_INI_NAME in files:
                inis.append(os.path.join(root, PHP_INI_NAME))
            if os.path.basename(root).lower() in ("pool.d", "php-fpm.d"):
                pools.extend(os.path.join(root, f) for f in files if f.endswith(".conf"))
    except PermissionError:
        log_enh(2, _fn, f"Permission denied while walking {top}")
    except Exception as e:
        log_enh(2, _fn, f"Error walking {top}: {str(e)}")
    return inis, pools


def _walk_config_trees():
    '''Walk every FALLBACK_TOP_DIRS tree once, one thread per tree. Returns
    (php_ini_paths, pool_conf_paths) in the same order a sequential walk gives.'''
    results = _run_parallel(_walk_tree, FALLBACK_TOP_DIRS)
    return [p for inis, _ in results for p in inis], [p for _, pools in results for p in pools]


def find_php_inis(reported, walked):
    '''Discover every php.ini on the host. Returns a de-duplicated list.'''
    _fn = "find_php_inis"
    log_enh(3, _fn, "Discovering php.ini files (shared SAPI baseline)")
    found = OrderedDict()
    sources = [(p, "reported by PHP") for p in reported]
    sources += [(p, "known-path") for pattern in HIGH_PRIORITY_GLOBS for p in glob.glob(pattern)]
    sources += [(p, "filesystem-walk") for p in walked]
    for p, source in sources:
        rp = _add_real(found, p)
        if rp:
            log_enh(1, _fn, f"Discovered php.ini ({source}): {rp}")
    return list(found.keys())


# --------------------- PROCESS DISCOVERY (/proc, no ps dependency) ---------------------
def _read_stat(pid):
    '''Return (ppid, starttime_ticks) for pid, or None if it is gone/unreadable.'''
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            data = f.read().decode("ascii", "replace")
        rest = data[data.rindex(")") + 2:].split()
        return int(rest[1]), int(rest[19])
    except (OSError, ValueError, IndexError):
        return None


def _proc_exe(pid):
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return None
    suffix = " (deleted)"   # binary replaced by a package upgrade
    return exe[:-len(suffix)] if exe.endswith(suffix) else exe


def _proc_cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
    except OSError:
        return ""


def _family(exe):
    base = os.path.basename(exe)
    if FPM_EXE_RE.match(base):
        return "fpm"
    if APACHE_EXE_RE.match(base):
        return "apache"
    return None


def _has_mod_php(pid):
    try:
        with open(f"/proc/{pid}/maps", "r", errors="replace") as f:
            return any("libphp" in line for line in f)
    except OSError:
        return False


def _php_processes():
    '''Scan /proc once. Returns (masters, workers) for php-fpm and for Apache
    instances that have mod_php loaded. A process is identified by its
    executable, never by argv text, so editors, log tailers or exporters whose
    arguments mention php-fpm are never matched.
    Each entry: {pid, ppid, start, exe, family}.'''
    procs = {}
    try:
        names = os.listdir("/proc")
    except OSError:
        return [], []
    for name in names:
        if not name.isdigit():
            continue
        pid = int(name)
        exe = _proc_exe(pid)
        if not exe:
            continue
        fam = _family(exe)
        if fam is None:
            continue
        st = _read_stat(pid)
        if st is None:
            continue
        procs[pid] = {"pid": pid, "ppid": st[0], "start": st[1], "exe": exe, "family": fam}

    masters, workers = [], []
    for p in procs.values():
        parent = procs.get(p["ppid"])
        if parent is not None and parent["family"] == p["family"]:
            workers.append(p)
        else:
            masters.append(p)
    php_apache = {m["pid"] for m in masters if m["family"] == "apache" and _has_mod_php(m["pid"])}
    masters = [m for m in masters if m["family"] == "fpm" or m["pid"] in php_apache]
    workers = [w for w in workers if w["family"] == "fpm" or w["ppid"] in php_apache]
    return masters, workers


def _fpm_conf_of(master):
    args = _proc_cmdline(master["pid"])
    m = _FPM_CONF_RE.search(args) or _FPM_CONF_ARG_RE.search(args)
    if not m:
        return None
    cand = m.group(1).strip('"\'')
    return os.path.realpath(cand) if os.path.isfile(cand) else None


def _same_process(p):
    '''True when pid still belongs to the process we recorded (guards PID reuse).'''
    st = _read_stat(p["pid"])
    return st is not None and st[1] == p["start"] and _proc_exe(p["pid"]) == p["exe"]


def _signal_master(p, sig):
    '''Signal a recorded master. Pins the process with a pidfd when available
    (Linux 5.3+, Python 3.9+) and re-validates identity, so a reused PID is
    never signalled. Returns False only when the signal could not be sent.'''
    _fn = "_signal_master"
    pid = p["pid"]
    pidfd = None
    try:
        # Python 3.9+ / Linux 5.3+ only; guarded, so older versions use os.kill.
        if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
            try:
                pidfd = os.pidfd_open(pid)  # novermin
            except ProcessLookupError:
                raise
            except OSError:
                pidfd = None   # kernel without pidfd support; fall back to kill
        if not _same_process(p):
            log_enh(2, _fn, f"PID {pid} is no longer the recorded {p['family']} master; not signalled")
            return True
        if pidfd is not None:
            signal.pidfd_send_signal(pidfd, sig)  # novermin
        else:
            os.kill(pid, sig)
        log_enh(1, _fn, f"Sent {signal.Signals(sig).name} to {p['family']} master PID {pid} ({p['exe']})")
        return True
    except ProcessLookupError:
        log_enh(2, _fn, f"{p['family']} master PID {pid} exited before it could be signalled")
        return True
    except OSError as e:
        log_enh(0, _fn, f"Could not signal {p['family']} master PID {pid}: {str(e)}")
        return False
    finally:
        if pidfd is not None:
            os.close(pidfd)


def _boot_epoch():
    '''Wall-clock time of boot, matching the clock /proc/<pid>/stat starttime uses.'''
    for clk in ("CLOCK_BOOTTIME", "CLOCK_MONOTONIC"):
        cid = getattr(time, clk, None)
        if cid is None:
            continue
        try:
            return time.time() - time.clock_gettime(cid)
        except OSError:
            continue
    with open("/proc/stat") as f:
        for line in f:
            if line.startswith("btime "):
                return float(line.split()[1])
    raise OSError("cannot determine boot time")


def _stale_workers(cutoff):
    '''Workers (php-fpm children, mod_php Apache children) started before cutoff.'''
    boot = _boot_epoch()
    _, workers = _php_processes()
    return [w for w in workers if boot + w["start"] / _CLK_TCK < cutoff - START_SLACK]


def _wait_fresh_workers(cutoff, timeout=WORKER_FRESH_TIMEOUT):
    '''Wait until every PHP worker started after cutoff. Old workers keep the
    pre-change (vulnerable) state, so any survivor is a failure.'''
    _fn = "_wait_fresh_workers"
    deadline = time.monotonic() + timeout
    while True:
        stale = _stale_workers(cutoff)
        if not stale:
            log_enh(1, _fn, "Every PHP worker started after the restart")
            return True
        if time.monotonic() >= deadline:
            for w in stale:
                log_enh(0, _fn, f"Stale {w['family']} worker PID {w['pid']} (parent {w['ppid']}) "
                                f"predates the restart")
            return False
        time.sleep(1)


def _config_cutoff(targets):
    '''Newest mtime of the files that need a process restart to take effect.'''
    mtimes = []
    for t in targets:
        if t["kind"] in ("ini", "dropin", "pool"):
            try:
                mtimes.append(os.lstat(t["path"]).st_mtime)
            except OSError:
                continue
    return max(mtimes) if mtimes else None


# --------------------- DISCOVERY: affected FPM pool + docroots ---------------------
def _fpm_conf_files_from_processes(masters):
    '''Resolve php-fpm.conf paths from running (CLI or service) master processes.'''
    _fn = "_fpm_conf_files_from_processes"
    confs = {c for c in (_fpm_conf_of(m) for m in masters if m["family"] == "fpm") if c}
    for c in confs:
        log_enh(1, _fn, f"php-fpm master process is using config: {c}")
    return confs


def _pools_from_fpm_conf(conf_path):
    '''Parse a php-fpm.conf 'include=' directives into concrete pool files.'''
    pools = set()
    base = os.path.dirname(conf_path)
    try:
        with open(conf_path, "r") as f:
            lines = f.read().splitlines()
    except Exception:
        return pools
    for line in lines:
        s = line.strip()
        if _is_comment(s) or "=" not in s:
            continue
        key, val = s.split("=", 1)
        if key.strip().lower() != "include":
            continue
        pattern = val.split(";", 1)[0].strip().strip('"\'')
        if not pattern:
            continue
        if not os.path.isabs(pattern):
            pattern = os.path.join(base, pattern)
        for p in glob.glob(pattern):
            if os.path.isfile(p):
                pools.add(os.path.realpath(p))
    return pools


def find_fpm_pool_files(walked, masters):
    found = OrderedDict()
    for pattern in POOL_GLOBS:
        for p in glob.glob(pattern):
            _add_real(found, p)
    for p in walked:
        _add_real(found, p)
    for conf in _fpm_conf_files_from_processes(masters):
        _add_real(found, conf)
        for pool in _pools_from_fpm_conf(conf):
            _add_real(found, pool)
    return list(found.keys())


def _section_is_affected(seg):
    '''A pool section is affected when its 'listen' matches --PORT.'''
    if not AFFECTED_PORT:
        return False
    listen = _effective_value(seg, "listen")
    if not listen:
        return False
    port = str(AFFECTED_PORT).strip()
    token = listen.rsplit(":", 1)[-1].strip()
    return token == port or listen.strip() == port


def _docroots_from_seg(seg):
    '''Extract candidate application document roots from a pool section.'''
    cands = []
    for key in ("chdir", "php_admin_value[doc_root]", "php_value[doc_root]"):
        v = _effective_value(seg, key)
        if v:
            cands.append(v.strip())
    for key in ("php_admin_value[open_basedir]", "php_value[open_basedir]"):
        v = _effective_value(seg, key)
        if v:
            cands.append(v.split(":", 1)[0].strip())
    roots = []
    for c in cands:
        c = c.strip().strip('"').strip("'")
        if not c or c.lower() == "none":
            continue
        c = os.path.normpath(c)
        if c in DOCROOT_DENY:
            continue
        if os.path.isdir(c) and c not in roots:
            roots.append(c)
    return roots


def _find_perdir_files(docroot):
    '''Return (user_ini_paths, htaccess_paths) that already exist under docroot.
    Symlinks are skipped (a web user could point them at root-owned files).
    A .htaccess is included only when it already carries php_* directives.'''
    _fn = "_find_perdir_files"
    user_inis, htaccess = [], []
    try:
        for root, dirs, files in os.walk(docroot):
            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
            for fname in (USER_INI_NAME, HTACCESS_NAME):
                if fname not in files:
                    continue
                p = os.path.join(root, fname)
                if os.path.islink(p):
                    log_enh(2, _fn, f"Skipping symlinked {fname}: {p}")
                    continue
                if fname == USER_INI_NAME:
                    user_inis.append(p)
                    continue
                try:
                    lines, _nl, _st = _read_lines(p)
                except OSError as e:
                    log_enh(2, _fn, f"Could not read {p}: {str(e)}")
                    continue
                if _htaccess_has_php(lines):
                    htaccess.append(p)
                else:
                    log_enh(3, _fn, f"Skipping .htaccess without php_* directives: {p}")
    except PermissionError:
        log_enh(2, _fn, f"Permission denied while walking docroot {docroot}")
    except Exception as e:
        log_enh(2, _fn, f"Error walking docroot {docroot}: {str(e)}")
    return user_inis, htaccess


def _build_ini_groups(reports, php_inis, dropins):
    '''One group per PHP runtime: {"files": [php.ini, drop-ins...], "fpm": bool},
    files in PHP's load order (the last file that sets a key wins). A php.ini
    no binary reported is grouped with the conf.d beside it.'''
    dropin_set = set(dropins)
    groups, covered = [], set()

    def _put(files, fpm):
        for g in groups:
            if g["files"] == files:
                g["fpm"] = g["fpm"] or fpm
                return
        groups.append({"files": files, "fpm": fpm})

    def _dropins_in(dirs):
        out = []
        for d in dirs:
            rd = os.path.realpath(d)
            try:
                names = sorted(os.listdir(rd))
            except OSError:
                continue
            for n in names:
                if n.endswith(".ini"):
                    rp = os.path.realpath(os.path.join(rd, n))
                    if rp in dropin_set and rp not in out:
                        out.append(rp)
        return out

    for loaded, dirs, fpm in reports:
        if not loaded:
            continue
        ini = os.path.realpath(loaded)
        if ini not in php_inis:
            continue
        _put([ini] + _dropins_in(dirs), fpm)
        covered.add(ini)
    for ini in php_inis:
        if ini not in covered:
            _put([ini] + _dropins_in([os.path.join(os.path.dirname(ini), "conf.d")]), False)
    return groups


def _group_for_pool(pool_path):
    '''The FPM runtime a pool file most likely belongs to: among FPM groups
    (all groups when none is known to be FPM), the one whose php.ini shares
    the longest directory prefix with the pool file.'''
    cands = [g for g in INI_GROUPS if g["fpm"]] or INI_GROUPS
    best, best_len = None, -1
    for g in cands:
        try:
            n = len(os.path.commonpath([os.path.dirname(g["files"][0]), pool_path]))
        except ValueError:
            n = 0
        if n > best_len:
            best, best_len = g, n
    return best


# --------------------- DISCOVERY: assemble targets ---------------------
def discover_targets():
    '''Return a de-duplicated list of target dicts: {path, kind, sections}.
    kind in {ini, pool, userini, htaccess}.'''
    _fn = "discover_targets"
    targets = []
    seen = set()

    def _add(path, kind, sections=None):
        if path in seen:
            return
        seen.add(path)
        targets.append({"path": path, "kind": kind, "sections": sections})

    global INI_GROUPS
    masters, _ = _php_processes()            # one /proc scan for all of discovery
    walked_inis, walked_pools = _walk_config_trees()
    reported_inis, scan_dirs, _src, reports = _ini_sources(masters)
    php_inis = find_php_inis(reported_inis, walked_inis)
    for p in php_inis:
        _add(p, "ini")
    dropins = find_dropins(scan_dirs, php_inis)
    for p in dropins:
        _add(p, "dropin")
    INI_GROUPS = _build_ini_groups(reports, php_inis, dropins)

    docroots = []
    if AFFECTED_PORT:
        affected = {}
        for pf in find_fpm_pool_files(walked_pools, masters):
            try:
                lines, _nl, _st = _read_lines(pf)
            except OSError as e:
                log_enh(2, _fn, f"Could not read pool file {pf}: {str(e)}")
                continue
            for name, s, e in _pool_sections(lines):
                if name.lower() == "global":
                    continue
                seg = lines[s:e]
                if _section_is_affected(seg):
                    affected.setdefault(pf, set()).add(name)
                    for dr in _docroots_from_seg(seg):
                        if dr not in docroots:
                            docroots.append(dr)
                    log_enh(1, _fn, f"Affected FPM pool matched: [{name}] in {pf}")
        for pf, names in affected.items():
            _add(pf, "pool", names)
        if not affected:
            log_enh(2, _fn, "PORT provided but no FPM pool listens on it; "
                            "pool and per-directory changes will be skipped")
    else:
        log_enh(2, _fn, "No PORT provided; cannot scope to an application; "
                        "pool and per-directory changes will be skipped")

    for dr in docroots:
        log_enh(3, _fn, f"Scanning application document root: {dr}")
    for user_inis, htaccess in _run_parallel(_find_perdir_files, docroots):
        for p in user_inis:
            _add(p, "userini")
            log_enh(1, _fn, f"Affected .user.ini: {p}")
        for p in htaccess:
            _add(p, "htaccess")
            log_enh(1, _fn, f"Affected .htaccess: {p}")

    if not targets:
        log_enh(2, _fn, "No target files found on this host")
    else:
        log_enh(1, _fn, f"Total targets selected: {len(targets)}")
    return targets


# --------------------- PER-FILE STATE ---------------------
def _lines_for_state(path, fn, missing):
    '''(lines, None) for a readable file, else (None, state): `missing` when
    the file is absent, FAILURE (logged under fn) when it cannot be read.'''
    try:
        return _read_lines(path)[0], None
    except FileNotFoundError:
        return None, missing
    except OSError as e:
        log_enh(0, fn, f"Error reading {path}: {str(e)}")
        return None, FAILURE


def _ini_is_mitigated(path, directives):
    _fn = "_ini_is_mitigated"
    lines, state = _lines_for_state(path, _fn, UNMITIGATE)
    if lines is None:
        return state
    for key, val, mode, desired in directives:
        eff = _effective_value(lines, key)
        if not _dir_ok(eff, val, mode, desired):
            log_enh(3, _fn, f"{path}: {key} not set correctly -> not mitigated")
            return UNMITIGATE
    log_enh(3, _fn, f"{path}: all required directives set correctly")
    return EXISTS


def _dropin_is_mitigated(path):
    '''A drop-in is compliant when none of its uncommented lines sets an
    enforced directive to a non-compliant value. Absent directives are fine:
    php.ini supplies them.'''
    _fn = "_dropin_is_mitigated"
    lines, state = _lines_for_state(path, _fn, EXISTS)
    if lines is None:
        return state
    compiled = _compile(INI_DIRECTIVES)
    for line in lines:
        if _is_comment(line):
            continue
        for key, val, mode, desired, rx in compiled:
            m = rx.match(line)
            if m and not _dir_ok(m.group(1).split(";", 1)[0].strip(), val, mode, desired):
                log_enh(3, _fn, f"{path}: {key} overrides php.ini with a non-compliant value "
                                f"-> not mitigated")
                return UNMITIGATE
    log_enh(3, _fn, f"{path}: no non-compliant overrides")
    return EXISTS


def _pool_is_mitigated(path, sections):
    _fn = "_pool_is_mitigated"
    lines, state = _lines_for_state(path, _fn, UNMITIGATE)
    if lines is None:
        return state
    wanted = {n.lower() for n in (sections or set())}
    pools = [(n, s, e) for (n, s, e) in _pool_sections(lines) if n.lower() in wanted]
    if not pools:
        log_enh(3, _fn, f"{path}: affected pool section(s) not found -> not mitigated")
        return UNMITIGATE
    for name, s, e in pools:
        seg = lines[s:e]
        for key, val, mode, desired in POOL_DIRECTIVES:
            eff = _effective_value(seg, key)
            if not _dir_ok(eff, val, mode, desired):
                log_enh(3, _fn, f"{path}: pool [{name}] {key} not set correctly -> not mitigated")
                return UNMITIGATE
    log_enh(3, _fn, f"{path}: affected pool section(s) hardened")
    return EXISTS


def _htaccess_is_mitigated(path):
    _fn = "_htaccess_is_mitigated"
    lines, state = _lines_for_state(path, _fn, UNMITIGATE)
    if lines is None:
        return state
    for setting, _tok, _mode, desired_bool in HTACCESS_DIRECTIVES:
        eff = _htaccess_effective(lines, setting)
        if eff != desired_bool:
            log_enh(3, _fn, f"{path}: {setting} not set correctly -> not mitigated")
            return UNMITIGATE
    log_enh(3, _fn, f"{path}: all required directives set correctly")
    return EXISTS


def _target_state(t):
    k = t["kind"]
    if k == "ini":
        return _ini_is_mitigated(t["path"], INI_DIRECTIVES)
    if k == "dropin":
        return _dropin_is_mitigated(t["path"])
    if k == "userini":
        return _ini_is_mitigated(t["path"], USERINI_DIRECTIVES)
    if k == "pool":
        return _pool_is_mitigated(t["path"], t["sections"])
    if k == "htaccess":
        return _htaccess_is_mitigated(t["path"])
    return FAILURE


def _group_effective(group, *keys):
    '''{key: (value, setter_path)} across a load-ordered group, reading each
    file once; for every key the last file that sets it wins.'''
    res = {k: (None, None) for k in keys}
    for p in group:
        try:
            lines = _read_lines(p)[0]
        except FileNotFoundError:
            continue
        for k in keys:
            v = _effective_value(lines, k)
            if v is not None:
                res[k] = (v, p)
    return res


def _upload_violations(targets):
    '''Every place where upload_max_filesize is not below the post_max_size in
    force: each PHP runtime (php.ini + its drop-ins) and each affected pool.
    Returns fix items {kind, path, sections, key, limit, add, desc}. A runtime
    or pool whose post_max_size is itself invalid is left to the per-file check.
    Raises OSError when a file cannot be read.'''
    items = OrderedDict()
    for grp in INI_GROUPS:
        g = grp["files"]
        eff = _group_effective(g, "post_max_size", UPLOAD_KEY)
        p_raw = eff["post_max_size"][0]
        p = _php_bytes(p_raw)
        if not p:
            continue
        u_raw, setter = eff[UPLOAD_KEY]
        shown = u_raw if u_raw is not None else f"{PHP_DEFAULT_UPLOAD} (PHP default)"
        u = _php_bytes(u_raw if u_raw is not None else PHP_DEFAULT_UPLOAD)
        if u and u < p:
            continue
        path = setter or g[0]
        prev = items.get((path, None))
        if prev is None or p < prev["limit"]:
            items[(path, None)] = {
                "kind": "ini", "path": path, "sections": None, "key": UPLOAD_KEY, "limit": p,
                "add": path == g[0],
                "desc": f"{UPLOAD_KEY} = {shown} is not below post_max_size = {p_raw} "
                        f"(runtime using {g[0]}; set in {path})"}

    for t in targets:
        if t["kind"] != "pool":
            continue
        lines, _nl, _st = _read_lines(t["path"])
        wanted = {n.lower() for n in (t["sections"] or set())}
        for name, s, e in _pool_sections(lines):
            if name.lower() not in wanted:
                continue
            seg = lines[s:e]
            p_raw = _effective_value(seg, "php_admin_value[post_max_size]")
            p = _php_bytes(p_raw)
            if not p:
                continue
            u_raw = _effective_value(seg, f"php_admin_value[{UPLOAD_KEY}]")
            if u_raw is None:
                u_raw = _effective_value(seg, f"php_value[{UPLOAD_KEY}]")
            if u_raw is None:   # inherited from the FPM runtime's php.ini / drop-ins
                grp = _group_for_pool(t["path"])
                if grp is not None:
                    u_raw = _group_effective(grp["files"], UPLOAD_KEY)[UPLOAD_KEY][0]
                shown = f"{u_raw if u_raw is not None else PHP_DEFAULT_UPLOAD} (inherited)"
                u = _php_bytes(u_raw if u_raw is not None else PHP_DEFAULT_UPLOAD)
            else:
                u, shown = _php_bytes(u_raw), u_raw
            if u and u < p:
                continue
            items[(t["path"], name)] = {
                "kind": "pool", "path": t["path"], "sections": {name},
                "key": f"php_admin_value[{UPLOAD_KEY}]", "limit": p, "add": True,
                "desc": f"pool [{name}] {UPLOAD_KEY} = {shown} is not below "
                        f"php_admin_value[post_max_size] = {p_raw} ({t['path']})"}
    return list(items.values())


def _fix_upload_limits(targets):
    '''Lower upload_max_filesize wherever it is not below post_max_size.
    Only files that are already targets (backed up) are written.'''
    _fn = "_fix_upload_limits"
    target_paths = {t["path"] for t in targets}
    try:
        for _attempt in range(3):
            items = _upload_violations(targets)
            if not items:
                return SUCCESS
            for it in items:
                if it["path"] not in target_paths:
                    log_enh(0, _fn, f"{it['path']} is not a backed-up target; not modifying it")
                    return FAILURE
                new = _fmt_bytes(_below(it["limit"]))
                log_enh(1, _fn, f"{it['desc']}; setting {it['key']} = {new}")
                fix = [(it["key"], new, "lt_bytes", it["limit"])]
                if it["kind"] == "pool":
                    rc = harden_pool(it["path"], it["sections"], fix)
                else:
                    rc = harden_ini(it["path"], fix, ";", add_missing=it["add"])
                if rc != SUCCESS:
                    return FAILURE
        for it in _upload_violations(targets):
            log_enh(0, _fn, f"Still not fixed: {it['desc']}")
        return FAILURE
    except OSError as e:
        log_enh(0, _fn, f"Error checking upload limits: {str(e)}")
        return FAILURE


# --------------------- VERIFY ---------------------
def verify(targets, runtime=True):
    '''
    Checks every target file and, when runtime is True, that no PHP worker
    predates the newest php.ini / pool change (such a worker still runs the old
    configuration).
    Returns:
        SKIP       -> no target files present
        SUCCESS    -> every target is hardened and the workers have reloaded it
        UNMITIGATE -> a target is not hardened, or workers are stale
        FAILURE    -> an error occurred
    '''
    _fn = "verify"
    try:
        log_enh(3, _fn, "Verifying PHP upload-progress hardening state")
        if not targets:
            log_enh(2, _fn, "No target files to verify; nothing to do")
            return SKIP
        all_ok = True
        for t in targets:
            state = _target_state(t)
            if state == FAILURE:
                return FAILURE
            if state == UNMITIGATE:
                log_enh(2, _fn, f"Not hardened ({t['kind']}): {t['path']}")
                all_ok = False
            else:
                log_enh(1, _fn, f"Hardened ({t['kind']}): {t['path']}")
        if not all_ok:
            log_enh(2, _fn, "One or more targets are not hardened")
            return UNMITIGATE
        violations = _upload_violations(targets)
        if violations:
            for v in violations:
                log_enh(2, _fn, v["desc"])
            log_enh(2, _fn, f"{UPLOAD_KEY} must be below post_max_size -> not mitigated")
            return UNMITIGATE
        if runtime:
            if _report_unrecognised(_fn):
                log_enh(0, _fn, "Cannot confirm that every PHP worker runs the hardened configuration")
                return FAILURE
            cutoff = _config_cutoff(targets)
            stale = _stale_workers(cutoff) if cutoff is not None else []
            if stale:
                for w in stale:
                    log_enh(2, _fn, f"{w['family']} worker PID {w['pid']} started before the "
                                    f"last configuration change")
                log_enh(2, _fn, f"Configuration hardened but {len(stale)} worker(s) still run the "
                                f"old configuration; restart required")
                return UNMITIGATE
        log_enh(1, _fn, "All targets are hardened; affected application is mitigated")
        return SUCCESS
    except Exception as e:
        log_enh(0, _fn, f"Error during verification: {str(e)}")
        return FAILURE


# --------------------- BACKUP (single immutable file) ---------------------
def _set_immutable(path, enable):
    '''Best-effort immutable flag on the backup.'''
    _fn = "_set_immutable"
    if shutil.which("chattr"):
        flag = "+i" if enable else "-i"
        rc, _, err = run_cmd(["chattr", flag, path])
        if rc == 0:
            log_enh(1, _fn, f"Set immutable flag {flag} on {path}")
            return True
        log_enh(2, _fn, f"chattr {flag} failed on {path}: {err}")
    try:
        os.chmod(path, 0o400 if enable else 0o600)
        log_enh(2, _fn, f"chattr unavailable; applied restrictive permissions to {path}")
        return True
    except Exception as e:
        log_enh(2, _fn, f"Could not adjust protection on {path}: {str(e)}")
        return False


def _remove_backup():
    _fn = "_remove_backup"
    _set_immutable(BACKUP_PATH, False)
    try:
        os.remove(BACKUP_PATH)
        log_enh(1, _fn, f"Removed backup manifest: {BACKUP_PATH}")
        return True
    except FileNotFoundError:
        return True
    except OSError as e:
        log_enh(2, _fn, f"Could not remove backup {BACKUP_PATH}: {str(e)}")
        _set_immutable(BACKUP_PATH, True)
        return False


def create_backup(originals):
    '''Write the single backup manifest from {path: original_bytes}.
    Returns (code, created). An existing backup is kept as-is.'''
    _fn = "create_backup"
    try:
        if os.path.lexists(BACKUP_PATH):
            log_enh(3, _fn, f"Backup already exists; preserving single backup: {BACKUP_PATH}")
            return SUCCESS, False
        manifest = {
            "version": BACKUP_VERSION,
            "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "files": {p: base64.b64encode(d).decode("ascii") for p, d in originals.items()},
        }
        data = json.dumps(manifest).encode("ascii")
        if _atomic_write(BACKUP_PATH, data, new_mode=0o600) != SUCCESS:
            log_enh(0, _fn, f"Could not write backup {BACKUP_PATH}")
            return FAILURE, False
        _set_immutable(BACKUP_PATH, True)
        log_enh(1, _fn, f"Single backup created for {len(originals)} file(s): {BACKUP_PATH}")
        return SUCCESS, True
    except Exception as e:
        log_enh(0, _fn, f"Error creating backup: {str(e)}")
        return FAILURE, False


def restore_backup():
    '''Restore every file from the manifest byte-for-byte, then remove it.
    Returns SUCCESS, FAILURE, SKIP (no manifest) or CORRUPT (unusable manifest).'''
    _fn = "restore_backup"
    if not os.path.lexists(BACKUP_PATH):
        log_enh(2, _fn, "No backup manifest present")
        return SKIP
    _set_immutable(BACKUP_PATH, False)
    try:
        raw, _st = _read_raw(BACKUP_PATH)
        manifest = json.loads(raw.decode("utf-8"))
        files = manifest["files"]
        if not isinstance(files, dict) or not files:
            raise ValueError("manifest has no files")
        version = int(manifest.get("version", 1))
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        log_enh(0, _fn, f"Backup manifest {BACKUP_PATH} is unusable: {str(e)}")
        _set_immutable(BACKUP_PATH, True)
        return CORRUPT

    ok = True
    for path, enc in files.items():
        try:
            if version >= 2:
                data = base64.b64decode(enc, validate=True)
            else:
                data = enc.encode("utf-8", "surrogateescape")   # legacy text-mode manifest
        except (ValueError, TypeError, AttributeError) as e:
            log_enh(0, _fn, f"Backup entry for {path} is corrupt: {str(e)}")
            ok = False
            continue
        if _atomic_write(path, data) == SUCCESS:
            log_enh(1, _fn, f"Restored original: {path}")
        else:
            log_enh(0, _fn, f"Failed to restore {path}")
            ok = False
    if ok:
        _remove_backup()
        return SUCCESS
    _set_immutable(BACKUP_PATH, True)
    return FAILURE


# --------------------- DIRECTIVE WRITE / REVERT ---------------------
def _directive_key(line):
    m = _KEY_RE.match(line)
    return m.group(1).lower() if m else None


def _marker_kind(line):
    '''Classify a line: ("mod", original_line), ("add", key_or_None) or (None, None).'''
    s = line.lstrip()
    if not (s.startswith(";") or s.startswith("#")):
        return None, None
    if TAG_MODIFIED in line:
        return "mod", line[line.find(TAG_MODIFIED) + len(TAG_MODIFIED):]
    if TAG_ADDED in line:
        rest = line[line.find(TAG_ADDED) + len(TAG_ADDED):].strip()
        return "add", (rest[1:].strip() or None) if rest.startswith(":") else None
    return None, None


def _revert_tags(lines):
    '''Undo this script's changes using the marker comment lines.
    Consecutive markers (left by repeated mitigations) are treated as one
    stack: the OLDEST marker decides the outcome (restore its original line,
    or drop the directive if it was added), and the single directive line
    under the stack is consumed only if its key matches the marker's key.
    Returns (new_lines, changed, mismatches).'''
    out = []
    changed = False
    mismatches = 0
    i, n = 0, len(lines)
    while i < n:
        kind, _info = _marker_kind(lines[i])
        if kind is None:
            out.append(lines[i])
            i += 1
            continue
        run = []
        while i < n:
            k, inf = _marker_kind(lines[i])
            if k is None:
                break
            run.append((k, inf))
            i += 1
        first_kind, first_info = run[0]
        last_kind, last_info = run[-1]
        expected = _directive_key(last_info) if last_kind == "mod" else (
            last_info.lower() if last_info else None)
        if first_kind == "mod":
            out.append(first_info)
        if i < n and (expected is None or _directive_key(lines[i]) == expected):
            i += 1          # the directive this script wrote
        else:
            mismatches += 1  # governed line was edited/removed: leave it alone
        changed = True
    return out, changed, mismatches


def _file_has_tags(path):
    '''True/False, or None when the file cannot be read.'''
    try:
        data, _st = _read_raw(path)
    except FileNotFoundError:
        return False
    except OSError as e:
        log_enh(0, "_file_has_tags", f"Error reading {path}: {str(e)}")
        return None
    text = data.decode("utf-8", "surrogateescape")
    return TAG_MODIFIED in text or TAG_ADDED in text


def _rewrite_directive(line, compiled, cc, nl, seen, out, fn, label):
    '''Check one uncommented ini/pool line against the compiled directives and
    append the result to out. A non-compliant value is commented out under a
    revert marker with the compliant value written below it. Returns True when
    the line was changed.'''
    for key, val, mode, desired, rx in compiled:
        m = rx.match(line)
        if not m:
            continue
        seen.add(key)
        if _dir_ok(m.group(1).split(";", 1)[0].strip(), val, mode, desired):
            out.append(line)
            return False
        new = _wval(val, mode, desired)
        out.append(f"{cc} {TAG_MODIFIED}{line}")
        out.append(f"{line[:len(line) - len(line.lstrip())]}{key} = {new}{nl}")
        log_enh(1, fn, f"{label}set {key} = {new}")
        return True
    out.append(line)
    return False


def _append_missing(compiled, seen, cc, nl, out, fn, label):
    '''Append every directive not yet seen, each under an ADDED marker.
    Returns True when anything was appended.'''
    changed = False
    for key, val, mode, desired, _rx in compiled:
        if key not in seen:
            new = _wval(val, mode, desired)
            out.append(f"{cc} {TAG_ADDED}:{key}{nl}")
            out.append(f"{key} = {new}{nl}")
            log_enh(1, fn, f"{label}added {key} = {new}")
            changed = True
    return changed


def _finish_harden(path, fn, changed, out, st):
    if not changed:
        log_enh(3, fn, f"{path}: already compliant; no change written")
        return SUCCESS
    return _write_lines(path, out, st)


def harden_ini(path, directives, cc=";", add_missing=True):
    '''Apply the given INI directive set to a php.ini / .user.ini / drop-in.
    With add_missing=False (conf.d drop-ins) only non-compliant lines are
    rewritten; absent directives are left to php.ini.'''
    _fn = "harden_ini"
    try:
        lines, nl, st = _read_lines(path)
    except OSError as e:
        log_enh(0, _fn, f"Error reading {path}: {str(e)}")
        return FAILURE

    compiled = _compile(directives)
    label = f"{path}: "
    out, seen, changed = [], set(), False
    for line in lines:
        if _is_comment(line):
            out.append(line)
        else:
            changed |= _rewrite_directive(line, compiled, cc, nl, seen, out, _fn, label)
    if add_missing:
        changed |= _append_missing(compiled, seen, cc, nl, out, _fn, label)
    return _finish_harden(path, _fn, changed, out, st)


def harden_pool(path, sections, directives=None):
    '''Apply POOL_DIRECTIVES (or the given directives) to the affected pool
    section(s) only. Missing directives are appended at the end of each
    affected section.'''
    _fn = "harden_pool"
    try:
        lines, nl, st = _read_lines(path)
    except OSError as e:
        log_enh(0, _fn, f"Error reading {path}: {str(e)}")
        return FAILURE

    compiled = _compile(POOL_DIRECTIVES if directives is None else directives)
    wanted = {n.lower() for n in (sections or set())}
    out, changed, cur, seen, active = [], False, None, set(), False
    for line in lines:
        m = _SECTION_RE.match(line)
        if m:
            if active:
                changed |= _append_missing(compiled, seen, ";", nl, out, _fn, f"{path}: pool [{cur}] ")
            cur, seen = m.group(1), set()
            active = cur.lower() in wanted
            out.append(line)
        elif active and not _is_comment(line):
            changed |= _rewrite_directive(line, compiled, ";", nl, seen, out, _fn, f"{path}: pool [{cur}] ")
        else:
            out.append(line)
    if active:
        changed |= _append_missing(compiled, seen, ";", nl, out, _fn, f"{path}: pool [{cur}] ")
    return _finish_harden(path, _fn, changed, out, st)


def harden_htaccess(path):
    '''Apply HTACCESS_DIRECTIVES to an existing .htaccess that uses php_* already.
    Missing directives are inserted inside the same <IfModule> block as the
    first existing php_* directive, so they stay guarded and never trigger
    "Invalid command 'php_flag'" when mod_php is not loaded.'''
    _fn = "harden_htaccess"
    try:
        lines, nl, st = _read_lines(path)
    except OSError as e:
        log_enh(0, _fn, f"Error reading {path}: {str(e)}")
        return FAILURE

    if not _htaccess_has_php(lines):
        log_enh(2, _fn, f"{path}: no php_* directives present; skipping to avoid breaking Apache")
        return SUCCESS

    compiled = [(setting, tok, desired, _htaccess_regex(setting))
                for setting, tok, _mode, desired in HTACCESS_DIRECTIVES]
    present = {setting for line in lines if not _is_comment(line, hash_only=True)
               for setting, _tok, _desired, rx in compiled if rx.match(line)}

    ins_idx, indent = _htaccess_insert_point(lines)
    additions = []
    for setting, tok, _desired, _rx in compiled:
        if setting not in present:
            additions.append(f"{indent}# {TAG_ADDED}:{setting}{nl}")
            additions.append(f"{indent}php_flag {setting} {tok}{nl}")
            log_enh(1, _fn, f"{path}: added php_flag {setting} {tok}"
                            + ("" if ins_idx is None else f" inside <IfModule> ending at line {ins_idx + 1}"))

    out, changed = [], bool(additions)
    for idx, line in enumerate(lines):
        if idx == ins_idx:
            out.extend(additions)
        if _is_comment(line, hash_only=True):
            out.append(line)
            continue
        matched = False
        for setting, tok, desired, rx in compiled:
            m = rx.match(line)
            if m:
                matched = True
                if _norm_bool(m.group(3)) != desired:
                    out.append(f"{m.group(1)}# {TAG_MODIFIED}{line}")
                    out.append(f"{m.group(1)}{m.group(2)} {setting} {tok}{nl}")
                    changed = True
                    log_enh(1, _fn, f"{path}: set {m.group(2)} {setting} {tok}")
                else:
                    out.append(line)
                break
        if not matched:
            out.append(line)
    if ins_idx is None:
        out.extend(additions)
    return _finish_harden(path, _fn, changed, out, st)


def harden_target(t):
    k = t["kind"]
    if k == "ini":
        return harden_ini(t["path"], INI_DIRECTIVES, ";")
    if k == "dropin":
        return harden_ini(t["path"], INI_DIRECTIVES, ";", add_missing=False)
    if k == "userini":
        return harden_ini(t["path"], USERINI_DIRECTIVES, ";")
    if k == "pool":
        return harden_pool(t["path"], t["sections"], _pool_directives(t["path"]))
    if k == "htaccess":
        return harden_htaccess(t["path"])
    return FAILURE


def _pool_directives(pool_path):
    '''POOL_DIRECTIVES with the post_max_size value to write taken from the
    FPM runtime (php.ini + drop-ins, already hardened at this point) when it
    is compliant, so adding a pool line never raises the limit (php.ini 30M
    -> pool 30M, not 32M). Falls back to the cap.'''
    write = POST_MAX_CAP
    grp = _group_for_pool(pool_path)
    if grp is not None:
        p_raw = _group_effective(grp["files"], "post_max_size")["post_max_size"][0]
        if _dir_ok(p_raw, POST_MAX_CAP, "max_bytes", None):
            write = p_raw.strip().strip('"').strip("'")
    return [(k, v, m, write) if m == "max_bytes" else (k, v, m, d) for k, v, m, d in POOL_DIRECTIVES]


def revert_file(path):
    '''Fallback revert of a single file using the marker comment lines.'''
    _fn = "revert_file"
    try:
        lines, _nl, st = _read_lines(path)
    except OSError as e:
        log_enh(0, _fn, f"Error reading {path}: {str(e)}")
        return FAILURE
    new_lines, changed, mismatches = _revert_tags(lines)
    if not changed:
        log_enh(3, _fn, f"{path}: no mitigation markers found; nothing to revert")
        return SKIP
    if mismatches:
        log_enh(2, _fn, f"{path}: {mismatches} marker(s) no longer sit above the directive this "
                        f"script wrote; original restored, edited line left in place")
    if _write_lines(path, new_lines, st) != SUCCESS:
        return FAILURE
    log_enh(1, _fn, f"Reverted mitigation changes in {path}")
    return SUCCESS


# --------------------- SERVICE RESTART ---------------------
def _systemd_running():
    return os.path.isdir("/run/systemd/system") and shutil.which("systemctl") is not None


def _active_units(match_fn):
    rc, out, _ = run_cmd(["systemctl", "list-units", "--type=service",
                          "--state=active", "--no-legend", "--no-pager", "--plain"])
    units = []
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            if parts and match_fn(parts[0].lower()):
                units.append(parts[0])
    return units


def _in_units(pid, units):
    '''True when pid lives in the cgroup of one of the given systemd units.'''
    try:
        with open(f"/proc/{pid}/cgroup") as f:
            content = f.read()
    except OSError:
        return False
    return any(f"/{u}" in content for u in units)


def _unit_pids(units):
    '''{unit: [pid, ...]} for every process in each unit's cgroup (one /proc pass).'''
    found = {u: [] for u in units}
    try:
        names = os.listdir("/proc")
    except OSError:
        return found
    for name in names:
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/cgroup") as f:
                content = f.read()
        except OSError:
            continue
        for u in units:
            if f"/{u}" in content:
                found[u].append(int(name))
    return found


def _unrecognised_php_units():
    '''Active systemd units that serve PHP but whose processes this script did
    not recognise, so it could neither restart nor check their workers:
      - a php*fpm* unit with no php-fpm process (by executable name) in it;
      - an apache2* / httpd* unit with a process that loads mod_php (libphp)
        but is not a recognised mod_php master or worker.
    An Apache unit without mod_php is not PHP and is ignored. Hosts without
    systemd are not checked. Returns [(unit, reason)].'''
    if not _systemd_running():
        return []
    fpm_units = _active_units(lambda u: "php" in u and "fpm" in u)
    web_units = _active_units(lambda u: u.startswith(("apache2", "httpd")))
    if not fpm_units and not web_units:
        return []
    masters, workers = _php_processes()
    known = {p["pid"]: p["family"] for p in masters + workers}
    pids = _unit_pids(fpm_units + web_units)
    out = []
    for u in fpm_units:
        if not any(known.get(p) == "fpm" for p in pids[u]):
            shown = ", ".join(f"{p}={_proc_exe(p) or '?'}" for p in pids[u][:5]) or "no processes"
            out.append((u, f"no php-fpm process recognised in the unit ({shown})"))
    for u in web_units:
        for p in pids[u]:
            if p not in known and _has_mod_php(p):
                out.append((u, f"PID {p} ({_proc_exe(p) or '?'}) loads mod_php but is not a recognised "
                               f"Apache executable"))
                break
    return out


def _report_unrecognised(fn):
    '''Log every unrecognised PHP unit; True when there were any.'''
    unrec = _unrecognised_php_units()
    for unit, reason in unrec:
        log_enh(0, fn, f"Active unit {unit} serves PHP but was not recognised: {reason}; "
                       f"its workers cannot be restarted or checked")
    return bool(unrec)


def _config_test_cmd(master):
    if master["family"] == "fpm":
        exe = master["exe"] if os.path.isfile(master["exe"]) else shutil.which(os.path.basename(master["exe"]))
        if not exe:
            return None
        conf = _fpm_conf_of(master)
        return [exe, "-t"] + (["-y", conf] if conf else [])
    ctl = shutil.which("apache2ctl") or shutil.which("apachectl")
    if ctl:
        return [ctl, "configtest"]
    return [master["exe"], "-t"] if os.path.isfile(master["exe"]) else None


def _config_tests(masters):
    '''Config-test every running php-fpm / mod_php Apache master, in parallel.
    Returns True only when every test passes.'''
    _fn = "_config_tests"
    cmds = []
    for m in masters:
        cmd = _config_test_cmd(m)
        if cmd is None:
            log_enh(0, _fn, f"No binary available to config-test {m['family']} master PID {m['pid']} ({m['exe']})")
            return False
        if cmd not in cmds:
            cmds.append(cmd)
    results = _run_parallel(run_cmd, cmds)
    ok = True
    for cmd, (rc, out, err) in zip(cmds, results):
        if rc == 0:
            log_enh(1, _fn, f"Config test passed: {' '.join(cmd)}")
        else:
            log_enh(0, _fn, f"Config test failed (rc={rc}): {' '.join(cmd)}: {err or out}")
            ok = False
    return ok


def restart_php_services():
    '''Config-test, then restart every process that serves PHP so no worker
    keeps pre-change state. systemd units are restarted; any master not inside
    a restarted unit (standalone php-fpm, or a unit whose restart failed) is
    signalled directly. Units are restarted one at a time so a failure is
    attributable and not every SAPI is down at once.
    Returns SUCCESS, FAILURE or CONFIG_INVALID (nothing was restarted).'''
    _fn = "restart_php_services"
    # A PHP unit this script cannot recognise would otherwise look like "no PHP
    # running" and be reported as restarted while its old workers keep running.
    if _report_unrecognised(_fn):
        return FAILURE
    masters, _ = _php_processes()
    if not masters:
        log_enh(2, _fn, "No running php-fpm or mod_php Apache found; nothing to restart")
        return SUCCESS
    if not _config_tests(masters):
        return CONFIG_INVALID

    ok = True
    restarted = set()
    if _systemd_running():
        want_apache = any(m["family"] == "apache" for m in masters)
        units = _active_units(lambda u: ("php" in u and "fpm" in u)
                              or (want_apache and u.startswith(("apache2", "httpd"))))
        for unit in units:
            rc, _, err = run_cmd(["systemctl", "restart", unit], timeout=RESTART_TIMEOUT)
            if rc == 0:
                restarted.add(unit)
                log_enh(1, _fn, f"Restarted {unit}")
            else:
                ok = False
                log_enh(0, _fn, f"Could not restart {unit}: {err}")

    masters, _ = _php_processes()
    for m in masters:
        if restarted and _in_units(m["pid"], restarted):
            continue
        sig = signal.SIGUSR2 if m["family"] == "fpm" else signal.SIGHUP
        if not _signal_master(m, sig):
            ok = False
    return SUCCESS if ok else FAILURE


def _restart_and_confirm():
    '''Restart, then require every worker to be newer than the restart.
    Returns SUCCESS, FAILURE or CONFIG_INVALID.'''
    _fn = "_restart_and_confirm"
    cutoff = time.time()
    rs = restart_php_services()
    if rs != SUCCESS:
        return rs
    if not _wait_fresh_workers(cutoff):
        log_enh(0, _fn, "PHP workers from before the restart are still running; "
                        "they keep the previous state")
        return FAILURE
    return SUCCESS


# --------------------- MITIGATE ---------------------
def _undo_changes(originals, backup_created):
    '''Put back the exact bytes read at the start of this run.'''
    _fn = "_undo_changes"
    ok = True
    for path, data in originals.items():
        try:
            current, _st = _read_raw(path)
        except FileNotFoundError:
            current = None
        except OSError as e:
            log_enh(0, _fn, f"Cannot read {path} to undo: {str(e)}")
            ok = False
            continue
        if current == data:
            continue
        if _atomic_write(path, data) == SUCCESS:
            log_enh(1, _fn, f"Restored original content of {path}")
        else:
            ok = False
    if ok and backup_created:
        _remove_backup()
    if not ok:
        log_enh(0, _fn, "Some files could not be restored; run 'rollback'")
    return ok


def mitigate(targets):
    '''Flow: verify -> backup -> harden -> config test -> restart -> confirm
    fresh workers -> verify again. Any failure before the restart restores the
    original files.'''
    _fn = "mitigate"
    try:
        log_enh(3, _fn, "Starting PHP upload-progress mitigation")
        state = verify(targets)
        if state == SUCCESS:
            log_enh(1, _fn, "Affected application already hardened; no action needed")
            return EXISTS
        if state == SKIP:
            log_enh(2, _fn, "No target files present; skipping mitigation")
            return SKIP
        if state == FAILURE:
            log_enh(0, _fn, "Initial verification failed; cannot proceed with mitigation")
            return FAILURE

        log_enh(1, _fn, "Application is not hardened; applying mitigation")
        originals = {}
        for t in targets:
            try:
                originals[t["path"]], _st = _read_raw(t["path"])
            except OSError as e:
                log_enh(0, _fn, f"Cannot read {t['path']}: {str(e)}; aborting")
                return FAILURE

        rc, backup_created = create_backup(originals)
        if rc != SUCCESS:
            log_enh(0, _fn, "Backup step failed; aborting mitigation")
            return FAILURE

        for t in targets:
            if harden_target(t) != SUCCESS:
                log_enh(0, _fn, f"Failed to harden {t['path']}; restoring original files")
                _undo_changes(originals, backup_created)
                return FAILURE
        if _fix_upload_limits(targets) != SUCCESS:
            log_enh(0, _fn, f"Could not bring {UPLOAD_KEY} below post_max_size; restoring original files")
            _undo_changes(originals, backup_created)
            return FAILURE

        rs = _restart_and_confirm()
        if rs == CONFIG_INVALID:
            log_enh(0, _fn, "Hardened configuration failed the config test; restoring original "
                            "files; services were not restarted")
            _undo_changes(originals, backup_created)
            return FAILURE
        if rs != SUCCESS:
            log_enh(0, _fn, "Configuration was written but not every PHP worker was restarted; "
                            "host is not mitigated")
            return FAILURE

        log_enh(3, _fn, "Re-verifying state after mitigation")
        final = verify(targets)
        if final == SUCCESS:
            log_enh(1, _fn, "Mitigation completed successfully")
            return SUCCESS
        if final == UNMITIGATE:
            log_enh(0, _fn, "Application still not hardened after mitigation")
            return UNMITIGATE
        log_enh(0, _fn, "Post-mitigation verification failed")
        return FAILURE
    except Exception as e:
        log_enh(0, _fn, f"Error during mitigation: {str(e)}")
        return FAILURE


# --------------------- ROLLBACK ---------------------
def rollback(targets):
    '''Revert whatever this script changed, whether the earlier mitigation
    completed, failed half-way, or was later edited by hand.
    Flow: backup restore (or marker revert) -> marker revert of leftovers ->
    config test -> restart -> confirm fresh workers -> confirm no markers remain.'''
    _fn = "rollback"
    try:
        log_enh(3, _fn, "Starting PHP upload-progress rollback")
        state = verify(targets, runtime=False)
        if state == FAILURE:
            log_enh(0, _fn, "Initial verification failed; cannot proceed with rollback")
            return FAILURE

        tagged = []
        for t in targets:
            has = _file_has_tags(t["path"])
            if has is None:
                return FAILURE
            if has:
                tagged.append(t["path"])
        has_backup = os.path.lexists(BACKUP_PATH)

        if not has_backup and not tagged:
            if state == SUCCESS:
                log_enh(2, _fn, "Settings are hardened but not by this script (no backup, no "
                                "markers); leaving them untouched")
            else:
                log_enh(2, _fn, "No backup and no markers; nothing this script changed")
            return SKIP

        if has_backup:
            log_enh(1, _fn, "Backup manifest found; restoring original files")
            r = restore_backup()
            if r == CORRUPT:
                log_enh(2, _fn, "Backup unusable; falling back to marker-based revert")
            elif r != SUCCESS:
                log_enh(0, _fn, "Failed to restore from backup")
                return FAILURE

        # Markers can remain when the backup was missing/corrupt or did not
        # cover a file (e.g. a later run against another pool).
        for t in targets:
            has = _file_has_tags(t["path"])
            if has is None:
                return FAILURE
            if has and revert_file(t["path"]) == FAILURE:
                log_enh(0, _fn, f"Failed to revert {t['path']}")
                return FAILURE

        rs = _restart_and_confirm()
        if rs == CONFIG_INVALID:
            log_enh(0, _fn, "Restored configuration failed the config test; services were not "
                            "restarted; fix the configuration manually")
            return FAILURE
        if rs != SUCCESS:
            log_enh(0, _fn, "Files reverted but not every PHP worker was restarted")
            return FAILURE

        leftover = [t["path"] for t in targets if _file_has_tags(t["path"]) is not False]
        if leftover:
            for p in leftover:
                log_enh(0, _fn, f"Mitigation markers still present or unreadable: {p}")
            return FAILURE

        if verify(targets, runtime=False) == SUCCESS:
            log_enh(2, _fn, "Files reverted; the original configuration was already compliant")
        log_enh(1, _fn, "Rollback completed successfully")
        return SUCCESS
    except Exception as e:
        log_enh(0, _fn, f"Error during rollback: {str(e)}")
        return FAILURE


# --------------------- MAIN ---------------------

def main():
    _fn = "main"
    global TARGET_SERVICE, AFFECTED_PORT
    exit_code = SUCCESS
    try:
        # This script runs the rollback only. It takes no arguments.
        TARGET_SERVICE = None
        AFFECTED_PORT = None

        if check_root() != SUCCESS:
            sys.exit(FAILURE)

        print_environment()

        if acquire_lock() != SUCCESS:
            sys.exit(FAILURE)

        targets = discover_targets()
        exit_code = rollback(targets)
    except KeyboardInterrupt:
        log_enh(2, _fn, "Script interrupted by user")
        exit_code = FAILURE
    except SystemExit:
        raise
    except Exception as e:
        log_enh(0, _fn, f"Unexpected error in main: {str(e)}")
        exit_code = FAILURE

    log_enh(3, _fn, f"Exiting with status code: {exit_code}")
    sys.exit(exit_code)


if __name__ == "__main__":
    try:
        log_enh(3, "__name__", "Initializing rollback run")
        main()
    except SystemExit:
        raise
    except Exception as e:
        log_enh(0, "__name__", f"Critical error: {str(e)}")
        sys.exit(FAILURE)
