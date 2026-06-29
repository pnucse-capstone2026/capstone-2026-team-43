"""Clipboard paste interceptor.

Flow
----
1. A hidden message-only HWND registers as a clipboard format listener
   (AddClipboardFormatListener) to track clipboard sequence numbers.
2. A WH_KEYBOARD_LL global keyboard hook intercepts Ctrl+V *before* it
   reaches the target application.
3. On Ctrl+V the hook queries the foreground window's process name:
   - allowlist process  → pass through immediately (no inspection)
   - inspect-list / unknown process → read clipboard text → regex check
     - no regex hit → pass through
     - regex hit    → suppress keystroke + notify user (paste blocked)
"""

import ctypes
import ctypes.wintypes
import logging
import threading
from typing import Callable, Optional

import win32api
import win32con
import win32gui
import win32process

from clipboard_ctrl.text_extractor import TextExtractor

logger = logging.getLogger(__name__)

# ── Win32 constants ──────────────────────────────────────────────────────────
WM_CLIPBOARDUPDATE = 0x031D
WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_SYSKEYDOWN = 0x0104
VK_V = 0x56
VK_CONTROL = 0x11
# HWND_MESSAGE: message-only window parent (-3 as a signed pointer-sized int)
HWND_MESSAGE: int = ctypes.cast(ctypes.c_void_p(-3), ctypes.c_void_p).value  # type: ignore[assignment]

_user32 = ctypes.windll.user32
_kernel32 = ctypes.windll.kernel32

# ── Keyboard hook struct ──────────────────────────────────────────────────────
LowLevelKeyboardProc = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_int,
    ctypes.wintypes.WPARAM,
    ctypes.wintypes.LPARAM,
)


class _KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode",      ctypes.wintypes.DWORD),
        ("scanCode",    ctypes.wintypes.DWORD),
        ("flags",       ctypes.wintypes.DWORD),
        ("time",        ctypes.wintypes.DWORD),
        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
    ]


# ── Main hook class ───────────────────────────────────────────────────────────
class ClipboardHook:
    """Intercepts Ctrl+V in risky apps and blocks the paste when regex hits."""

    def __init__(
        self,
        should_inspect: Callable[[str], bool],
        on_text_pasted: Callable[[str, str], bool],
    ) -> None:
        """
        Parameters
        ----------
        should_inspect:
            Receives the foreground process name (lower-case exe, e.g. ``slack.exe``).
            Return True  → inspect clipboard content before allowing paste.
            Return False → allow paste without inspection.
        on_text_pasted:
            Receives (normalized_text, process_name).
            Return True  → block the paste.
            Return False → allow the paste.
        """
        self._should_inspect = should_inspect
        self._on_text_pasted = on_text_pasted

        self._thread: Optional[threading.Thread] = None
        self._thread_id: Optional[int] = None
        self._hwnd: Optional[int] = None
        self._hook_id: Optional[int] = None
        self._hook_proc_ref: Optional[LowLevelKeyboardProc] = None  # prevent GC

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the hook in a dedicated daemon thread."""
        if self._thread and self._thread.is_alive():
            logger.warning("ClipboardHook already running")
            return
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="ClipboardHook"
        )
        self._thread.start()
        logger.info("ClipboardHook thread started")

    def stop(self) -> None:
        """Signal the hook thread to quit and wait for it."""
        if self._thread_id:
            _user32.PostThreadMessageW(self._thread_id, win32con.WM_QUIT, 0, 0)
        if self._thread:
            self._thread.join(timeout=3.0)
        logger.info("ClipboardHook stopped")

    # ── Internals ─────────────────────────────────────────────────────────────

    def _get_foreground_process_name(self) -> Optional[str]:
        hwnd = _user32.GetForegroundWindow()
        if not hwnd:
            return None
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        try:
            handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                False,
                pid,
            )
            path: str = win32process.GetModuleFileNameEx(handle, 0)
            win32api.CloseHandle(handle)
            return path.rsplit("\\", 1)[-1].lower()
        except Exception:
            return None

    def _handle_paste(self) -> bool:
        """Return True to block the paste, False to allow it."""
        process_name = self._get_foreground_process_name()
        if not process_name:
            return False

        if not self._should_inspect(process_name):
            return False

        text = TextExtractor.extract()
        if not text:
            return False

        normalized = TextExtractor.normalize(text)
        if not normalized:
            return False

        return self._on_text_pasted(normalized, process_name)

    def _keyboard_hook_proc(
        self, n_code: int, w_param: int, l_param: int
    ) -> int:
        if n_code >= 0 and w_param in (WM_KEYDOWN, WM_SYSKEYDOWN):
            kb = ctypes.cast(l_param, ctypes.POINTER(_KBDLLHOOKSTRUCT)).contents
            if kb.vkCode == VK_V:
                ctrl_down = bool(_user32.GetAsyncKeyState(VK_CONTROL) & 0x8000)
                if ctrl_down:
                    try:
                        if self._handle_paste():
                            return 1  # Suppress keystroke → paste is blocked
                    except Exception:
                        logger.exception("Error inside paste handler")

        return _user32.CallNextHookEx(self._hook_id, n_code, w_param, l_param)

    def _wnd_proc(self, hwnd: int, msg: int, w_param: int, l_param: int) -> int:
        if msg == WM_CLIPBOARDUPDATE:
            logger.debug("Clipboard sequence updated")
        elif msg == win32con.WM_DESTROY:
            _user32.RemoveClipboardFormatListener(hwnd)
            win32gui.PostQuitMessage(0)
        return win32gui.DefWindowProc(hwnd, msg, w_param, l_param)

    def _run(self) -> None:
        self._thread_id = win32api.GetCurrentThreadId()

        # Register hidden window class
        class_name = "SentryDLPClipboardListener"
        wc = win32gui.WNDCLASS()
        wc.lpszClassName = class_name
        wc.lpfnWndProc = self._wnd_proc
        try:
            win32gui.RegisterClass(wc)
        except Exception:
            pass  # Already registered from a previous run in the same process

        # Create message-only HWND
        try:
            self._hwnd = win32gui.CreateWindow(
                class_name,
                "Sentry DLP Listener",
                0,
                0, 0, 0, 0,
                HWND_MESSAGE,
                0, 0, None,
            )
        except Exception:
            # Fallback: invisible top-level window (no WS_VISIBLE)
            self._hwnd = win32gui.CreateWindow(
                class_name, "Sentry DLP Listener",
                0, 0, 0, 0, 0, 0, 0, 0, None,
            )

        _user32.AddClipboardFormatListener(self._hwnd)

        # Install low-level keyboard hook
        self._hook_proc_ref = LowLevelKeyboardProc(self._keyboard_hook_proc)
        self._hook_id = _user32.SetWindowsHookExW(
            WH_KEYBOARD_LL,
            self._hook_proc_ref,
            _kernel32.GetModuleHandleW(None),
            0,
        )
        if not self._hook_id:
            err = ctypes.GetLastError()
            logger.error("Failed to install WH_KEYBOARD_LL (error=%d)", err)
            return

        logger.info(
            "Keyboard hook installed (hwnd=%s hook_id=%s)", self._hwnd, self._hook_id
        )

        try:
            win32gui.PumpMessages()  # Blocks until WM_QUIT
        finally:
            if self._hook_id:
                _user32.UnhookWindowsHookEx(self._hook_id)
                self._hook_id = None
            if self._hwnd:
                try:
                    win32gui.DestroyWindow(self._hwnd)
                except Exception:
                    pass
                self._hwnd = None
            logger.info("Keyboard hook uninstalled")
