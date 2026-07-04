"""usb_minifilter.file_guard — Python 유저모드 클라이언트.

역할
----
커널 드라이버(sentry_filter.sys)의 필터 통신 포트에 연결해 파일 이벤트를 수신,
DLP 파이프라인(정규식 → PayloadBuilder → ApiClient)으로 분석한 뒤 Allow/Block 응답.

필요 조건
---------
- sentry_filter.sys가 로드되어 포트를 생성한 상태여야 함
- 관리자 권한으로 실행 (필터 포트 연결에 필요)
- fltlib.dll (Windows 기본 포함, Filter Manager 유저모드 라이브러리)

메시지 구조체는 sentry_comm.h와 완전히 동일한 메모리 레이아웃이어야 한다.
Python ctypes는 pack=1 / 필드 순서·타입을 C와 1:1 매핑한다.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import logging
import threading
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# ── fltlib.dll 로드 ────────────────────────────────────────────────────────

try:
    _fltlib = ctypes.windll.LoadLibrary("fltlib.dll")
except OSError as _e:
    _fltlib = None
    logger.warning("fltlib.dll 로드 실패: %s (드라이버 없이 실행 중인 경우 정상)", _e)

INVALID_HANDLE_VALUE = ctypes.wintypes.HANDLE(-1).value
WAIT_OBJECT_0        = 0x00000000
INFINITE             = 0xFFFFFFFF

# FilterConnectCommunicationPort 에러 코드
ERROR_FILE_NOT_FOUND = 2
ERROR_ACCESS_DENIED  = 5

# ── sentry_comm.h와 동일한 크기 상수 ─────────────────────────────────────

SENTRY_MAX_PATH_LEN    = 520
SENTRY_MAX_PROCNAME_LEN = 128

# SENTRY_FLAG_*
FLAG_USB     = 0x0001
FLAG_NETWORK = 0x0002
FLAG_WRITE   = 0x0010
FLAG_RENAME  = 0x0020

# SENTRY_COMMAND
SENTRY_ALLOW = 0
SENTRY_BLOCK  = 1

PORT_NAME = "\\\\.\\SentryDLPPort"

# ── ctypes 구조체 (C pragma pack(1) 대응) ────────────────────────────────

class FilterMessageHeader(ctypes.Structure):
    """FILTER_MESSAGE_HEADER — fltUser.h 동일 레이아웃."""
    _pack_ = 1
    _fields_ = [
        ("ReplyLength", ctypes.c_ulong),
        ("MessageId",   ctypes.c_ulonglong),
    ]


class FilterReplyHeader(ctypes.Structure):
    """FILTER_REPLY_HEADER — fltUser.h 동일 레이아웃."""
    _pack_ = 1
    _fields_ = [
        ("Status",    ctypes.c_long),
        ("MessageId", ctypes.c_ulonglong),
    ]


class SentryNotification(ctypes.Structure):
    """SENTRY_NOTIFICATION — sentry_comm.h 동일 레이아웃."""
    _pack_ = 1
    _fields_ = [
        ("Flags",       ctypes.c_ulong),
        ("ProcessId",   ctypes.c_ulong),
        ("FileSize",    ctypes.c_longlong),
        ("FilePath",    ctypes.c_wchar * SENTRY_MAX_PATH_LEN),
        ("ProcessName", ctypes.c_wchar * SENTRY_MAX_PROCNAME_LEN),
    ]


class SentryMessage(ctypes.Structure):
    """SENTRY_MESSAGE — 커널이 FilterGetMessage로 보내는 전체 패킷."""
    _pack_ = 1
    _fields_ = [
        ("Header", FilterMessageHeader),
        ("Data",   SentryNotification),
    ]


class SentryReply(ctypes.Structure):
    """SENTRY_REPLY — SENTRY_COMMAND enum."""
    _pack_ = 1
    _fields_ = [
        ("Command", ctypes.c_ulong),   # SentryAllow=0, SentryBlock=1
    ]


class SentryReplyMsg(ctypes.Structure):
    """SENTRY_REPLY_MSG — FilterReplyMessage로 커널에 돌려주는 전체 패킷."""
    _pack_ = 1
    _fields_ = [
        ("Header", FilterReplyHeader),
        ("Data",   SentryReply),
    ]


# ── fltlib API argtypes/restype 설정 ────────────────────────────────────

def _setup_fltlib() -> bool:
    """fltlib.dll 함수 시그니처 등록. 실패 시 False 반환."""
    if _fltlib is None:
        return False
    try:
        _fltlib.FilterConnectCommunicationPort.argtypes = [
            ctypes.c_wchar_p,                 # lpPortName
            ctypes.c_ulong,                   # dwOptions (0)
            ctypes.c_void_p,                  # lpContext
            ctypes.c_ushort,                  # wSizeOfContext
            ctypes.c_void_p,                  # lpSecurityAttributes
            ctypes.POINTER(ctypes.wintypes.HANDLE),  # hPort (out)
        ]
        _fltlib.FilterConnectCommunicationPort.restype = ctypes.c_long  # HRESULT

        _fltlib.FilterGetMessage.argtypes = [
            ctypes.wintypes.HANDLE,           # hPort
            ctypes.POINTER(FilterMessageHeader),  # lpMessageBuffer
            ctypes.c_ulong,                   # dwMessageBufferSize
            ctypes.c_void_p,                  # lpOverlapped (NULL)
        ]
        _fltlib.FilterGetMessage.restype = ctypes.c_long

        _fltlib.FilterReplyMessage.argtypes = [
            ctypes.wintypes.HANDLE,           # hPort
            ctypes.POINTER(FilterReplyHeader),# lpReplyBuffer
            ctypes.c_ulong,                   # dwReplyBufferSize
        ]
        _fltlib.FilterReplyMessage.restype = ctypes.c_long
        return True
    except AttributeError as e:
        logger.error("fltlib 함수 서명 등록 실패: %s", e)
        return False


_FLTLIB_OK = _setup_fltlib()


# ── FileGuard 클래스 ──────────────────────────────────────────────────────

class FileGuard:
    """커널 필터 포트에 연결해 파일 이벤트를 DLP 파이프라인으로 처리하는 에이전트."""

    def __init__(
        self,
        rule_filter: Any,          # clipboard_ctrl.rule_filter.RuleFilter
        payload_builder: Any,      # core_comm.payload_builder.PayloadBuilder
        api_client: Any,           # core_comm.api_client.ApiClient
        event_logger: Any,         # core_comm.event_logger.EventLogger
        file_inspector: Any,       # network_hook.file_inspector.FileInspector
        on_blocked: Optional[Callable[[str, list, str], None]] = None,
    ) -> None:
        self._rule_filter    = rule_filter
        self._builder        = payload_builder
        self._api_client     = api_client
        self._event_logger   = event_logger
        self._file_inspector = file_inspector
        self._on_blocked     = on_blocked

        self._port: ctypes.wintypes.HANDLE = ctypes.wintypes.HANDLE(INVALID_HANDLE_VALUE)
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    # ── 시작·중지 ─────────────────────────────────────────────────────────

    def start(self) -> None:
        if not _FLTLIB_OK:
            raise RuntimeError("fltlib.dll를 사용할 수 없습니다 — 드라이버가 로드됐는지 확인하세요")

        hr = _fltlib.FilterConnectCommunicationPort(
            PORT_NAME,
            0,
            None,
            0,
            None,
            ctypes.byref(self._port),
        )
        if hr != 0:
            raise OSError(f"FilterConnectCommunicationPort 실패 — HRESULT=0x{hr & 0xFFFFFFFF:08X}\n"
                          "  sentry_filter.sys가 로드되어 있고 관리자 권한으로 실행 중인지 확인하세요")

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="FileGuard",
            daemon=True,
        )
        self._thread.start()
        logger.info("[FileGuard] 드라이버 포트 연결 완료 → 감시 시작")

    def stop(self) -> None:
        self._stop_event.set()
        if self._port.value != INVALID_HANDLE_VALUE:
            ctypes.windll.kernel32.CloseHandle(self._port)
            self._port = ctypes.wintypes.HANDLE(INVALID_HANDLE_VALUE)
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        logger.info("[FileGuard] 중지")

    # ── 메인 루프 ──────────────────────────────────────────────────────────

    def _run(self) -> None:
        msg     = SentryMessage()
        msg_ptr = ctypes.cast(ctypes.byref(msg), ctypes.POINTER(FilterMessageHeader))

        while not self._stop_event.is_set():
            hr = _fltlib.FilterGetMessage(
                self._port,
                msg_ptr,
                ctypes.sizeof(SentryMessage),
                None,   # Overlapped=NULL → 동기 블로킹
            )

            if self._stop_event.is_set():
                break

            if hr != 0:
                err = ctypes.GetLastError()
                logger.error("[FileGuard] FilterGetMessage 실패 hr=0x%08X err=%d", hr & 0xFFFFFFFF, err)
                break

            try:
                command = self._inspect(msg)
            except Exception:
                logger.exception("[FileGuard] 검사 중 예외 — Fail-Open")
                command = SENTRY_ALLOW

            self._send_reply(msg.Header.MessageId, command)

    # ── 검사 로직 ──────────────────────────────────────────────────────────

    def _inspect(self, msg: SentryMessage) -> int:
        """파일 이벤트를 분석해 SENTRY_ALLOW 또는 SENTRY_BLOCK 반환."""
        data         = msg.Data
        file_path    = data.FilePath
        process_name = data.ProcessName
        flags        = data.Flags

        channel = "usb" if (flags & FLAG_USB) else "network_share"

        logger.debug(
            "[FileGuard] 이벤트: path=%s process=%s flags=0x%X",
            file_path, process_name, flags,
        )

        # 1단계: 파일 내용 추출 (FileInspector)
        try:
            text = self._file_inspector.extract_from_path(Path(file_path))
        except Exception:
            text = None

        if not text:
            logger.debug("[FileGuard] 텍스트 추출 불가 — 허용")
            return SENTRY_ALLOW

        # 2단계: 정규식 1차 게이트
        hits = self._rule_filter.match(text)
        if not hits:
            return SENTRY_ALLOW

        # 3단계: PayloadBuilder → ApiClient
        payload = self._builder.build(text, hits, channel, process_name)
        result  = self._api_client.analyze(payload)

        logger.info(
            "[FileGuard] AI 판단: action=%s risk=%.0f path=%s",
            result.action, result.risk_score, file_path,
        )

        if result.should_block:
            self._event_logger.log(
                channel=channel,
                action="blocked",
                process_name=process_name,
                hits=hits,
                text=text,
                extra={
                    "file_path":  file_path,
                    "risk_score": result.risk_score,
                    "reason":     result.reason,
                },
            )
            if self._on_blocked:
                self._on_blocked(file_path, hits, process_name)
            return SENTRY_BLOCK

        if result.needs_review:
            self._event_logger.log(
                channel=channel,
                action="review",
                process_name=process_name,
                hits=hits,
                text=text,
                extra={
                    "file_path":  file_path,
                    "risk_score": result.risk_score,
                    "reason":     result.reason,
                },
            )

        return SENTRY_ALLOW

    # ── 응답 전송 ──────────────────────────────────────────────────────────

    def _send_reply(self, message_id: int, command: int) -> None:
        reply = SentryReplyMsg()
        reply.Header.Status    = 0           # STATUS_SUCCESS
        reply.Header.MessageId = message_id
        reply.Data.Command     = command

        hr = _fltlib.FilterReplyMessage(
            self._port,
            ctypes.cast(ctypes.byref(reply), ctypes.POINTER(FilterReplyHeader)),
            ctypes.sizeof(SentryReplyMsg),
        )
        if hr != 0:
            logger.error("[FileGuard] FilterReplyMessage 실패 hr=0x%08X", hr & 0xFFFFFFFF)
