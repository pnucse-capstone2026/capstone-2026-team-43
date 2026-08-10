"""proxy_cert.py — mitmproxy CA 인증서 설치 / 상태 확인 헬퍼.

사용 방법
---------
  # mitmproxy를 최초 실행해 CA 인증서를 생성한 뒤:
  from network_hook.proxy_cert import ProxyCert
  pc = ProxyCert()
  if not pc.is_installed():
      ok = pc.install()   # 관리자 권한 필요

  # 프록시 설정 on/off:
  pc.enable_system_proxy(port=8082)
  # ...
  pc.disable_system_proxy()

내부 구현
---------
1. mitmproxy CA 생성  : mitmproxy를 --mode regular 로 1회 임시 실행 → CA 파일 생성됨
2. 인증서 설치        : certutil -addstore Root <cert.cer>  (관리자)
3. 시스템 프록시 설정 : winreg  HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings
                        또는 WinHTTP (netsh winhttp set proxy)
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import winreg
from pathlib import Path

logger = logging.getLogger(__name__)

# mitmproxy 기본 CA 경로 (사용자 홈 디렉터리)
_MITM_DIR  = Path.home() / ".mitmproxy"
_CERT_PEM  = _MITM_DIR / "mitmproxy-ca-cert.pem"
_CERT_CER  = _MITM_DIR / "mitmproxy-ca-cert.cer"   # DER 포맷 (Windows certutil 용)

# Windows 레지스트리 프록시 설정 경로
_IE_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

CERT_SUBJECT = "mitmproxy"  # certutil 검색용 subject 키워드


class ProxyCert:
    """CA 인증서 및 시스템 프록시 설정 관리."""

    # ── 인증서 생성 ──────────────────────────────────────────────────────────

    def generate_ca(self, timeout: int = 10) -> bool:
        """
        mitmproxy를 짧게 실행해 CA 인증서를 생성 후 종료.
        이미 존재하면 건너뜀.
        """
        if _CERT_PEM.exists() and _CERT_CER.exists():
            logger.debug("[ProxyCert] CA 이미 존재 → 생성 건너뜀")
            return True

        mitmdump_path = shutil.which("mitmdump") or shutil.which("mitmdump.exe")
        if not mitmdump_path:
            logger.error("[ProxyCert] mitmdump 실행 파일을 찾을 수 없습니다. mitmproxy를 먼저 설치하세요.")
            return False

        logger.info("[ProxyCert] mitmproxy CA 생성 중 …")
        try:
            # --ignore-hosts '.*' 로 실제 트래픽 처리 없이 즉시 종료
            proc = subprocess.run(
                [mitmdump_path, "--ignore-hosts", ".*", "--set", "termlog_verbosity=warn"],
                timeout=timeout,
                capture_output=True,
            )
        except subprocess.TimeoutExpired:
            pass  # 인증서 파일이 생성되면 OK
        except Exception as exc:
            logger.error("[ProxyCert] CA 생성 실패: %s", exc)
            return False

        ok = _CERT_PEM.exists()
        if ok:
            logger.info("[ProxyCert] CA 생성 완료: %s", _CERT_PEM)
        else:
            logger.error("[ProxyCert] CA 파일이 생성되지 않았습니다.")
        return ok

    # ── 인증서 설치 상태 확인 ────────────────────────────────────────────────

    def is_installed(self) -> bool:
        """Windows 루트 인증서 스토어에 mitmproxy CA가 있는지 확인."""
        try:
            result = subprocess.run(
                ["certutil", "-verifystore", "Root", CERT_SUBJECT],
                capture_output=True,
                text=True,
            )
            return CERT_SUBJECT.lower() in result.stdout.lower()
        except Exception:
            return False

    # ── 인증서 설치 ──────────────────────────────────────────────────────────

    def install(self) -> bool:
        """
        mitmproxy CA를 Windows 루트 스토어에 설치.
        ※ 관리자 권한 필요. 권한 없으면 UAC 프롬프트 트리거.
        """
        if not _CERT_CER.exists():
            logger.warning("[ProxyCert] .cer 파일 없음. generate_ca() 먼저 실행 필요.")
            if not self.generate_ca():
                return False

        # PEM → DER 변환 (.cer) — mitmproxy 가 이미 둘 다 생성하지만 만약 없으면 변환
        if not _CERT_CER.exists() and _CERT_PEM.exists():
            try:
                subprocess.run(
                    ["certutil", "-encode", str(_CERT_PEM), str(_CERT_CER)],
                    check=True,
                    capture_output=True,
                )
            except Exception as exc:
                logger.error("[ProxyCert] PEM→DER 변환 실패: %s", exc)
                return False

        logger.info("[ProxyCert] 인증서 설치 중 … (관리자 권한 필요)")
        try:
            result = subprocess.run(
                ["certutil", "-addstore", "Root", str(_CERT_CER)],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                logger.info("[ProxyCert] 인증서 설치 성공")
                return True
            else:
                logger.error("[ProxyCert] 설치 실패 (코드 %d): %s", result.returncode, result.stderr)
                return False
        except Exception as exc:
            logger.error("[ProxyCert] certutil 실행 오류: %s", exc)
            return False

    # ── 인증서 제거 ──────────────────────────────────────────────────────────

    def uninstall(self) -> bool:
        """Windows 루트 스토어에서 mitmproxy CA 제거."""
        try:
            result = subprocess.run(
                ["certutil", "-delstore", "Root", CERT_SUBJECT],
                capture_output=True,
                text=True,
            )
            ok = result.returncode == 0
            if ok:
                logger.info("[ProxyCert] 인증서 제거 성공")
            else:
                logger.warning("[ProxyCert] 제거 실패: %s", result.stderr)
            return ok
        except Exception as exc:
            logger.error("[ProxyCert] 제거 오류: %s", exc)
            return False

    # ── 시스템 프록시 설정 ───────────────────────────────────────────────────

    def enable_system_proxy(self, host: str = "127.0.0.1", port: int = 8082) -> bool:
        """
        HKCU Internet Settings 에 HTTP/HTTPS 프록시 등록.
        레지스트리 변경 → 브라우저 재시작 없이 적용 (WinINet 실시간 반영).
        """
        proxy_server = f"{host}:{port}"
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                _IE_SETTINGS,
                0,
                winreg.KEY_SET_VALUE,
            ) as key:
                winreg.SetValueEx(key, "ProxyEnable",  0, winreg.REG_DWORD,  1)
                winreg.SetValueEx(key, "ProxyServer",  0, winreg.REG_SZ, proxy_server)
                # bypass: localhost / 내부 도메인은 프록시 우회
                winreg.SetValueEx(
                    key, "ProxyOverride", 0, winreg.REG_SZ,
                    "localhost;127.0.0.1;<local>"
                )
            logger.info("[ProxyCert] 시스템 프록시 설정 완료: %s", proxy_server)
            # WinINet 에 프록시 변경 알림 (옵션 — 일부 브라우저용)
            self._notify_proxy_change()
            return True
        except OSError as exc:
            logger.error("[ProxyCert] 레지스트리 프록시 설정 실패: %s", exc)
            return False

    def disable_system_proxy(self) -> bool:
        """시스템 프록시 해제."""
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                _IE_SETTINGS,
                0,
                winreg.KEY_SET_VALUE,
            ) as key:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            logger.info("[ProxyCert] 시스템 프록시 해제 완료")
            self._notify_proxy_change()
            return True
        except OSError as exc:
            logger.error("[ProxyCert] 프록시 해제 실패: %s", exc)
            return False

    def is_proxy_enabled(self) -> bool:
        """현재 시스템 프록시 활성화 여부."""
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                _IE_SETTINGS,
                0,
                winreg.KEY_READ,
            ) as key:
                val, _ = winreg.QueryValueEx(key, "ProxyEnable")
                return bool(val)
        except OSError:
            return False

    def _notify_proxy_change(self) -> None:
        """WinINet / WinHTTP 에 인터넷 설정 변경 통지."""
        try:
            import ctypes
            INTERNET_OPTION_REFRESH          = 37
            INTERNET_OPTION_SETTINGS_CHANGED = 39
            wininet = ctypes.windll.Wininet
            wininet.InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
            wininet.InternetSetOptionW(None, INTERNET_OPTION_REFRESH,          None, 0)
        except Exception:
            pass  # 통지 실패는 무시 (브라우저 재시작으로 대체)

    # ── 유틸 ─────────────────────────────────────────────────────────────────

    @staticmethod
    def cert_path() -> Path:
        return _CERT_CER

    @staticmethod
    def ca_dir() -> Path:
        return _MITM_DIR
