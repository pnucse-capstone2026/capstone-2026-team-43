"""usb_minifilter — 파일시스템 미니필터 드라이버 연동 모듈.

구성
----
driver/          C 커널 드라이버 소스 (WDK 빌드)
  sentry_comm.h      커널↔유저 공유 메시지 정의
  sentry_filter.h    드라이버 내부 헤더
  sentry_filter.c    미니필터 드라이버 구현
  sentry_filter.inf  설치 INF
  CMakeLists.txt     WDK CMake 빌드 설정

install/         설치 스크립트
  install.ps1        드라이버 복사 + 서비스 등록 + fltMC load
  uninstall.ps1      fltMC unload + 서비스 제거

file_guard.py    Python 유저모드 클라이언트
  FileGuard        필터 포트 연결 → 이벤트 수신 → DLP 분석 → 응답
"""

from usb_minifilter.file_guard import FileGuard

__all__ = ["FileGuard"]
