"""네트워크·메일 반출 탐지 모듈.

채널별 구현 현황
----------------
outlook_hook  : Outlook COM ItemSend 이벤트 — Python (win32com)
smtp_proxy    : 로컬 SMTP 프록시 — Python (aiosmtpd)
http_monitor  : HTTP/S 업로드 — 설계 완료, WinDivert 드라이버 필요
file_inspector: 첨부파일 텍스트 추출 공통 유틸 — Python
"""
