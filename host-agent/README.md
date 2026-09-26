# sentry-host-agent

Windows 호스트 에이전트 — 클립보드·네트워크·USB 매체 통제를 통한 정보 유출 방지.

## 구조

```
sentry-host-agent/
├── clipboard_ctrl/     # [1단계] 클립보드 제어 (Python)
├── network_hook/       # [2단계] 메일/메신저 통제 (추후 C/C++ DLL)
├── usb_minifilter/     # [3단계] USB 매체 제어 (추후 커널 드라이버)
├── core_comm/          # 공통 서버 통신 및 이벤트 로깅
├── config/             # settings.yaml, regex_patterns.json
├── tests/
├── main_agent.py       # 에이전트 진입점
└── requirements.txt
```

## 빠른 시작

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python main_agent.py
```

## 테스트

```bash
pytest tests/
```
