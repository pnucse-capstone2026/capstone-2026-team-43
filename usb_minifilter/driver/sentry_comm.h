/*
 * sentry_comm.h
 *
 * 커널 드라이버(sentry_filter.sys) ↔ 유저모드 에이전트(file_guard.py) 간
 * 공유되는 메시지 구조체 정의.
 *
 * 커널에서는 fltKernel.h 포함 후, 유저모드에서는 fltUser.h 포함 후 이 헤더를 include.
 * Python ctypes 측에서는 이 파일을 참고해 동일한 필드 순서·크기로 Structure를 정의한다.
 *
 * ────────────────────────────────────────────────────────────
 *  통신 흐름
 *  Kernel pre-op → FltSendMessage ──▶ FilterGetMessage (Python)
 *                                        DLP 분석 (정규식 + AI)
 *               FltSendMessage ◀── FilterReplyMessage (Python)
 *  Kernel: 허용 또는 STATUS_ACCESS_DENIED 반환
 * ────────────────────────────────────────────────────────────
 */

#pragma once

/* ── 필터 포트 이름 (커널·유저 양쪽에서 동일하게 사용) ───────────────────── */
#define SENTRY_PORT_NAME        L"\\SentryDLPPort"
#define SENTRY_PORT_NAME_USER    "\\\\.\\SentryDLPPort"   /* 유저모드용 (ASCII) */

/* ── 크기 상수 ────────────────────────────────────────────────────────────── */
#define SENTRY_MAX_PATH_LEN     520     /* WCHAR count; MAX_PATH=260 의 2배 여유 */
#define SENTRY_MAX_PROCNAME_LEN 128     /* WCHAR count */

/* ── 파일 시스템 대상 유형 플래그 (Flags 필드에 OR 결합) ──────────────────── */
#define SENTRY_FLAG_USB         0x0001  /* 이동식 미디어 (USB 드라이브 등) */
#define SENTRY_FLAG_NETWORK     0x0002  /* 네트워크 공유 (SMB/UNC) */
#define SENTRY_FLAG_WRITE       0x0010  /* 쓰기 접근 요청 */
#define SENTRY_FLAG_RENAME      0x0020  /* 이름 변경/이동 */

/* ── 커널이 유저에게 보내는 알림 ─────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct _SENTRY_NOTIFICATION {
    ULONG       Flags;                          /* SENTRY_FLAG_* 조합 */
    ULONG       ProcessId;
    LONGLONG    FileSize;                       /* -1 이면 알 수 없음 */
    WCHAR       FilePath[SENTRY_MAX_PATH_LEN];  /* 볼륨 포함 전체 경로 */
    WCHAR       ProcessName[SENTRY_MAX_PROCNAME_LEN];
} SENTRY_NOTIFICATION, *PSENTRY_NOTIFICATION;
#pragma pack(pop)

/* ── 유저가 커널에 돌려주는 응답 ─────────────────────────────────────────── */
typedef enum _SENTRY_COMMAND {
    SentryAllow = 0,   /* I/O 계속 허용 */
    SentryBlock = 1    /* STATUS_ACCESS_DENIED 반환 */
} SENTRY_COMMAND;

#pragma pack(push, 1)
typedef struct _SENTRY_REPLY {
    SENTRY_COMMAND Command;
} SENTRY_REPLY, *PSENTRY_REPLY;
#pragma pack(pop)

/* ── FilterGetMessage/FltSendMessage에 쓰이는 래퍼 구조체 ───────────────── */
/* 커널 → 유저 */
typedef struct _SENTRY_MESSAGE {
    FILTER_MESSAGE_HEADER   Header;   /* fltKernel.h / fltUser.h 제공 */
    SENTRY_NOTIFICATION     Data;
} SENTRY_MESSAGE, *PSENTRY_MESSAGE;

/* 유저 → 커널 */
typedef struct _SENTRY_REPLY_MSG {
    FILTER_REPLY_HEADER     Header;   /* fltKernel.h / fltUser.h 제공 */
    SENTRY_REPLY            Data;
} SENTRY_REPLY_MSG, *PSENTRY_REPLY_MSG;
