/*
 * sentry_filter.h  —  드라이버 내부 선언
 */

#pragma once

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "sentry_comm.h"

/* ── 드라이버 전역 상태 ───────────────────────────────────────────────────── */
typedef struct _SENTRY_GLOBALS {
    PDRIVER_OBJECT  DriverObject;
    PFLT_FILTER     Filter;

    /* 유저모드 에이전트와의 통신 포트 */
    PFLT_PORT       ServerPort;         /* FltCreateCommunicationPort 결과 */
    PFLT_PORT       ClientPort;         /* 유저모드가 연결하면 설정됨 */
    KEVENT          ClientConnected;    /* 연결 완료 신호 */

    /* 통계 (DebugView 확인용) */
    LONG            TotalIntercepted;
    LONG            TotalBlocked;
} SENTRY_GLOBALS, *PSENTRY_GLOBALS;

extern SENTRY_GLOBALS g_Sentry;

/* ── 유틸리티 ────────────────────────────────────────────────────────────── */

/*
 * 볼륨 플래그 조회 — USB인지 네트워크 공유인지 반환
 * Return: SENTRY_FLAG_USB | SENTRY_FLAG_NETWORK 중 해당하는 것(들)
 */
ULONG
SentryGetVolumeFlags(
    _In_ PFLT_INSTANCE Instance
);

/*
 * 파일의 전체 경로를 UNICODE_STRING으로 반환.
 * 호출자는 Buffer를 ExFreePoolWithTag로 해제해야 한다.
 */
NTSTATUS
SentryGetFilePath(
    _In_  PFLT_CALLBACK_DATA    Data,
    _In_  PFLT_INSTANCE         Instance,
    _Out_ PUNICODE_STRING       FilePath,
    _Out_ PULONG                Length
);

/*
 * 현재 프로세스의 이미지 이름 (파일명 부분만) 조회.
 */
VOID
SentryGetProcessName(
    _Out_writes_(MaxLen) PWCHAR  Buffer,
    _In_  ULONG                  MaxLen
);

/* ── 유저모드 통신 ────────────────────────────────────────────────────────── */

/*
 * 파일 I/O 이벤트를 유저모드 에이전트로 전송하고 결과를 기다린다.
 * Return: SentryAllow 또는 SentryBlock
 *         연결 없음·타임아웃 시 SentryAllow (Fail-Open 정책)
 */
SENTRY_COMMAND
SentrySendAndWait(
    _In_ PSENTRY_NOTIFICATION Notification,
    _In_ LONGLONG             TimeoutMs       /* 대기 최대 시간 (ms) */
);

/* ── FltMgr 콜백 ──────────────────────────────────────────────────────────── */

FLT_PREOP_CALLBACK_STATUS
SentryPreCreate(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Out_   PVOID                *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
SentryPreWrite(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Out_   PVOID                *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
SentryPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Out_   PVOID                *CompletionContext
);

/* ── 필터 등록·해제 ──────────────────────────────────────────────────────── */

NTSTATUS
SentryPortConnect(
    _In_     PFLT_PORT ClientPort,
    _In_opt_ PVOID     ServerPortCookie,
    _In_opt_ PVOID     ConnectionContext,
    _In_     ULONG     SizeOfContext,
    _Out_    PVOID    *ConnectionPortCookie
);

VOID
SentryPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
);

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
SentryUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
SentryInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS  FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE            VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE    VolumeFilesystemType
);

NTSTATUS
SentryInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS          FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

/* ── 메모리 태그 ──────────────────────────────────────────────────────────── */
#define SENTRY_TAG  'yrtS'   /* 'Stry' little-endian */
