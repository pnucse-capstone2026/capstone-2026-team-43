/*
 * sentry_filter.c  —  Sentry DLP 미니필터 드라이버
 *
 * 빌드 요구사항
 *   - Windows Driver Kit (WDK) 10.0.26100.x 이상
 *   - Visual Studio 2022 + WDK 확장
 *   - CMakeLists.txt (이 디렉토리)로 빌드
 *
 * 동작 원리
 *   1. IRP_MJ_CREATE pre-op: 쓰기/생성 요청이 USB 또는 네트워크 공유를
 *      대상으로 하면 유저모드 에이전트(file_guard.py)로 알림 전송
 *   2. 에이전트가 DLP 분석(정규식 → AI) 후 Allow/Block 응답
 *   3. Block 응답 → STATUS_ACCESS_DENIED 반환 (I/O 차단)
 *   4. Allow 또는 타임아웃(Fail-Open) → IRP 계속 처리
 *
 * IRP_MJ_WRITE pre-op: CREATE에서 놓친 직접 쓰기 요청 방어
 * IRP_MJ_SET_INFORMATION: RENAME/MOVE-TO 경로 변경 감시
 *
 * Altitude: 265000  (FSFilter Activity Monitor / Content Screener 범위)
 */

#include "sentry_filter.h"

/* ── 드라이버 전역 ──────────────────────────────────────────────────────── */

SENTRY_GLOBALS g_Sentry = { 0 };

/* ── FltMgr 등록 테이블 ─────────────────────────────────────────────────── */

CONST FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    {
        IRP_MJ_CREATE,
        0,
        SentryPreCreate,
        NULL    /* PostCreate 불필요 */
    },
    {
        IRP_MJ_WRITE,
        0,
        SentryPreWrite,
        NULL
    },
    {
        IRP_MJ_SET_INFORMATION,
        0,
        SentryPreSetInformation,
        NULL
    },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),       /* Size */
    FLT_REGISTRATION_VERSION,       /* Version */
    0,                              /* Flags */
    NULL,                           /* Context */
    g_Callbacks,                    /* OperationRegistration */
    SentryUnload,                   /* FilterUnloadCallback */
    SentryInstanceSetup,            /* InstanceSetupCallback */
    SentryInstanceQueryTeardown,    /* InstanceQueryTeardownCallback */
    NULL,                           /* InstanceTeardownStartCallback */
    NULL,                           /* InstanceTeardownCompleteCallback */
    NULL, NULL, NULL                /* GenerateFileName, NormalizeNameComponent, etc. */
};

/* ── DriverEntry ────────────────────────────────────────────────────────── */

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS            status;
    UNICODE_STRING      portName;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES   oa;

    UNREFERENCED_PARAMETER(RegistryPath);

    g_Sentry.DriverObject = DriverObject;
    KeInitializeEvent(&g_Sentry.ClientConnected, NotificationEvent, FALSE);

    /* 필터 등록 */
    status = FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_Sentry.Filter);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Sentry] FltRegisterFilter 실패: 0x%08X\n", status));
        return status;
    }

    /* 유저모드 통신 포트 생성
     * 보안 설명자: Administrators + SYSTEM만 연결 가능 */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    RtlInitUnicodeString(&portName, SENTRY_PORT_NAME);
    InitializeObjectAttributes(
        &oa,
        &portName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        sd
    );

    status = FltCreateCommunicationPort(
        g_Sentry.Filter,
        &g_Sentry.ServerPort,
        &oa,
        NULL,               /* ServerPortCookie */
        SentryPortConnect,
        SentryPortDisconnect,
        NULL,               /* MessageNotifyCallback: 커널이 메시지 받을 일 없음 */
        1                   /* MaxConnections: 에이전트 1개만 */
    );

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        KdPrint(("[Sentry] FltCreateCommunicationPort 실패: 0x%08X\n", status));
        goto Cleanup;
    }

    /* 필터 시작 */
    status = FltStartFiltering(g_Sentry.Filter);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[Sentry] FltStartFiltering 실패: 0x%08X\n", status));
        FltCloseCommunicationPort(g_Sentry.ServerPort);
        goto Cleanup;
    }

    KdPrint(("[Sentry] 드라이버 로드 완료. Port=%wZ\n", &portName));
    return STATUS_SUCCESS;

Cleanup:
    FltUnregisterFilter(g_Sentry.Filter);
    return status;
}

/* ── 언로드 ─────────────────────────────────────────────────────────────── */

NTSTATUS
SentryUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    KdPrint(("[Sentry] 드라이버 언로드. 차단=%ld / 총=%ld\n",
             g_Sentry.TotalBlocked, g_Sentry.TotalIntercepted));

    FltCloseCommunicationPort(g_Sentry.ServerPort);
    FltUnregisterFilter(g_Sentry.Filter);
    return STATUS_SUCCESS;
}

/* ── 인스턴스 콜백 ──────────────────────────────────────────────────────── */

NTSTATUS
SentryInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS    FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE              VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE      VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    /* FAT/NTFS 볼륨과 네트워크 파일시스템에만 부착 */
    if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {
        return STATUS_SUCCESS;  /* 네트워크 공유 감시 */
    }

    if (VolumeFilesystemType == FLT_FSTYPE_NTFS ||
        VolumeFilesystemType == FLT_FSTYPE_FAT  ||
        VolumeFilesystemType == FLT_FSTYPE_EXFAT) {
        return STATUS_SUCCESS;
    }

    /* CD-ROM, RAW 등은 건너뜀 */
    return STATUS_FLT_DO_NOT_ATTACH;
}

NTSTATUS
SentryInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS             FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

/* ── 포트 연결·해제 콜백 ────────────────────────────────────────────────── */

NTSTATUS
SentryPortConnect(
    _In_     PFLT_PORT ClientPort,
    _In_opt_ PVOID     ServerPortCookie,
    _In_opt_ PVOID     ConnectionContext,
    _In_     ULONG     SizeOfContext,
    _Out_    PVOID    *ConnectionPortCookie
)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    g_Sentry.ClientPort = ClientPort;
    KeSetEvent(&g_Sentry.ClientConnected, IO_NO_INCREMENT, FALSE);
    *ConnectionPortCookie = NULL;

    KdPrint(("[Sentry] 에이전트 연결됨\n"));
    return STATUS_SUCCESS;
}

VOID
SentryPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(g_Sentry.Filter, &g_Sentry.ClientPort);
    KeClearEvent(&g_Sentry.ClientConnected);
    KdPrint(("[Sentry] 에이전트 연결 끊김\n"));
}

/* ══════════════════════════════════════════════════════════════════════════
 * 유틸리티 함수
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * 볼륨의 USB / 네트워크 여부를 SENTRY_FLAG_* 비트 조합으로 반환.
 */
ULONG
SentryGetVolumeFlags(
    _In_ PFLT_INSTANCE Instance
)
{
    NTSTATUS                status;
    IO_STATUS_BLOCK         ioSb;
    FILE_FS_DEVICE_INFORMATION devInfo = { 0 };
    ULONG                   flags = 0;

    status = FltQueryVolumeInformation(
        Instance,
        &ioSb,
        &devInfo,
        sizeof(devInfo),
        FileFsDeviceInformation
    );

    if (!NT_SUCCESS(status)) {
        return 0;
    }

    if (devInfo.DeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM ||
        devInfo.DeviceType == FILE_DEVICE_SMB) {
        flags |= SENTRY_FLAG_NETWORK;
    }

    if (devInfo.Characteristics & FILE_REMOVABLE_MEDIA) {
        flags |= SENTRY_FLAG_USB;
    }

    return flags;
}

/*
 * 파일의 볼륨-포함 전체 경로 조회.
 * 성공 시 FilePath->Buffer에 할당된 메모리를 ExFreePoolWithTag(buf, SENTRY_TAG)로 해제.
 */
NTSTATUS
SentryGetFilePath(
    _In_  PFLT_CALLBACK_DATA Data,
    _In_  PFLT_INSTANCE      Instance,
    _Out_ PUNICODE_STRING    FilePath,
    _Out_ PULONG             Length
)
{
    NTSTATUS     status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

    UNREFERENCED_PARAMETER(Instance);
    UNREFERENCED_PARAMETER(Length);

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );

    if (!NT_SUCCESS(status)) {
        FilePath->Buffer = NULL;
        FilePath->Length = 0;
        return status;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (NT_SUCCESS(status)) {
        *FilePath = nameInfo->Name;     /* 포인터 복사 — nameInfo가 살아있는 동안 유효 */
    }

    /* 호출자가 nameInfo를 해제: FltReleaseFileNameInformation(nameInfo) */
    /* 단순화를 위해 여기서는 nameInfo를 out-param으로 반환하지 않고
     * 호출 측에서 FltGetFileNameInformation을 직접 사용한다.           */
    FltReleaseFileNameInformation(nameInfo);
    return status;
}

/*
 * 현재 프로세스의 이미지 파일명(exe 이름)을 Buffer에 복사.
 */
VOID
SentryGetProcessName(
    _Out_writes_(MaxLen) PWCHAR Buffer,
    _In_  ULONG MaxLen
)
{
    PEPROCESS   process;
    PUNICODE_STRING imageName = NULL;
    NTSTATUS    status;

    RtlZeroMemory(Buffer, MaxLen * sizeof(WCHAR));
    process = PsGetCurrentProcess();

    /* PsQueryFullProcessImageName은 PASSIVE_LEVEL에서만 호출 가능 */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        RtlStringCchCopyW(Buffer, MaxLen, L"<unknown>");
        return;
    }

    /* SeLocateProcessImageName: Vista+ 공개 API */
    status = SeLocateProcessImageName(process, &imageName);
    if (NT_SUCCESS(status) && imageName && imageName->Length > 0) {
        /* 전체 경로에서 마지막 '\\' 이후 파일명만 복사 */
        USHORT i = imageName->Length / sizeof(WCHAR);
        while (i > 0 && imageName->Buffer[i - 1] != L'\\') --i;
        RtlStringCchCopyNW(Buffer, MaxLen,
                           imageName->Buffer + i,
                           (imageName->Length / sizeof(WCHAR)) - i);
        ExFreePool(imageName);
    } else {
        RtlStringCchCopyW(Buffer, MaxLen, L"<unknown>");
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 * 유저모드 통신
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * 파일 이벤트를 유저모드 에이전트로 전송하고 응답(Allow/Block)을 받아 반환.
 * 에이전트 미연결 / 타임아웃 → SentryAllow (Fail-Open)
 */
SENTRY_COMMAND
SentrySendAndWait(
    _In_ PSENTRY_NOTIFICATION Notification,
    _In_ LONGLONG             TimeoutMs
)
{
    NTSTATUS            status;
    SENTRY_MESSAGE      sendBuf   = { 0 };
    SENTRY_REPLY_MSG    replyBuf  = { 0 };
    ULONG               replySize = sizeof(SENTRY_REPLY_MSG);
    LARGE_INTEGER       timeout;

    if (g_Sentry.ClientPort == NULL) {
        return SentryAllow;   /* 에이전트 미연결 */
    }

    /* 타임아웃: 음수=상대시간, 100-ns 단위 */
    timeout.QuadPart = -(TimeoutMs * 10000LL);

    RtlCopyMemory(&sendBuf.Data, Notification, sizeof(SENTRY_NOTIFICATION));

    status = FltSendMessage(
        g_Sentry.Filter,
        &g_Sentry.ClientPort,
        &sendBuf.Data,              /* SenderBuffer */
        sizeof(SENTRY_NOTIFICATION),
        &replyBuf.Data,             /* ReplyBuffer */
        &replySize,
        &timeout
    );

    if (status == STATUS_TIMEOUT) {
        KdPrint(("[Sentry] 응답 타임아웃 — Fail-Open\n"));
        return SentryAllow;
    }

    if (!NT_SUCCESS(status)) {
        KdPrint(("[Sentry] FltSendMessage 오류: 0x%08X — Fail-Open\n", status));
        return SentryAllow;
    }

    return replyBuf.Data.Command;
}

/* ══════════════════════════════════════════════════════════════════════════
 * Pre-Operation 콜백
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * 공통 검사 로직.
 * 대상 볼륨이 USB 또는 네트워크 공유이고 쓰기/생성 요청이면
 * 에이전트에 알리고 결과에 따라 IRP를 차단 또는 허용.
 */
static FLT_PREOP_CALLBACK_STATUS
SentryCheckAndDecide(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _In_    ULONG                 ExtraFlags
)
{
    ULONG                   volFlags;
    SENTRY_NOTIFICATION     notif   = { 0 };
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS                status;
    SENTRY_COMMAND          cmd;

    /* 볼륨 유형 검사 — 대상이 아니면 즉시 통과 */
    volFlags = SentryGetVolumeFlags(FltObjects->Instance);
    if ((volFlags & (SENTRY_FLAG_USB | SENTRY_FLAG_NETWORK)) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    InterlockedIncrement(&g_Sentry.TotalIntercepted);

    /* 알림 구조체 채우기 */
    notif.Flags     = volFlags | ExtraFlags;
    notif.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    notif.FileSize  = -1;

    /* 파일 경로 */
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );
    if (NT_SUCCESS(status)) {
        FltParseFileNameInformation(nameInfo);
        RtlStringCchCopyNW(
            notif.FilePath,
            SENTRY_MAX_PATH_LEN,
            nameInfo->Name.Buffer,
            min(nameInfo->Name.Length / sizeof(WCHAR), SENTRY_MAX_PATH_LEN - 1)
        );
        FltReleaseFileNameInformation(nameInfo);
    }

    /* 프로세스 이름 */
    SentryGetProcessName(notif.ProcessName, SENTRY_MAX_PROCNAME_LEN);

    /* 에이전트 전송 + 결과 대기 (최대 5초) */
    cmd = SentrySendAndWait(&notif, 5000);

    if (cmd == SentryBlock) {
        InterlockedIncrement(&g_Sentry.TotalBlocked);
        KdPrint(("[Sentry] 차단: %ws by %ws\n",
                 notif.FilePath, notif.ProcessName));

        Data->IoStatus.Status      = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ── IRP_MJ_CREATE pre-op ───────────────────────────────────────────────── */

FLT_PREOP_CALLBACK_STATUS
SentryPreCreate(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Out_   PVOID                *CompletionContext
)
{
    ACCESS_MASK desiredAccess;
    ULONG       createOptions;

    UNREFERENCED_PARAMETER(CompletionContext);

    /* 커널 모드 I/O는 신뢰 — 건너뜀 */
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    createOptions = Data->Iopb->Parameters.Create.Options;

    /* 쓰기·삭제·추가 접근 요청이 없으면 건너뜀 */
    if (!(desiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA |
                           FILE_WRITE_ATTRIBUTES | DELETE | GENERIC_WRITE |
                           GENERIC_ALL))) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 디렉토리 열기 요청은 건너뜀 */
    if (createOptions & FILE_DIRECTORY_FILE) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return SentryCheckAndDecide(Data, FltObjects, SENTRY_FLAG_WRITE);
}

/* ── IRP_MJ_WRITE pre-op ────────────────────────────────────────────────── */

FLT_PREOP_CALLBACK_STATUS
SentryPreWrite(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Out_   PVOID                *CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return SentryCheckAndDecide(Data, FltObjects, SENTRY_FLAG_WRITE);
}

/* ── IRP_MJ_SET_INFORMATION pre-op (이름 변경/이동 감시) ──────────────── */

FLT_PREOP_CALLBACK_STATUS
SentryPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Out_   PVOID                *CompletionContext
)
{
    FILE_INFORMATION_CLASS infoClass;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    /* 이름 변경(RENAME) / 하드링크 생성만 감시 */
    if (infoClass != FileRenameInformation &&
        infoClass != FileRenameInformationEx &&
        infoClass != FileLinkInformation) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return SentryCheckAndDecide(Data, FltObjects, SENTRY_FLAG_RENAME);
}
