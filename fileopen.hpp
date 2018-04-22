#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

_Success_(return != nullptr)
HANDLE OpenFileCaseSensitive(_In_z_ PCWSTR lpFileName, _In_ ULONG dwDesiredAccess);