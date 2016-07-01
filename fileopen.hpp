#pragma once
#define WIN32_LEAN_AND_MEAN
#define _ATL_NO_AUTOMATIC_NAMESPACE
#define _CSTRING_DISABLE_NARROW_WIDE_CONVERSION
#include <windows.h>
#include <atlstr.h>

_Success_(return != nullptr)
HANDLE OpenFileCaseSensitive(ATL::CStringW full_path);