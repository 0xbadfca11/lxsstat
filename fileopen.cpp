#define _ATL_NO_AUTOMATIC_NAMESPACE
#define _CSTRING_DISABLE_NARROW_WIDE_CONVERSION
#include <atlalloc.h>
#include <atlbase.h>
#include <atlstr.h>
#include <windows.h>
#include <winternl.h>
#include <memory>
#include "fileopen.hpp"
#pragma comment(lib, "ntdll")

namespace ATL
{
	struct CHandle2 : CHandle
	{
		CHandle2() = default;
		CHandle2(const CHandle2& h)
		{
			ATLENSURE(DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &m_h, 0, FALSE, DUPLICATE_SAME_ACCESS));
		}
		CHandle2(CHandle2&& h) noexcept
		{
			Attach(h.Detach());
		}
		CHandle2(HANDLE h) noexcept
		{
			Attach(h);
		}
		CHandle2& operator=(const CHandle2& h)
		{
			Close();
			ATLENSURE(DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &m_h, 0, FALSE, DUPLICATE_SAME_ACCESS));
		}
		CHandle2& operator=(CHandle2&& h) noexcept
		{
			Attach(h.Detach());
			return *this;
		}
		CHandle2& operator=(HANDLE h) noexcept
		{
			Attach(h);
			return *this;
		}
		~CHandle2() = default;
		void Attach(HANDLE h) noexcept
		{
			Close();
			if (h != INVALID_HANDLE_VALUE)
			{
				CHandle::Attach(h);
			}
		}
	};
}
template <typename T>
bool PickNextEntry(T& p) noexcept
{
	_ASSERT(p);
	if (p->NextEntryOffset)
	{
		p = reinterpret_cast<T>(reinterpret_cast<uintptr_t>(p) + p->NextEntryOffset);
		return true;
	}
	else
	{
		return false;
	}
}
std::unique_ptr<FILE_ID_128> IterateDirectory(const HANDLE directory, const PCWSTR name)
{
	const size_t name_len = wcslen(name);
	const size_t buf_size = 1024 * 1024;
	ATL::CHeapPtr<FILE_ID_EXTD_DIR_INFO> dir_info;
	ATLENSURE(dir_info.AllocateBytes(buf_size));
	if (GetFileInformationByHandleEx(directory, FileIdExtdDirectoryRestartInfo, dir_info, buf_size))
	{
		do {
			const FILE_ID_EXTD_DIR_INFO* dir_ptr = dir_info;
			do
			{
				const size_t len = dir_ptr->FileNameLength / sizeof(WCHAR);
				if (len == name_len && wcsncmp(dir_ptr->FileName, name, name_len) == 0)
				{
					return std::make_unique<FILE_ID_128>(dir_ptr->FileId);
				}
			} while (PickNextEntry(dir_ptr));
		} while (GetFileInformationByHandleEx(directory, FileIdExtdDirectoryInfo, dir_info, buf_size));
	}
	return nullptr;
}
ATL::CHandle2 OpenAtNoCase(const HANDLE directory, const PCWSTR name)
{
	UNICODE_STRING unicode_name;
	RtlInitUnicodeString(&unicode_name, name);
	OBJECT_ATTRIBUTES obj_attr;
	InitializeObjectAttributes(&obj_attr, &unicode_name, OBJ_CASE_INSENSITIVE, directory, nullptr);
	IO_STATUS_BLOCK iob;
	HANDLE h;
	NTSTATUS status = NtOpenFile(&h, FILE_GENERIC_READ, &obj_attr, &iob, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_BY_FILE_ID | FILE_OPEN_REPARSE_POINT);
	if (NT_SUCCESS(status))
	{
		return h;
	}
	else
	{
		SetLastError(RtlNtStatusToDosError(status));
		return nullptr;
	}
}
_Success_(return != nullptr)
HANDLE OpenFileCaseSensitive(ATL::CStringW full_path)
{
	int pos = wcsncmp(full_path, LR"(\\?\)", 4) == 0 ? 7 : 3;
	ATL::CStringW child_name(full_path, pos);
	ATL::CHandle2 node(CreateFileW(child_name, FILE_LIST_DIRECTORY | FILE_TRAVERSE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
	if (!node)
	{
		return nullptr;
	}
	ATL::CHandle2 volume = node;
	while ((child_name = full_path.Tokenize(L"\\", pos)) != L"")
	{
		if (std::unique_ptr<FILE_ID_128> child = IterateDirectory(node, child_name))
		{
			FILE_ID_DESCRIPTOR Id = { sizeof Id };
			Id.Type = ExtendedFileIdType;
			Id.ExtendedFileId = *child;
			node = OpenFileById(volume, &Id, FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
		}
		else
		{
			node = OpenAtNoCase(node, child_name);
		}
		if (!node)
		{
			return nullptr;
		}
	}
	return node.Detach();
}