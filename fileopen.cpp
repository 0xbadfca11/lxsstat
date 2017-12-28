#define WIN32_LEAN_AND_MEAN
#define STRICT_GS_ENABLED
#define _ATL_NO_AUTOMATIC_NAMESPACE
#define _CSTRING_DISABLE_NARROW_WIDE_CONVERSION
#include <atlalloc.h>
#include <atlbase.h>
#include <atlstr.h>
#include <windows.h>
#include <pathcch.h>
#include <list>
#include <optional>
#include "fileopen.hpp"
#include "chandle2.hpp"
#pragma comment(lib, "pathcch")

bool PickNextEntry(const FILE_ID_EXTD_DIR_INFO*& p) noexcept
{
	_ASSERT(p);
	if (p->NextEntryOffset)
	{
		p = reinterpret_cast<const FILE_ID_EXTD_DIR_INFO*>(reinterpret_cast<uintptr_t>(p) + p->NextEntryOffset);
		return true;
	}
	else
	{
		return false;
	}
}
std::optional<FILE_ID_128> IterateDirectory(HANDLE directory, PCWSTR target_name)
{
	const size_t target_name_len = wcslen(target_name);
	const size_t buf_size = 1024 * 1024;
	ATL::CHeapPtr<FILE_ID_EXTD_DIR_INFO> dir_info;
	ATLENSURE(dir_info.AllocateBytes(buf_size));
	if (GetFileInformationByHandleEx(directory, FileIdExtdDirectoryRestartInfo, dir_info, buf_size))
	{
		do {
			const FILE_ID_EXTD_DIR_INFO* dir_ptr = dir_info;
			do
			{
				const size_t dentry_len = dir_ptr->FileNameLength / sizeof(WCHAR);
				if (target_name_len == dentry_len && wcsncmp(dir_ptr->FileName, target_name, target_name_len) == 0)
				{
					return dir_ptr->FileId;
				}
			} while (PickNextEntry(dir_ptr));
		} while (GetFileInformationByHandleEx(directory, FileIdExtdDirectoryInfo, dir_info, buf_size));
		SetLastError(ERROR_FILE_NOT_FOUND);
	}
	return std::nullopt;
}
_Success_(return != nullptr)
HANDLE OpenFileCaseSensitive(ATL::CStringW full_path)
{
	if (PathIsUNCW(full_path) || PathIsRelativeW(full_path))
	{
		SetLastError(ERROR_NOT_SUPPORTED);
		return nullptr;
	}
	PCWSTR root;
	ATLENSURE_SUCCEEDED(PathCchSkipRoot(full_path, &root));
	int pos = static_cast<int>(root - full_path);
	ATL::CHandle2 volume(CreateFileW(ATL::CStringW(full_path, pos), FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
	if (!volume)
	{
		return nullptr;
	}
	ULONG fs_flags;
	ATLENSURE(GetVolumeInformationByHandleW(volume, nullptr, 0, nullptr, nullptr, &fs_flags, nullptr, 0));
	if (!(fs_flags & FILE_SUPPORTS_OPEN_BY_FILE_ID))
	{
		SetLastError(ERROR_NOT_SUPPORTED);
		return nullptr;
	}
	struct node
	{
		node() = default;
		node(const ATL::CStringW& name) : name(name) {}
		~node() = default;
		ATL::CStringW name;
		ATL::CHandle2 handle;
	};
	std::list<node> path_components;
	for (ATL::CStringW path; path = full_path.Tokenize(L"\\", pos), pos != -1;)
	{
		if (wcscmp(path, L".") == 0)
		{
			continue;
		}
		else if (wcscmp(path, L"..") == 0)
		{
			path_components.pop_back();
		}
		else
		{
			path_components.emplace_back(path);
		}
	}
	HANDLE parent = volume;
	for (auto it = path_components.begin(), end = path_components.end(); it != end; ++it)
	{
		const bool is_last = std::next(it) == end;
		if (std::optional<FILE_ID_128> child = IterateDirectory(parent, it->name))
		{
			FILE_ID_DESCRIPTOR Id = { sizeof Id };
			Id.Type = ExtendedFileIdType;
			Id.ExtendedFileId = *child;
			it->handle = OpenFileById(volume, &Id, is_last ? GENERIC_READ : FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
		}
		if (!it->handle)
		{
			_CrtDbgBreak();
			return nullptr;
		}
		if (is_last)
		{
			return it->handle.Detach();
		}
		FILE_BASIC_INFO file_basic_info;
		ATLENSURE(GetFileInformationByHandleEx(it->handle, FileBasicInfo, &file_basic_info, sizeof file_basic_info));
		if (!(file_basic_info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			SetLastError(ERROR_FILE_NOT_FOUND);
			_CrtDbgBreak();
			return nullptr;
		}
		parent = it->handle;
	}
	__assume(0);
}