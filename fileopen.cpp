#define WIN32_LEAN_AND_MEAN
#define STRICT_GS_ENABLED
#define _ATL_NO_AUTOMATIC_NAMESPACE
#define _ATL_NO_DEFAULT_LIBS
#define _ATL_NO_WIN_SUPPORT
#include <atlalloc.h>
#include <atlbase.h>
#include <windows.h>
#include <pathcch.h>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>
#include <crtdbg.h>
#include "fileopen.hpp"
#include "chandle2.hpp"
#pragma comment(lib, "pathcch")

std::optional<FILE_ID_128> IterateDirectory(_In_ HANDLE directory, _In_z_ PCWSTR target_name)
{
	const size_t target_name_len = wcslen(target_name);
	const int buf_size = 1024 * 1024;
	ATL::CHeapPtr<FILE_ID_EXTD_DIR_INFO> dir_info;
	ATLENSURE(dir_info.AllocateBytes(buf_size));
	if (GetFileInformationByHandleEx(directory, FileIdExtdDirectoryRestartInfo, dir_info, buf_size))
	{
		do {
			const FILE_ID_EXTD_DIR_INFO* dir_ptr = dir_info;
			for (;; reinterpret_cast<uintptr_t&>(dir_ptr) += dir_ptr->NextEntryOffset)
			{
				const size_t dentry_len = dir_ptr->FileNameLength / sizeof(WCHAR);
				if (target_name_len == dentry_len && wcsncmp(dir_ptr->FileName, target_name, target_name_len) == 0)
				{
					return dir_ptr->FileId;
				}
				if (dir_ptr->NextEntryOffset == 0)
				{
					break;
				}
			}
		} while (GetFileInformationByHandleEx(directory, FileIdExtdDirectoryInfo, dir_info, buf_size));
		SetLastError(ERROR_FILE_NOT_FOUND);
	}
	return std::nullopt;
}
_Success_(return != nullptr)
HANDLE OpenFileCaseSensitive(_In_z_ PCWSTR lpFileName, _In_ ULONG dwDesiredAccess)
{
	auto full_path = std::make_unique<WCHAR[]>(PATHCCH_MAX_CCH);
	ATLENSURE(GetCurrentDirectoryW(PATHCCH_MAX_CCH, full_path.get()));
	if (HRESULT result = PathCchCombineEx(full_path.get(), PATHCCH_MAX_CCH, full_path.get(), lpFileName, PATHCCH_ENSURE_IS_EXTENDED_LENGTH_PATH); FAILED(result))
	{
		SetLastError(result);
		return nullptr;
	}
	PCWSTR root;
	ATLENSURE_SUCCEEDED(PathCchSkipRoot(full_path.get(), &root));
	const size_t pos = root - full_path.get();
	if (full_path[pos] == L'\0')
	{
		HANDLE root_directory = CreateFileW(full_path.get(), dwDesiredAccess, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
		return root_directory != INVALID_HANDLE_VALUE ? root_directory : nullptr;
	}
	ATL::CHandle2 volume = CreateFileW(std::wstring(full_path.get(), pos).c_str(), FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
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
	std::vector<std::wstring> path_components;
	{
		std::wstringstream ss(&full_path[pos]);
		std::wstring part;
		while (std::getline(ss, part, L'\\'))
		{
			path_components.emplace_back(std::move(part));
		}
	}
	HANDLE parent = volume;
	ATL::CHandle2 part;
	for (auto it = path_components.cbegin(), last = std::prev(path_components.cend()); ; ++it)
	{
		const bool is_last = it == last;
		const std::optional<FILE_ID_128> child = IterateDirectory(parent, it->c_str());
		if (!child)
		{
			_CrtDbgBreak();
			return nullptr;
		}
		FILE_ID_DESCRIPTOR Id = { sizeof Id, ExtendedFileIdType };
		Id.ExtendedFileId = *child;
		part = OpenFileById(volume, &Id, is_last ? dwDesiredAccess : FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
		if (!part)
		{
			_CrtDbgBreak();
			return nullptr;
		}
		if (is_last)
		{
			return part.Detach();
		}
		FILE_BASIC_INFO file_basic_info;
		ATLENSURE(GetFileInformationByHandleEx(part, FileBasicInfo, &file_basic_info, sizeof file_basic_info));
		if (file_basic_info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
		{
			SetLastError(ERROR_CANT_RESOLVE_FILENAME);
			_CrtDbgBreak();
			return nullptr;
		}
		if (!(file_basic_info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			SetLastError(ERROR_FILE_NOT_FOUND);
			_CrtDbgBreak();
			return nullptr;
		}
		parent = part;
	}
}