#define _ATL_NO_AUTOMATIC_NAMESPACE
#define _CSTRING_DISABLE_NARROW_WIDE_CONVERSION
#include <atlalloc.h>
#include <atlbase.h>
#include <atlstr.h>
#include <windows.h>
#include <winioctl.h>
#include <winternl.h>
#include <pathcch.h>
#include <list>
#include <memory>
#include "fileopen.hpp"
#pragma comment(lib, "ntdll")
#pragma comment(lib, "pathcch")

const ULONG SYMLINK_FLAG_RELATIVE = 1;
struct REPARSE_DATA_BUFFER
{
	ULONG  ReparseTag;
	USHORT ReparseDataLength;
	USHORT Reserved;
	union {
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			ULONG  Flags;
			WCHAR  PathBuffer[1];
		} SymbolicLinkReparseBuffer;
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			WCHAR  PathBuffer[1];
		} MountPointReparseBuffer;
	};
};
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
			return *this;
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
		SetLastError(ERROR_FILE_NOT_FOUND);
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
	NTSTATUS status = NtOpenFile(&h, FILE_GENERIC_READ, &obj_attr, &iob, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT);
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
	if (PathIsUNCW(full_path) || PathIsRelativeW(full_path) || full_path[0] == L'\\')
	{
		SetLastError(ERROR_NOT_SUPPORTED);
		return nullptr;
	}
	PCWSTR root;
	ATLENSURE_SUCCEEDED(PathCchSkipRoot(full_path, &root));
	int pos = static_cast<int>(root - full_path);
	ATL::CHandle2 volume(CreateFileW(ATL::CStringW(full_path, pos), FILE_LIST_DIRECTORY | FILE_TRAVERSE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
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
	std::list<ATL::CStringW> components;
	for (ATL::CStringW path; path = full_path.Tokenize(L"\\", pos), pos != -1;)
	{
		if (wcscmp(path, L".") == 0)
		{
			continue;
		}
		else if (wcscmp(path, L"..") == 0)
		{
			components.pop_back();
		}
		else
		{
			components.emplace_back(path);
		}
	}
	ATL::CHandle2 parent = volume;
	ATL::CHandle2 node = nullptr;
	int visited = 0;
	for (auto it = components.begin(), end = components.end(); it != end; ++it)
	{
		if (std::unique_ptr<FILE_ID_128> child = IterateDirectory(parent, *it))
		{
			FILE_ID_DESCRIPTOR Id = { sizeof Id };
			Id.Type = ExtendedFileIdType;
			Id.ExtendedFileId = *child;
			node = OpenFileById(volume, &Id, FILE_GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
		}
		else
		{
			node = OpenAtNoCase(parent, *it);
		}
		if (!node)
		{
			_CrtDbgBreak();
			return nullptr;
		}
		FILE_ATTRIBUTE_TAG_INFO attr_tag;
		if (GetFileInformationByHandleEx(node, FileAttributeTagInfo, &attr_tag, sizeof attr_tag) && attr_tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
		{
			if (++visited >= 64)
			{
				_CrtDbgBreak();
				SetLastError(ERROR_CANT_RESOLVE_FILENAME);
				return nullptr;
			}
			ATL::CHeapPtr<REPARSE_DATA_BUFFER> reparse_point;
			ATLENSURE(reparse_point.AllocateBytes(MAXIMUM_REPARSE_DATA_BUFFER_SIZE));
			ULONG junk;
			ATLENSURE(DeviceIoControl(node, FSCTL_GET_REPARSE_POINT, nullptr, 0, reparse_point, MAXIMUM_REPARSE_DATA_BUFFER_SIZE, &junk, nullptr));
			if (reparse_point->ReparseTag == IO_REPARSE_TAG_SYMLINK)
			{
				ATL::CStringW sym_path(&reparse_point->SymbolicLinkReparseBuffer.PathBuffer[reparse_point->SymbolicLinkReparseBuffer.SubstituteNameOffset / sizeof(WCHAR)], reparse_point->SymbolicLinkReparseBuffer.SubstituteNameLength / sizeof(WCHAR));
				auto sym_it = it;
				int sym_pos = reparse_point->SymbolicLinkReparseBuffer.Flags == SYMLINK_FLAG_RELATIVE ? 0 : 4;
				for (ATL::CStringW path; path = sym_path.Tokenize(L"\\", sym_pos), sym_pos != -1; )
				{
					if (wcscmp(path, L".") == 0)
					{
						continue;
					}
					else if (wcscmp(path, L"..") == 0)
					{
						components.pop_back();
					}
					else
					{
						components.emplace_back(path);
					}
				}
				if (reparse_point->SymbolicLinkReparseBuffer.Flags == 0)
				{
					_ASSERTE(wcsncmp(sym_path, LR"(\??\)", 4) == 0);
					(*++it).AppendChar(L'\\');
					volume = CreateFileW(*it, FILE_LIST_DIRECTORY | FILE_TRAVERSE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
					parent = volume;
				}
				else if (reparse_point->SymbolicLinkReparseBuffer.Flags == SYMLINK_FLAG_RELATIVE)
				{
					/* No thing to do. */
				}
				else
				{
					_CrtDbgBreak();
					return nullptr;
				}
			}
			else if (reparse_point->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT)
			{
				ATL::CStringW mount_path(&reparse_point->MountPointReparseBuffer.PathBuffer[reparse_point->MountPointReparseBuffer.SubstituteNameOffset / sizeof(WCHAR)], reparse_point->MountPointReparseBuffer.SubstituteNameLength / sizeof(WCHAR));
				if (wcsncmp(mount_path, LR"(\??\Volume)", 10) == 0)
				{
					volume = CreateFileW(mount_path, FILE_LIST_DIRECTORY | FILE_TRAVERSE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
					parent = volume;
				}
				else if (wcsncmp(mount_path, LR"(\??\)", 4) == 0)
				{
					int mount_pos = 4;
					auto mount_it = it;
					for (ATL::CStringW path; path = mount_path.Tokenize(L"\\", mount_pos), mount_pos != -1; )
					{
						mount_it = components.emplace(mount_it, path);
					}
					(*++it).AppendChar(L'\\');
					volume = CreateFileW(*it, FILE_LIST_DIRECTORY | FILE_TRAVERSE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
					parent = volume;
				}
				else
				{
					_CrtDbgBreak();
					return nullptr;
				}
			}
			else
			{
				if (std::next(it) == components.end())
				{
					return node.Detach();
				}
				else
				{
					_CrtDbgBreak();
					return nullptr;
				}
			}
		}
		else
		{
			parent = node;
		}
	}
	return node.Detach();
}