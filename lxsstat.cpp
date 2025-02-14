#define WIN32_LEAN_AND_MEAN
#define WIL_SUPPRESS_EXCEPTIONS
#define WIL_USE_STL 1
#define WIN32_NO_STATUS
#define _CRTDBG_MAP_ALLOC
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winternl.h>
#include <winioctl.h>
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <wil/resource.h>
#include <wil/result.h>
#include <crtdbg.h>
#include "lxsstat.hpp"
#pragma comment(lib, "ntdll")

EXTERN_C NTSYSAPI NTSTATUS NTAPI ZwQueryEaFile(
	_In_     HANDLE           FileHandle,
	_Out_    PIO_STATUS_BLOCK IoStatusBlock,
	_Out_    PVOID            Buffer,
	_In_     ULONG            Length,
	_In_     BOOLEAN          ReturnSingleEntry,
	_In_opt_ PVOID            EaList,
	_In_     ULONG            EaListLength,
	_In_opt_ PULONG           EaIndex,
	_In_     BOOLEAN          RestartScan
);
// "this attribute has a no minimum size but a maximum of 65536 bytes."
// https://flatcap.org/linux-ntfs/ntfs/attributes/ea.html
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/0eb94f48-6aac-41df-a878-79f4dcfd8989
// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ns-wdm-_file_full_ea_information
struct FILE_FULL_EA_INFORMATION
{
	ULONG  NextEntryOffset;
	UCHAR  Flags;
	UCHAR  EaNameLength;
	USHORT EaValueLength;
	CHAR   EaName[UINT16_MAX - 8];
};
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/79dc1ea1-158c-4b24-b0e1-8c16c7e2af6b
// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntifs/ns-ntifs-_file_get_ea_information
struct FILE_GET_EA_INFORMATION
{
	ULONG NextEntryOffset;
	// "The EaName MUST be less than 255 characters"
	// "This value MUST NOT include the terminating null character to EaName."
	UCHAR EaNameLength;
	// "contains the extended attribute name followed by a single terminating null character byte."
	CHAR  EaName[UINT8_MAX];
};

namespace Lxss
{
	bool GetEA(HANDLE file, PCSTR ea_name, void* ea, size_t ea_size)
	{
		const size_t ea_name_len = strlen(ea_name);
		if (ea_name_len >= sizeof FILE_GET_EA_INFORMATION::EaName)
		{
			SetLastError(ERROR_INVALID_PARAMETER);
			return false;
		}
		FILE_GET_EA_INFORMATION EaQuery;
		EaQuery.NextEntryOffset = 0;
		EaQuery.EaNameLength = static_cast<UCHAR>(ea_name_len);
		FAIL_FAST_IF(strcpy_s(EaQuery.EaName, ea_name) != 0);
		const auto Ea = std::make_unique_for_overwrite<FILE_FULL_EA_INFORMATION>();

		IO_STATUS_BLOCK ea_iob;
		NTSTATUS ea_status = ZwQueryEaFile(file, &ea_iob, Ea.get(), sizeof(FILE_FULL_EA_INFORMATION), FALSE, &EaQuery, sizeof EaQuery, nullptr, TRUE);
		if (NT_ERROR(ea_status))
		{
			SetLastError(ea_status);
			return false;
		}
		// When EaList != null, ZwQueryEaFile() always return STATUS_SUCCESS even EA not found.
		if (Ea->EaValueLength == 0)
		{
			SetLastError(static_cast<ULONG>(STATUS_NO_EAS_ON_FILE));
			return false;
		}
		_ASSERTE(_stricmp(Ea->EaName, ea_name) == 0);
		if (Ea->EaValueLength > ea_size)
		{
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			return false;
		}
		FAIL_FAST_IF(memcpy_s(ea, ea_size, &Ea->EaName[Ea->EaNameLength + 1], Ea->EaValueLength) != 0);
		return true;
	}
	std::array<char, 11> mode_tostring(uint32_t st_mode) noexcept
	{
		return
		{
			/*[0]*/ S_ISLNK(st_mode) ? 'l' : S_ISDIR(st_mode) ? 'd' : S_ISREG(st_mode) ? '-' : S_ISCHR(st_mode) ? 'c' : S_ISFIFO(st_mode) ? 'p' : S_ISSOCK(st_mode) ? 's' : '?',
			/*[1]*/ st_mode & S_IRUSR ? 'r' : '-',
			/*[2]*/ st_mode & S_IWUSR ? 'w' : '-',
			/*[3]*/ st_mode & S_ISUID ? st_mode & S_IXUSR ? 's' : 'S' : st_mode & S_IXUSR ? 'x' : '-',
			/*[4]*/ st_mode & S_IRGRP ? 'r' : '-',
			/*[5]*/ st_mode & S_IWGRP ? 'w' : '-',
			/*[6]*/ st_mode & S_ISGID ? st_mode & S_IXGRP ? 's' : 'S' : st_mode & S_IXGRP ? 'x' : '-',
			/*[7]*/ st_mode & S_IROTH ? 'r' : '-',
			/*[8]*/ st_mode & S_IWOTH ? 'w' : '-',
			/*[9]*/ st_mode & S_ISVTX ? st_mode & S_IXOTH ? 't' : 'T' : st_mode & S_IXOTH ? 'x' : '-',
			'\0'
		};
	}
	timespec FileTimeToUnixTime(LONG64 ft) noexcept
	{
		const int64_t diff_win_unix = 116444736000000000;
		const int32_t unit = 10000000;
		const int32_t nsec_per_unit = 100;
		return { (ft - diff_win_unix) / unit, static_cast<long>((ft - diff_win_unix) % unit * nsec_per_unit) };
	}
	constexpr uint64_t inline MAKEUINT64(uint32_t low, uint32_t high) noexcept
	{
		return low | high * 1ULL << 32;
	}
	static_assert(MAKEUINT64(0, 1) == 0x1'0000'0000);
	std::wstring A2W(PCSTR str)
	{
		const int cch = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, str, -1, nullptr, 0);
		FAIL_FAST_IF(cch == 0);
		std::wstring wstr(cch - 1, '\0');
		FAIL_FAST_IF(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, str, -1, wstr.data(), cch) == 0);
		return wstr;
	}
	int stat(PCWSTR path, struct Lxss::stat* buf)
	{
		wil::unique_hfile h(CreateFileW(path, FILE_READ_EA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
		if (!h)
		{
			return -1;
		}

		BY_HANDLE_FILE_INFORMATION file_info;
		if (!GetFileInformationByHandle(h.get(), &file_info))
		{
			return -1;
		}
		FILE_BASIC_INFO file_basic_info;
		if (!GetFileInformationByHandleEx(h.get(), FileBasicInfo, &file_basic_info, sizeof file_basic_info))
		{
			return -1;
		}
		FILE_STANDARD_INFO file_std_info;
		if (!GetFileInformationByHandleEx(h.get(), FileStandardInfo, &file_std_info, sizeof file_std_info))
		{
			return -1;
		}
		FILE_ATTRIBUTE_TAG_INFO file_attribute_tag_info;
		if (!GetFileInformationByHandleEx(h.get(), FileAttributeTagInfo, &file_attribute_tag_info, sizeof file_attribute_tag_info))
		{
			return -1;
		}
		FILE_STORAGE_INFO file_storage_info;
		if (!GetFileInformationByHandleEx(h.get(), FileStorageInfo, &file_storage_info, sizeof file_storage_info))
		{
			return -1;
		}

		if (LXATTRB lxattr; GetEA(h.get(), LxssEaName, &lxattr, sizeof lxattr)) [[unlikely]]
		{
			// issue #3
			buf->st_dev = 0;
			buf->st_ino = MAKEUINT64(file_info.nFileIndexLow, file_info.nFileIndexHigh);
			buf->st_nlink = file_std_info.NumberOfLinks;
			buf->st_atim.tv_sec = lxattr.atime;
			buf->st_atim.tv_nsec = lxattr.atime_extra;
			buf->st_mtim.tv_sec = lxattr.mtime;
			buf->st_mtim.tv_nsec = lxattr.mtime_extra;
			buf->st_ctim.tv_sec = lxattr.ctime;
			buf->st_ctim.tv_nsec = lxattr.ctime_extra;
			buf->st_size = S_ISREG(lxattr.st_mode) || S_ISLNK(lxattr.st_mode) ? file_std_info.EndOfFile.QuadPart : (S_ISDIR(lxattr.st_mode)) ? file_storage_info.PhysicalBytesPerSectorForPerformance : 0;
			buf->st_blksize = file_storage_info.PhysicalBytesPerSectorForPerformance;
			buf->st_blocks = !S_ISDIR(lxattr.st_mode) ? file_std_info.AllocationSize.QuadPart / 512 : 0;
			buf->st_uid = lxattr.st_uid;
			buf->st_gid = lxattr.st_gid;
			// issue #4
			_RPT1(_CRT_WARN, "st_rdev?(%08lx)\n", lxattr.unknown2);
			buf->st_rdev = 0;
			buf->st_mode = lxattr.st_mode;

			return 0;
		}

		bool linux_control = false;

		// issue #3
		buf->st_dev = 0;
		buf->st_ino = MAKEUINT64(file_info.nFileIndexLow, file_info.nFileIndexHigh);
		// ?
		buf->st_ino += 2;
		buf->st_nlink = file_std_info.NumberOfLinks;
		buf->st_atim = FileTimeToUnixTime(file_basic_info.LastAccessTime.QuadPart);
		buf->st_mtim = FileTimeToUnixTime(file_basic_info.LastWriteTime.QuadPart);
		buf->st_ctim = FileTimeToUnixTime(file_basic_info.ChangeTime.QuadPart);
		buf->st_size = file_std_info.EndOfFile.QuadPart;
		buf->st_blksize = file_storage_info.PhysicalBytesPerSectorForPerformance;
		buf->st_blocks = !(file_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? file_std_info.AllocationSize.QuadPart / 512 : 0;

		buf->st_uid = 0;
		if (GetEA(h.get(), LX_FILE_METADATA_UID_EA_NAME, &buf->st_uid, sizeof buf->st_uid))
		{
			linux_control = true;
		}

		buf->st_gid = 0;
		if (GetEA(h.get(), LX_FILE_METADATA_GID_EA_NAME, &buf->st_gid, sizeof buf->st_gid))
		{
			linux_control = true;
		}

		// issue #4
		buf->st_rdev = 0;
		if (uint64_t st_rdev; GetEA(h.get(), LX_FILE_METADATA_DEVICE_ID_EA_NAME, &st_rdev, sizeof st_rdev))
		{
			linux_control = true;
		}

		buf->st_mode = 0;
		if (GetEA(h.get(), LX_FILE_METADATA_MODE_EA_NAME, &buf->st_mode, sizeof buf->st_mode))
		{
			linux_control = true;
		}
		if (file_attribute_tag_info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
		{
			if (file_attribute_tag_info.ReparseTag == IO_REPARSE_TAG_LX_SYMLINK)
			{
				// WSL can create symlink even metadata is disabled.
				if (!linux_control)
				{
					buf->st_mode = S_IFLNK | S_IRWXU | S_IRWXG | S_IRWXO;
					linux_control = true;
				}
				if (buf->st_size == 0)
				{
					const wil::unique_process_heap_ptr<REPARSE_GUID_DATA_BUFFER> reparse_buf(static_cast<PREPARSE_GUID_DATA_BUFFER>(HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, MAXIMUM_REPARSE_DATA_BUFFER_SIZE)));
					ULONG junk;
					if (!DeviceIoControl(h.get(), FSCTL_GET_REPARSE_POINT, nullptr, 0, reparse_buf.get(), MAXIMUM_REPARSE_DATA_BUFFER_SIZE, &junk, nullptr))
					{
						return -1;
					}
					buf->st_size = reparse_buf->ReparseDataLength - 4;
					_ASSERT(reparse_buf->ReparseTag == IO_REPARSE_TAG_LX_SYMLINK);
					_ASSERT(reparse_buf->ReparseGuid.Data1 == 2);
				}
			}
			// WSL can create socket even metadata is disabled.
			else if (file_attribute_tag_info.ReparseTag == IO_REPARSE_TAG_AF_UNIX && !linux_control)
			{
				buf->st_mode = S_IFSOCK;
				linux_control = true;
			}
		}
		return linux_control ? 0 : -1;
	}
	int64_t readlink(PCWSTR pathname, std::wstring* buf)
	{
		wil::unique_hfile h(CreateFileW(pathname, FILE_READ_DATA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
		if (!h)
		{
			return -1;
		}
		BY_HANDLE_FILE_INFORMATION file_info;
		if (!GetFileInformationByHandle(h.get(), &file_info))
		{
			return -1;
		}
		if (!(file_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
		{
			SetLastError(ERROR_NOT_A_REPARSE_POINT);
			return -1;
		}
		const wil::unique_process_heap_ptr<REPARSE_GUID_DATA_BUFFER> reparse_buf(static_cast<PREPARSE_GUID_DATA_BUFFER>(HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, MAXIMUM_REPARSE_DATA_BUFFER_SIZE)));
		ULONG junk;
		if (!DeviceIoControl(h.get(), FSCTL_GET_REPARSE_POINT, nullptr, 0, reparse_buf.get(), MAXIMUM_REPARSE_DATA_BUFFER_SIZE, &junk, nullptr))
		{
			return -1;
		}
		if (reparse_buf->ReparseTag != IO_REPARSE_TAG_LX_SYMLINK)
		{
			SetLastError(ERROR_NOT_A_REPARSE_POINT);
			return -1;
		}
		if (file_info.nFileSizeLow == 0 && file_info.nFileSizeHigh == 0)
		{
			reinterpret_cast<PSTR>(&reparse_buf->ReparseGuid)[reparse_buf->ReparseDataLength] = '\0';
			*buf = A2W(reinterpret_cast<PCSTR>(&reparse_buf->ReparseGuid.Data2));
		}
		else [[unlikely]]
		{
			// This limit has no basis.
			const int PATH_MAX = 16 * 1024;
			if (file_info.nFileSizeLow > PATH_MAX)
			{
				SetLastError(ERROR_CANT_RESOLVE_FILENAME);
				return -1;
			}
			const auto buffer = std::make_unique_for_overwrite<char[]>(PATH_MAX);
			ULONG read_size;
			if (!ReadFile(h.get(), buffer.get(), file_info.nFileSizeLow, &read_size, nullptr) || read_size != file_info.nFileSizeLow)
			{
				return -1;
			}
			buffer[read_size] = '\0';
			*buf = A2W(buffer.get());
		}
		return buf->size();
	}
}