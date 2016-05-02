#define WIN32_LEAN_AND_MEAN
#define STRICT
#define _ATL_NO_AUTOMATIC_NAMESPACE
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winternl.h>
#include <pathcch.h>
#include <atlalloc.h>
#include <atlbase.h>
#include <atlchecked.h>
#include <atlcore.h>
#include <array>
#include <memory>
#include <string>
#include <cstdint>
#include "lxsstat.hpp"
#pragma comment(lib, "pathcch")
#pragma comment(lib, "ntdll")

#pragma region
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
struct FILE_FULL_EA_INFORMATION
{
	ULONG  NextEntryOffset;
	UCHAR  Flags;
	UCHAR  EaNameLength;
	USHORT EaValueLength;
	CHAR   EaName[ANYSIZE_ARRAY];
};
struct FILE_GET_EA_INFORMATION
{
	ULONG NextEntryOffset;
	UCHAR EaNameLength;
	CHAR  EaName[ANYSIZE_ARRAY];
};
constexpr size_t MAXIMUM_LENGTH_OF_EA_NAME = (std::numeric_limits<decltype(FILE_FULL_EA_INFORMATION::EaNameLength)>::max)();
constexpr size_t MAXIMUM_LENGTH_OF_EA_VALUE = (std::numeric_limits<decltype(FILE_FULL_EA_INFORMATION::EaValueLength)>::max)();
#pragma endregion

namespace Lxss
{
	const auto lxss_root = []()->std::wstring
	{
		WCHAR temp[MAX_PATH];
		if (!ExpandEnvironmentStringsW(LR"(%LOCALAPPDATA%\lxss)", temp, ARRAYSIZE(temp)))
		{
			ATL::AtlThrowLastWin32();
		}
		return temp;
	}();
	std::wstring realpath(std::wstring path)
	{
		_RPT1(_CRT_WARN, "realpath(<%ls)\n", path.c_str());
		if (path[0] == L'/')
		{
			for (size_t pos = path.find(L'#'); pos != std::string::npos; pos = path.find(L'#', pos))
			{
				path.insert(++pos, L"0023");
			}
			for (size_t pos = path.find(L':'); pos != std::string::npos; pos = path.find(L':', pos))
			{
				path[pos] = L'#';
				path.insert(++pos, L"003A");
			}
			bool need_reloc = false;
			const PCWSTR reloc_directory[] = {
				L"/root",
				L"/home",
			};
			for (int i = 0; i < _countof(reloc_directory); ++i)
			{
				const size_t reloc_length = wcslen(reloc_directory[i]);
				if (
					wcsncmp(path.c_str(), reloc_directory[i], reloc_length) == 0
					&& (path[reloc_length] == L'\0' || path[reloc_length] == L'/'))
				{
					need_reloc = true;
					break;
				}
			}
			path.insert(0, !need_reloc ? lxss_root + L"\\rootfs" : lxss_root);
		}
		const WCHAR prefix[] = LR"(\\?\)";
		if (!PathIsRelativeW(path.c_str()) && wcsncmp(path.c_str(), prefix, wcslen(prefix)) != 0 && path[0] != '\\')
		{
			path.insert(0, prefix);
		}
		auto stage1 = std::make_unique<WCHAR[]>(PATHCCH_MAX_CCH);
		if (!GetFullPathNameW(path.c_str(), PATHCCH_MAX_CCH, stage1.get(), nullptr))
		{
			ATL::AtlThrowLastWin32();
		}
		std::wstring stage2(stage1.get());
		if (wcsncmp(stage2.c_str(), prefix, wcslen(prefix)) != 0 && !PathIsUNCW(stage2.c_str()))
		{
			stage2.insert(0, prefix);
		}
		_RPT1(_CRT_WARN, "realpath(>%ls)\n", stage2.c_str());
		return stage2;
	}
	std::array<char, 11> mode_tostring(uint32_t st_mode)
	{
		if (S_ISLNK(st_mode))
		{
			return{ "lrwxrwxrwx" };
		}

		std::array<char, 11> result;
		std::get<0>(result) = S_ISDIR(st_mode) ? 'd' : S_ISREG(st_mode) ? '-' : '?';
		std::get<1>(result) = st_mode & S_IRUSR ? 'r' : '-';
		std::get<2>(result) = st_mode & S_IWUSR ? 'w' : '-';
		std::get<3>(result) = st_mode & S_ISUID
			? st_mode & S_IXUSR ? 's' : 'S'
			: st_mode & S_IXUSR ? 'x' : '-';
		std::get<4>(result) = st_mode & S_IRGRP ? 'r' : '-';
		std::get<5>(result) = st_mode & S_IWGRP ? 'w' : '-';
		std::get<6>(result) = st_mode & S_ISGID
			? st_mode & S_IXGRP ? 's' : 'S'
			: st_mode & S_IXGRP ? 'x' : '-';
		std::get<7>(result) = st_mode & S_IROTH ? 'r' : '-';
		std::get<8>(result) = st_mode & S_IWOTH ? 'w' : '-';
		std::get<9>(result) = st_mode & S_ISVTX
			? st_mode & S_IXOTH ? 't' : 'T'
			: st_mode & S_IXOTH ? 'x' : '-';
		std::get<10>(result) = '\0';
		return result;
	}
	_Success_(return == 0) int stat(_In_z_ const wchar_t *__restrict path, _Out_ struct Lxss::stat *__restrict buf)
	{
		auto windows_path = realpath(path);

		ATL::CHandle h(CreateFileW(windows_path.c_str(), FILE_READ_EA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_POSIX_SEMANTICS, nullptr));
		if (h == INVALID_HANDLE_VALUE)
		{
			return -1;
		}

		constexpr size_t EaLength = offsetof(FILE_FULL_EA_INFORMATION, EaName) + MAXIMUM_LENGTH_OF_EA_NAME + MAXIMUM_LENGTH_OF_EA_VALUE;
		ATL::CHeapPtr<FILE_FULL_EA_INFORMATION> Ea;
		Ea.AllocateBytes(EaLength);

		constexpr size_t EaQueryLength = offsetof(FILE_GET_EA_INFORMATION, EaName) + MAXIMUM_LENGTH_OF_EA_NAME;
		ATL::CHeapPtr<FILE_GET_EA_INFORMATION> EaQuery;
		EaQuery.AllocateBytes(EaQueryLength);
		EaQuery->NextEntryOffset = 0;
		EaQuery->EaNameLength = (UCHAR)strlen(LxssEaName);
		ATL::Checked::strcpy_s(EaQuery->EaName, MAXIMUM_LENGTH_OF_EA_NAME, LxssEaName);

		IO_STATUS_BLOCK ea_iob;
		NTSTATUS ea_status = ZwQueryEaFile(h, &ea_iob, Ea, EaLength, FALSE, EaQuery, EaQueryLength, nullptr, TRUE);
		if (NT_ERROR(ea_status))
		{
			SetLastError(ea_status);
			return -1;
		}
		// If EaList != null ZwQueryEaFile() always return STATUS_SUCCESS even EA not found.
		if (Ea->EaValueLength != sizeof(LXATTRB))
		{
			SetLastError((ULONG)STATUS_NO_EAS_ON_FILE);
			return -1;
		}
		_ASSERTE(strcmp(Ea->EaName, LxssEaName) == 0);
		const LXATTRB* const lxattr = (LXATTRB*)&Ea->EaName[Ea->EaNameLength + 1];

		auto file_std_info = std::make_unique<FILE_STANDARD_INFO>();
		if (!GetFileInformationByHandleEx(h, FileStandardInfo, file_std_info.get(), sizeof(FILE_STANDARD_INFO)))
		{
			return -1;
		}
		auto file_storage_info = std::make_unique<FILE_STORAGE_INFO>();
		if (!GetFileInformationByHandleEx(h, FileStorageInfo, file_storage_info.get(), sizeof(FILE_STORAGE_INFO)))
		{
			return -1;
		}
		auto file_id_info = std::make_unique<FILE_ID_INFO>();
		if (!GetFileInformationByHandleEx(h, FileIdInfo, file_id_info.get(), sizeof(FILE_ID_INFO)))
		{
			return -1;
		}

		// Always 0 ?
		buf->st_dev = 0;
		buf->FileId = file_id_info->FileId;
		// When directory, Linux subsystem always 2. Wont add each sub directory '..'.
		buf->st_nlink = !lxattr->permission.is_directory ? file_std_info->NumberOfLinks : 2;
		buf->st_atim.tv_sec = lxattr->atime;
		buf->st_atim.tv_nsec = lxattr->atime_extra;
		buf->st_mtim.tv_sec = lxattr->mtime;
		buf->st_mtim.tv_nsec = lxattr->mtime_extra;
		buf->st_ctim.tv_sec = lxattr->ctime;
		buf->st_ctim.tv_nsec = lxattr->ctime_extra;
		buf->st_birthtim.tv_sec = 0;
		buf->st_birthtim.tv_nsec = 0;
		buf->st_size = !lxattr->permission.is_directory ? file_std_info->EndOfFile.QuadPart : 0;
		buf->st_blksize = file_storage_info->PhysicalBytesPerSectorForPerformance;
		buf->st_blocks = file_std_info->AllocationSize.QuadPart / 512;
		buf->st_uid = lxattr->st_uid;
		buf->st_gid = lxattr->st_gid;
		buf->st_mode = lxattr->st_mode;

		return 0;
	}
}