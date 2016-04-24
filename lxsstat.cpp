#define WIN32_LEAN_AND_MEAN
#define STRICT
#define _ATL_NO_AUTOMATIC_NAMESPACE
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winternl.h>
#include <pathcch.h>
#include <atlbase.h>
#include <atlalloc.h>
#include <atlchecked.h>
#include <memory>
#include <mutex>
#include <string>
#include <stdint.h>
#include <time.h>
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
#pragma region
EXTERN_C NTSYSAPI NTSTATUS NTAPI NtQueryVolumeInformationFile(
	_In_  HANDLE           FileHandle,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_Out_ PVOID            FsInformation,
	_In_  ULONG            Length,
	_In_  ULONG            FsInformationClass
);
constexpr ULONG FileFsSizeInformation = 3;
struct FILE_FS_SIZE_INFORMATION
{
	LARGE_INTEGER TotalAllocationUnits;
	LARGE_INTEGER AvailableAllocationUnits;
	ULONG         SectorsPerAllocationUnit;
	ULONG         BytesPerSector;
};
#pragma endregion

constexpr char LxssEaName[] = "LXATTRB";
#include <pshpack1.h>
struct LXATTRB
{
	uint32_t unknown1;
	struct
	{
		uint32_t other : 3;
		uint32_t group : 3;
		uint32_t owner : 3;
		uint32_t sticky : 1;
		uint32_t sgid : 1;
		uint32_t suid : 1;
		uint32_t unknown : 1;
		uint32_t is_symlink : 1;
		uint32_t is_directory : 1;
		uint32_t is_file : 1;
	} permission;
	uint32_t uid;
	uint32_t gid;
	uint32_t unknown2;
	uint32_t atime_extra;
	uint32_t mtime_extra;
	uint32_t ctime_extra;
	uint64_t atime;
	uint64_t mtime;
	uint64_t ctime;
};
#include <poppack.h>
static_assert(sizeof(LXATTRB::permission) == sizeof(uint32_t), "");
static_assert(sizeof(LXATTRB) == 56, "");

const auto lxss_root = []()->std::wstring
{
	WCHAR temp[MAX_PATH];
	if (!ExpandEnvironmentStringsW(LR"(%LOCALAPPDATA%\lxss\)", temp, ARRAYSIZE(temp)))
	{
		ATL::AtlThrowLastWin32();
	}
	return temp;
}();
std::wstring ConvertPOSIX2Windows(std::wstring posix_path)
{
	_ASSERTE(posix_path[0] == L'/');
	bool need_reloc = false;
	const PCWSTR reloc_directory[] = {
		L"/root/",
		L"/home/",
	};
	for (int i = 0; i < _countof(reloc_directory); ++i)
	{
		if (wcsncmp(posix_path.c_str(), reloc_directory[i], wcslen(reloc_directory[i])) == 0 && posix_path.length() > wcslen(reloc_directory[i]))
		{
			need_reloc = true;
			break;
		}
	}
	for (;;)
	{
		auto pos = posix_path.find('/');
		if (pos == std::wstring::npos)
		{
			break;
		}
		posix_path[pos] = '\\';
	}
	std::wstring windows_path = lxss_root + (!need_reloc ? L"rootfs" + posix_path : posix_path);
	auto final_path = std::make_unique<WCHAR[]>(PATHCCH_MAX_CCH);
	if (FAILED(PathCchCanonicalizeEx(final_path.get(), PATHCCH_MAX_CCH, windows_path.c_str(), PATHCCH_ALLOW_LONG_PATHS)))
	{
		ATL::AtlThrowLastWin32();
	}
	_RPT1(_CRT_WARN, "ConvertPOSIX2Windows()=%ls\n", final_path.get());
	return final_path.get();
}
int __cdecl wmain(int argc, wchar_t* argv[])
{
	if (argc <= 1)
	{
		puts("lxsstat POSIX_PATH [...]");
		return EXIT_FAILURE;
	}

	for (int i = 1; i < argc; ++i)
	{
		bool source_is_posix_path = argv[i][0] == L'/';
		auto windows_path = source_is_posix_path ? ConvertPOSIX2Windows(argv[i]) : argv[i];

		ATL::CHandle h(CreateFileW(windows_path.c_str(), FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_POSIX_SEMANTICS, nullptr));
		if (h == INVALID_HANDLE_VALUE)
		{
			ULONG error = GetLastError();
			fprintf(stderr, "%ls\nGetLastError()==0x%08lx\n", windows_path.c_str(), error);
			if (error == ERROR_SHARING_VIOLATION)
			{
				fputs("May be bash still alive.\n", stderr);
			}
			h.Detach();
			continue;
		}

		constexpr size_t EaLength = offsetof(FILE_FULL_EA_INFORMATION, EaName) + MAXIMUM_LENGTH_OF_EA_NAME + MAXIMUM_LENGTH_OF_EA_VALUE;
		ATL::CTempBuffer<FILE_FULL_EA_INFORMATION> Ea(EaLength);

		constexpr size_t EaQueryLength = offsetof(FILE_GET_EA_INFORMATION, EaName) + MAXIMUM_LENGTH_OF_EA_NAME;
		ATL::CTempBuffer<FILE_GET_EA_INFORMATION> EaQuery(EaQueryLength);
		EaQuery->NextEntryOffset = 0;
		EaQuery->EaNameLength = (UCHAR)strlen(LxssEaName);
		ATL::Checked::strcpy_s(EaQuery->EaName, MAXIMUM_LENGTH_OF_EA_NAME, LxssEaName);

		IO_STATUS_BLOCK ea_iob;
		NTSTATUS ea_status = ZwQueryEaFile(h, &ea_iob, Ea, EaLength, FALSE, EaQuery, EaQueryLength, nullptr, TRUE);
		if (NT_ERROR(ea_status))
		{
			if (ea_status == STATUS_NO_EAS_ON_FILE)
			{
				fprintf(stderr, "%ls\nExtended Attributes not found\n", windows_path.c_str());
			}
			else
			{
				fprintf(stderr, "%ls\nERROR=%lx\n", windows_path.c_str(), ea_status);
			}
			continue;
		}
		// If EaList != null ZwQueryEaFile() always return STATUS_SUCCESS even EA not found.
		if (ea_iob.Information < 16 + sizeof(LXATTRB))
		{
			fprintf(stderr, "%ls\nExtended Attributes not found\n", windows_path.c_str());
			continue;
		}
		_ASSERTE(strcmp(Ea->EaName, LxssEaName) == 0);
		const LXATTRB* const lxattr = (LXATTRB*)&Ea->EaName[Ea->EaNameLength + 1];

		FILE_FS_SIZE_INFORMATION fssize_info;
		IO_STATUS_BLOCK fssize_iob;
		NTSTATUS fssize_status = NtQueryVolumeInformationFile(h, &fssize_iob, &fssize_info, sizeof fssize_info, FileFsSizeInformation);
		if (NT_ERROR(fssize_status))
		{
			fprintf(stderr, "%ls\nERROR=%lx\n", windows_path.c_str(), fssize_status);
			continue;
		}
		auto file_std_info = std::make_unique<FILE_STANDARD_INFO>();
		GetFileInformationByHandleEx(h, FileStandardInfo, file_std_info.get(), sizeof(FILE_STANDARD_INFO));
		auto file_id_info = std::make_unique<FILE_ID_INFO>();
		GetFileInformationByHandleEx(h, FileIdInfo, file_id_info.get(), sizeof(FILE_ID_INFO));

		printf("  File: '%ls'", argv[i]);
		if (lxattr->permission.is_symlink)
		{
			if (file_std_info->EndOfFile.QuadPart <= PATHCCH_MAX_CCH)
			{
				ATL::CTempBuffer<BYTE> buffer(file_std_info->EndOfFile.QuadPart);
				ULONG read_size;
				if (ReadFile(h, buffer, file_std_info->EndOfFile.LowPart, &read_size, nullptr))
				{
					printf("  ->  '%.*s'\n", read_size, (PBYTE)buffer);
				}
				else
				{
					printf("  ->  ????(%lx)", GetLastError());
				}
			}
			else
			{
				fputs(" symlink too long\n", stderr);
			}
		}
		else
		{
			puts("");
		}

		const ULONG cluster_size = fssize_info.BytesPerSector * fssize_info.SectorsPerAllocationUnit;
		printf(
			"  Size: %-16llu Blocks: %-10llu IO Block: %-8lu ",
			file_std_info->EndOfFile.QuadPart,
			file_std_info->AllocationSize.QuadPart ? file_std_info->AllocationSize.QuadPart / cluster_size : 0,
			cluster_size
		);

		if (lxattr->permission.is_symlink)
		{
			puts("symbolic link");
		}
		else if (lxattr->permission.is_directory)
		{
			puts("directory");
		}
		else if (lxattr->permission.is_file)
		{
			puts("regular file");
		}
		else
		{
			puts("unknown");
		}

		BYTE eight_bytes[8] = {};
		if (memcmp(&file_id_info->FileId.Identifier[8], eight_bytes, sizeof(ULONG64)) == 0)
		{
			printf(
				"Inode: %-16llu  Links: %lu\n",
				*(PULONG64)&file_id_info->FileId,
				file_std_info->NumberOfLinks
			);
		}
		else
		{
			printf(
				"Inode: 0x%016llx%016llx  Links: %lu\n",
				*(PULONG64)&file_id_info->FileId.Identifier[8],
				*(PULONG64)&file_id_info->FileId.Identifier[0],
				file_std_info->NumberOfLinks
			);
		}

		printf(
			"Access: (%u%u%u%u)  Uid : (%u)   Gid : (%u)\n",
			lxattr->permission.sticky | lxattr->permission.suid << 1 | lxattr->permission.suid << 2,
			lxattr->permission.owner,
			lxattr->permission.group,
			lxattr->permission.other,
			lxattr->uid,
			lxattr->gid
		);

		uint64_t mactime[3] = { lxattr->atime, lxattr->mtime, lxattr->ctime };
		uint32_t mactime_extra[3] = { lxattr->atime_extra, lxattr->mtime_extra, lxattr->ctime_extra };
		const char *mactime_string[] = { "Access", "Modify", "Change" };
		for (int j = 0; j < _countof(mactime); ++j)
		{
			char str[80];
			strftime(
				str,
				sizeof str,
				"%Y-%m-%d %T",
				gmtime((__time64_t*)&mactime[j])
			);
			printf("%s: %s.%09lu +0000\n", mactime_string[j], str, mactime_extra[j]);
		}
	}
}