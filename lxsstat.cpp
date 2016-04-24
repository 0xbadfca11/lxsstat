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
		printf("  File: '%ls'\n", argv[i]);

		ATL::CHandle h(CreateFileW(windows_path.c_str(), FILE_READ_EA, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_POSIX_SEMANTICS, nullptr));
		if (h == INVALID_HANDLE_VALUE)
		{
			ULONG error = GetLastError();
			fprintf(stderr, "GetLastError()==0x%08lx\n", error);
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

		IO_STATUS_BLOCK iob;
		NTSTATUS status = ZwQueryEaFile(h, &iob, Ea, EaLength, FALSE, EaQuery, EaQueryLength, nullptr, TRUE);
		if (NT_ERROR(status))
		{
			if (status == STATUS_NO_EAS_ON_FILE)
			{
				fprintf(stderr, "Extended Attributes not found\n");
			}
			continue;
		}
		// If EaList != null ZwQueryEaFile() always return STATUS_SUCCESS even EA not found.
		if (iob.Information < 16 + sizeof(LXATTRB))
		{
			fprintf(stderr, "Extended Attributes not found\n");
			continue;
		}
		_ASSERTE(strcmp(Ea->EaName, LxssEaName) == 0);
		const LXATTRB* const lxattr = (LXATTRB*)&Ea->EaName[Ea->EaNameLength + 1];

		if (lxattr->permission.is_symlink)
		{
			puts("symlink");
		}
		else if (lxattr->permission.is_directory)
		{
			puts("directory");
		}
		else if (lxattr->permission.is_file)
		{
			puts("file");
		}
		else
		{
			puts("unknown");
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