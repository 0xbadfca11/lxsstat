#define WIN32_LEAN_AND_MEAN
#define STRICT_GS_ENABLED
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
#include <atlconv.h>
#include <atlcore.h>
#include <array>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <ctime>
#include <fcntl.h>
#include <io.h>
#include "lxsstat.hpp"
#include "fileopen.hpp"
#pragma comment(lib, "pathcch")
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
// EaNameLength not include '\0'. But buffer must include '\0'.
const size_t MAXIMUM_LENGTH_OF_EA_NAME = (std::numeric_limits<decltype(FILE_FULL_EA_INFORMATION::EaNameLength)>::max)() + 1;
const size_t MAXIMUM_LENGTH_OF_EA_VALUE = (std::numeric_limits<decltype(FILE_FULL_EA_INFORMATION::EaValueLength)>::max)();

namespace Lxss
{
	bool is_distribution_legacy = true;
	ULONG default_uid = 0;
	const auto lxss_root = []()->std::wstring
	{
		WCHAR lxss_dir[MAX_PATH];
		ATL::CRegKey lxss_reg_key;
		if (lxss_reg_key.Open(HKEY_CURRENT_USER, TEXT(R"(Software\Microsoft\Windows\CurrentVersion\Lxss)"), KEY_READ) == ERROR_SUCCESS)
		{
			ULONG cch_value = 0;
			if (RegGetValueW(lxss_reg_key, nullptr, L"DefaultDistribution", RRF_RT_REG_SZ, nullptr, nullptr, &cch_value) == ERROR_SUCCESS)
			{
				ATL::CTempBuffer<WCHAR> DefaultDistribution;
				DefaultDistribution.AllocateBytes(cch_value);
				if (RegGetValueW(lxss_reg_key, nullptr, L"DefaultDistribution", RRF_RT_REG_SZ, nullptr, DefaultDistribution, &cch_value) == ERROR_SUCCESS)
				{
					_RPT1(_CRT_WARN, "DefaultDistribution = %ls\n", (PCWSTR)DefaultDistribution);
					ATL::CRegKey lxss_distribution_key;
					if (lxss_distribution_key.Open(lxss_reg_key, ATL::CW2T(DefaultDistribution), KEY_READ) == ERROR_SUCCESS)
					{
						cch_value = 0;
						if (RegGetValueW(lxss_distribution_key, nullptr, L"DistributionName", RRF_RT_REG_SZ, nullptr, nullptr, &cch_value) == ERROR_SUCCESS)
						{
							ATL::CTempBuffer<WCHAR> DistributionName;
							DistributionName.AllocateBytes(cch_value);
							if (RegGetValueW(lxss_distribution_key, nullptr, L"DistributionName", RRF_RT_REG_SZ, nullptr, DistributionName, &cch_value) == ERROR_SUCCESS)
							{
								_RPT1(_CRT_WARN, "DistributionName = %ls\n", (PCWSTR)DistributionName);
								if (wcscmp(DistributionName, L"Legacy") != 0)
								{
									is_distribution_legacy = false;
								}
							}
						}
						cch_value = sizeof default_uid;
						RegGetValueW(lxss_distribution_key, nullptr, L"DefaultUid", RRF_RT_REG_DWORD | RRF_ZEROONFAILURE, nullptr, &default_uid, &cch_value);
						cch_value = sizeof lxss_dir;
						if (RegGetValueW(lxss_distribution_key, nullptr, L"BasePath", RRF_RT_REG_SZ, nullptr, lxss_dir, &cch_value) == ERROR_SUCCESS)
						{
							return lxss_dir;
						}
					}
				}
			}
			cch_value = sizeof default_uid;
			RegGetValueW(lxss_reg_key, nullptr, L"DefaultUid", RRF_RT_REG_DWORD | RRF_ZEROONFAILURE, nullptr, &default_uid, &cch_value);
		}
		ATLENSURE(ExpandEnvironmentStringsW(LR"(%LOCALAPPDATA%\lxss)", lxss_dir, ARRAYSIZE(lxss_dir)));
		return lxss_dir;
	}();
	_Success_(return == true) bool GetEA(_In_ HANDLE file, _In_z_ PCSTR ea_name, _Out_writes_bytes_all_(ea_size) void* ea, size_t ea_size)
	{
		const size_t EaLength = offsetof(FILE_FULL_EA_INFORMATION, EaName) + MAXIMUM_LENGTH_OF_EA_NAME + MAXIMUM_LENGTH_OF_EA_VALUE;
		ATL::CHeapPtr<FILE_FULL_EA_INFORMATION> Ea;
		Ea.AllocateBytes(EaLength);

		const size_t EaQueryLength = offsetof(FILE_GET_EA_INFORMATION, EaName) + MAXIMUM_LENGTH_OF_EA_NAME;
		ATL::CHeapPtr<FILE_GET_EA_INFORMATION> EaQuery;
		EaQuery.AllocateBytes(EaQueryLength);
		EaQuery->NextEntryOffset = 0;
		const size_t ea_name_len = strlen(ea_name);
		if (ea_name_len + 1 >= MAXIMUM_LENGTH_OF_EA_NAME)
		{
			SetLastError(ERROR_BAD_ARGUMENTS);
			return false;
		}
		EaQuery->EaNameLength = (UCHAR)ea_name_len;
		ATL::Checked::strcpy_s(EaQuery->EaName, MAXIMUM_LENGTH_OF_EA_NAME, ea_name);

		IO_STATUS_BLOCK ea_iob;
		NTSTATUS ea_status = ZwQueryEaFile(file, &ea_iob, Ea, EaLength, FALSE, EaQuery, EaQueryLength, nullptr, TRUE);
		if (NT_ERROR(ea_status))
		{
			SetLastError(ea_status);
			return false;
		}
		// When EaList != null, ZwQueryEaFile() always return STATUS_SUCCESS even EA not found.
		if (Ea->EaValueLength == 0)
		{
			SetLastError((ULONG)STATUS_NO_EAS_ON_FILE);
			return false;
		}
		_ASSERTE(_stricmp(Ea->EaName, ea_name) == 0);
		if (Ea->EaValueLength > ea_size)
		{
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			return false;
		}
		ATL::AtlCrtErrorCheck(memcpy_s(ea, ea_size, &Ea->EaName[Ea->EaNameLength + 1], Ea->EaValueLength));
		return true;
	}
	const bool is_wslfs = []()->bool
	{
		ATL::CHandle h(OpenFileCaseSensitive(realpath(L"/").c_str(), FILE_READ_EA | FILE_READ_ATTRIBUTES));
		if (!h)
		{
			_CrtDbgBreak();
			return false;
		}
		uint32_t st_mode;
		if (GetEA(h, LX_FILE_METADATA_MODE_EA_NAME, &st_mode, sizeof st_mode))
		{
			return true;
		}
		return false;
	}();
	const std::unordered_map<std::string, std::vector<std::string>> Passwd = ParsePasswd(realpath(L"/etc/passwd"));
	std::wstring realpath(std::wstring path)
	{
		_RPT1(_CRT_WARN, "realpath(<%ls)\n", path.c_str());
		if (path[0] == L'~')
		{
			std::string user = "root";
			size_t pos;
			if (path[1] == L'/' || path[1] == L'\0')
			{
				pos = 1;
				if (PCSTR default_user = UserNameFromUID(default_uid))
				{
					user = default_user;
				}
				else
				{
					fwprintf(stderr, L"Can't get default user name\n");
				}
			}
			else
			{
				pos = path.find(L'/', 1);
				const std::wstring name = pos != std::wstring::npos ? path.substr(1, pos - 1) : path.substr(1);
				user = (PCSTR)ATL::CW2A(name.c_str(), CP_UTF8);
			}
			auto it = Passwd.find(user);
			if (it == Passwd.end())
			{
				fwprintf(stderr, L"Can't found user \"%hs\"\n", user.c_str());
			}
			else
			{
				path = pos != std::wstring::npos ? (PCWSTR)ATL::CA2W(it->second[5].c_str(), CP_UTF8) + path.substr(pos) : (PCWSTR)ATL::CA2W(it->second[5].c_str(), CP_UTF8);
			}
		}
		if (path[0] == L'/')
		{
			const WCHAR fixups[] = LR"(#<>:"\|?*)"
				L"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"
				L"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
			for (size_t pos = path.find_first_of(fixups); pos != std::string::npos; pos = path.find_first_of(fixups, pos))
			{
				if (is_wslfs)
				{
					path[pos] |= 0xF000;
				}
				else
				{
					WCHAR buf[5];
					ATLENSURE(swprintf_s(buf, L"%04X", path[pos]) == _countof(buf) - 1);
					path[pos] = L'#';
					path.insert(++pos, buf);
					pos += _countof(buf) - 1;
				}
			}
			bool need_reloc = false;
			if (is_distribution_legacy)
			{
				const PCWSTR reloc_directory[] = {
					L"/root",
					L"/home",
				};
				for (uint32_t i = 0; i < _countof(reloc_directory); ++i)
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
			}
			path.insert(0, !need_reloc ? lxss_root + L"\\rootfs" : lxss_root);
		}
		std::replace(path.begin(), path.end(), L'/', L'\\');
		std::wstring full_path(PATHCCH_MAX_CCH, L'\0');
		ATLENSURE(GetCurrentDirectoryW(PATHCCH_MAX_CCH, full_path.data()));
		ATLENSURE_SUCCEEDED(PathCchCombineEx(full_path.data(), PATHCCH_MAX_CCH, full_path.c_str(), path.c_str(), PATHCCH_ENSURE_IS_EXTENDED_LENGTH_PATH));
		full_path.resize(wcslen(full_path.c_str()));
		_RPT1(_CRT_WARN, "realpath(>%ls)\n", full_path.c_str());
		return full_path;
	}
	std::array<char, 11> mode_tostring(uint32_t st_mode) noexcept
	{
		if (S_ISLNK(st_mode))
		{
			return{ "lrwxrwxrwx" };
		}

		return
		{
			/*[0]*/ S_ISDIR(st_mode) ? 'd' : S_ISREG(st_mode) ? '-' : S_ISCHR(st_mode) ? 'c' : S_ISFIFO(st_mode) ? 'p' : S_ISSOCK(st_mode) ? 's' : '?',
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
	struct _timespec64 FileTimeToUnixTime(LONG64 ft) noexcept
	{
		const int64_t diff_win_unix = 116444736000000000;
		const int32_t unit = 10000000;
		const int32_t nsec_per_unit = 100;
		return{ (ft - diff_win_unix) / unit, static_cast<long>((ft - diff_win_unix) % unit * nsec_per_unit) };
	}
	constexpr uint64_t inline MAKEUINT64(uint32_t low, uint32_t high) noexcept
	{
		return low | high * 1ULL << 32;
	}
	static_assert(MAKEUINT64(0, 1) == 0x100000000);
	_Success_(return == 0) int stat(_In_z_ const wchar_t *__restrict path, _Out_ struct Lxss::stat *__restrict buf)
	{
		auto windows_path = realpath(path);

		ATL::CHandle h(OpenFileCaseSensitive(windows_path.c_str(), FILE_READ_EA | FILE_READ_ATTRIBUTES));
		if (!h)
		{
			return -1;
		}

		BY_HANDLE_FILE_INFORMATION file_info;
		if (!GetFileInformationByHandle(h, &file_info))
		{
			return -1;
		}
		FILE_BASIC_INFO file_basic_info;
		if (!GetFileInformationByHandleEx(h, FileBasicInfo, &file_basic_info, sizeof file_basic_info))
		{
			return -1;
		}
		FILE_STANDARD_INFO file_std_info;
		if (!GetFileInformationByHandleEx(h, FileStandardInfo, &file_std_info, sizeof file_std_info))
		{
			return -1;
		}
		FILE_ATTRIBUTE_TAG_INFO file_attribute_tag_info;
		if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, &file_attribute_tag_info, sizeof file_attribute_tag_info))
		{
			return -1;
		}
		FILE_STORAGE_INFO file_storage_info;
		if (!GetFileInformationByHandleEx(h, FileStorageInfo, &file_storage_info, sizeof file_storage_info))
		{
			return -1;
		}

		if (LXATTRB lxattr; GetEA(h, LxssEaName, &lxattr, sizeof lxattr))
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
			buf->st_blocks = file_std_info.AllocationSize.QuadPart / 512;
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
		buf->st_nlink = file_std_info.NumberOfLinks;
		buf->st_atim = FileTimeToUnixTime(file_basic_info.LastAccessTime.QuadPart);
		buf->st_mtim = FileTimeToUnixTime(file_basic_info.LastWriteTime.QuadPart);
		buf->st_ctim = FileTimeToUnixTime(file_basic_info.ChangeTime.QuadPart);
		buf->st_size = file_std_info.EndOfFile.QuadPart;
		buf->st_blksize = file_storage_info.PhysicalBytesPerSectorForPerformance;
		buf->st_blocks = file_std_info.AllocationSize.QuadPart / 512;

		buf->st_uid = 0;
		if (GetEA(h, LX_FILE_METADATA_UID_EA_NAME, &buf->st_uid, sizeof buf->st_uid))
		{
			linux_control = true;
		}

		buf->st_gid = 0;
		if (GetEA(h, LX_FILE_METADATA_GID_EA_NAME, &buf->st_gid, sizeof buf->st_gid))
		{
			linux_control = true;
		}

		// issue #4
		buf->st_rdev = 0;
		if (uint64_t st_rdev; GetEA(h, LX_FILE_METADATA_DEVICE_ID_EA_NAME, &st_rdev, sizeof st_rdev))
		{
			linux_control = true;
		}

		buf->st_mode = 0;
		if (GetEA(h, LX_FILE_METADATA_MODE_EA_NAME, &buf->st_mode, sizeof buf->st_mode))
		{
			linux_control = true;
		}
		else if (file_attribute_tag_info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
		{
			if (file_attribute_tag_info.ReparseTag == IO_REPARSE_TAG_LX_SYMLINK)
			{
				buf->st_mode = S_IFLNK | S_IRWXU | S_IRWXG | S_IRWXO;
				linux_control = true;
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
	const std::unordered_map<uint32_t, const std::string> uids = ParseGroup(realpath(L"/etc/passwd"));
	const std::unordered_map<uint32_t, const std::string> gids = ParseGroup(realpath(L"/etc/group"));
	struct fileclose
	{
		void operator()(FILE* f) noexcept
		{
			fclose(f);
		}
	};
	std::unique_ptr<FILE, fileclose> fopenInLxss(const std::wstring& file)
	{
		HANDLE h = OpenFileCaseSensitive(file.c_str(), FILE_READ_DATA);
		if (!h)
		{
			return nullptr;
		}
		int fd = _open_osfhandle((intptr_t)h, _O_RDONLY);
		if (fd == -1)
		{
			CloseHandle(h);
			return nullptr;
		}
		std::unique_ptr<FILE, fileclose> f(_fdopen(fd, "r"));
		if (!f)
		{
			_close(fd);
			return nullptr;
		}
		return f;
	}
	std::vector<std::string> ReadLines(_In_ FILE* f)
	{
		std::vector<std::string> lines;
		for (;;)
		{
			std::string line;
			for (;;)
			{
				char buf[0x80];
				if (!fgets(buf, _countof(buf), f))
				{
					return lines;
				}
				line += buf;
				if (feof(f))
				{
					break;
				}
				else if (std::find(std::cbegin(buf), std::cend(buf), '\n') == std::cend(buf))
				{
					continue;
				}
				else
				{
					break;
				}
			}
			auto pos = line.find_last_not_of('\n');
			if (pos != std::string::npos)
			{
				line = line.substr(0, pos + 1);
			}
			lines.emplace_back(std::move(line));
		}
	}
	std::unordered_map<std::string, std::vector<std::string>> ParsePasswd(const std::wstring& file)
	{
		auto f = fopenInLxss(file);
		if (!f)
		{
			return {};
		}
		const auto lines = ReadLines(f.get());
		std::unordered_map<std::string, std::vector<std::string>> passwd;
		for (auto line : lines)
		{
			std::stringstream ss(line);
			std::string part;
			std::vector<std::string> elements;
			while (std::getline(ss, part, ':'))
			{
				elements.emplace_back(std::move(part));
			}
			elements.shrink_to_fit();
			std::string name = elements[0];
			passwd.emplace(
				std::piecewise_construct,
				std::make_tuple(std::move(name)),
				std::make_tuple(std::move(elements)));
		}
		return passwd;
	}
	std::unordered_map<uint32_t, const std::string> ParseGroup(const std::wstring& file)
	{
		auto f = fopenInLxss(file);
		if (!f)
		{
			return {};
		}
		const auto lines = ReadLines(f.get());
		std::unordered_map<uint32_t, const std::string> ids;
		for (const auto& line : lines)
		{
			auto const head = line.data();
			size_t name_length = line.find(":");
			size_t id_pos = line.find(":", name_length + 1) + 1;
			ids.emplace(std::piecewise_construct, std::make_tuple(std::stoi(head + id_pos)), std::make_tuple(head, name_length));
		}
		return ids;
	}
	_Ret_maybenull_z_ PCSTR NameFromIDs(const std::unordered_map<uint32_t, const std::string>& ids, uint32_t id)
	{
		_ASSERTE(ids.size() > 0);
		auto it = ids.find(id);
		if (it != ids.end())
		{
			return it->second.c_str();
		}
		else
		{
			return nullptr;
		}
	}
	_Ret_maybenull_z_ PCSTR UserNameFromUID(uint32_t uid)
	{
		return NameFromIDs(uids, uid);
	}
	_Ret_maybenull_z_ PCSTR GroupNameFromGID(uint32_t gid)
	{
		return NameFromIDs(gids, gid);
	}
}