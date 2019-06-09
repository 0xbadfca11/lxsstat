#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <array>
#include <string>
#include <unordered_map>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <sys/stat.h>

#ifndef STATUS_NO_EAS_ON_FILE
const ULONG STATUS_NO_EAS_ON_FILE = 0xC0000052L;
#else
static_assert(STATUS_NO_EAS_ON_FILE == 0xC0000052L);
#endif

#ifndef IO_REPARSE_TAG_LX_SYMLINK
const ULONG IO_REPARSE_TAG_LX_SYMLINK = 0xA000001D;
static_assert(IsReparseTagMicrosoft(IO_REPARSE_TAG_LX_SYMLINK));
#else
static_assert(IO_REPARSE_TAG_LX_SYMLINK == 0xA000001D);
#endif
#ifndef IO_REPARSE_TAG_LX_FIFO
const ULONG IO_REPARSE_TAG_LX_FIFO = 0x80000024;
static_assert(IsReparseTagMicrosoft(IO_REPARSE_TAG_LX_FIFO));
#else
static_assert(IO_REPARSE_TAG_LX_FIFO == 0x80000024);
#endif
#ifndef IO_REPARSE_TAG_LX_CHR
const ULONG IO_REPARSE_TAG_LX_CHR = 0x80000025;
static_assert(IsReparseTagMicrosoft(IO_REPARSE_TAG_LX_CHR));
#else
static_assert(IO_REPARSE_TAG_LX_CHR == 0x80000025);
#endif
#ifndef IO_REPARSE_TAG_LX_BLK
const ULONG IO_REPARSE_TAG_LX_BLK = 0x80000026;
static_assert(IsReparseTagMicrosoft(IO_REPARSE_TAG_LX_BLK));
#else
static_assert(IO_REPARSE_TAG_LX_BLK == 0x80000026);
#endif
#ifndef LX_FILE_METADATA_UID_EA_NAME
const char LX_FILE_METADATA_UID_EA_NAME[] = "$LXUID";
#endif
#ifndef LX_FILE_METADATA_GID_EA_NAME
const char LX_FILE_METADATA_GID_EA_NAME[] = "$LXGID";
#endif
#ifndef LX_FILE_METADATA_MODE_EA_NAME
const char LX_FILE_METADATA_MODE_EA_NAME[] = "$LXMOD";
#endif
#ifndef LX_FILE_METADATA_DEVICE_ID_EA_NAME
const char LX_FILE_METADATA_DEVICE_ID_EA_NAME[] = "$LXDEV";
#endif

namespace Lxss
{
	const uint32_t S_IFSOCK = 0140000;
	const uint32_t S_IFLNK = 0120000;
	const uint32_t S_IFBLK = 060000;
	const uint32_t S_IFIFO = 010000;
	const uint32_t S_ISUID = 04000;
	const uint32_t S_ISGID = 02000;
	const uint32_t S_ISVTX = 01000;
	const uint32_t S_IRWXU = 0700;
	const uint32_t S_IRUSR = 0400;
	const uint32_t S_IWUSR = 0200;
	const uint32_t S_IXUSR = 0100;
	const uint32_t S_IRWXG = 070;
	const uint32_t S_IRGRP = 040;
	const uint32_t S_IWGRP = 020;
	const uint32_t S_IXGRP = 010;
	const uint32_t S_IRWXO = 07;
	const uint32_t S_IROTH = 04;
	const uint32_t S_IWOTH = 02;
	const uint32_t S_IXOTH = 01;
	static bool inline S_ISLNK(uint32_t st_mode) noexcept
	{
		return (st_mode & S_IFMT) == S_IFLNK;
	}
	static bool inline S_ISDIR(uint32_t st_mode) noexcept
	{
		return (st_mode & S_IFMT) == S_IFDIR;
	}
	static bool inline S_ISREG(uint32_t st_mode) noexcept
	{
		return (st_mode & S_IFMT) == S_IFREG;
	}
	static bool inline S_ISCHR(uint32_t st_mode) noexcept
	{
		return (st_mode & S_IFMT) == S_IFCHR;
	}
	static bool inline S_ISBLK(uint32_t st_mode) noexcept
	{
		return (st_mode & S_IFMT) == S_IFBLK;
	}
	static bool inline S_ISFIFO(uint32_t st_mode) noexcept
	{
		return (st_mode & S_IFMT) == S_IFIFO;
	}
	static bool inline S_ISSOCK(uint32_t st_mode) noexcept
	{
		return (st_mode & S_IFMT) == S_IFSOCK;
	}
	struct stat
	{
		uint32_t st_dev;
		uint64_t st_ino;
		uint32_t st_nlink;
		struct _timespec64 st_atim;
		struct _timespec64 st_mtim;
		struct _timespec64 st_ctim;
		uint64_t st_size;
		uint32_t st_blksize;
		uint64_t st_blocks;
		uint32_t st_uid;
		uint32_t st_gid;
		uint32_t st_rdev;
		uint32_t st_mode;
	};
	_Success_(return == 0) int stat(_In_z_ const wchar_t *__restrict path, _Out_ struct Lxss::stat *__restrict buf);
	std::wstring realpath(std::wstring path);
	int64_t readlink(_In_z_ const wchar_t* pathname, _Inout_ std::wstring* buf);
	std::array<char, 11> mode_tostring(uint32_t st_mode) noexcept;
	std::unordered_map<std::string, std::vector<std::string>> ParsePasswd(const std::wstring& file);
	std::unordered_map<uint32_t, const std::string> ParseGroup(const std::wstring& file);
	_Ret_maybenull_z_ PCSTR UserNameFromUID(uint32_t uid);
	_Ret_maybenull_z_ PCSTR GroupNameFromGID(uint32_t gid);

	struct LXATTRB
	{
		uint32_t unknown1;// version ?
		uint32_t st_mode;
		uint32_t st_uid;
		uint32_t st_gid;
		uint32_t unknown2;// st_rdev ?
		uint32_t atime_extra;
		uint32_t mtime_extra;
		uint32_t ctime_extra;
		uint64_t atime;
		uint64_t mtime;
		uint64_t ctime;
	};
	static_assert(sizeof(LXATTRB) == 56);
	const char LxssEaName[] = "LXATTRB";
}