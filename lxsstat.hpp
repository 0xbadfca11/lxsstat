#pragma once
#define WIN32_LEAN_AND_MEAN
#define STRICT
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
constexpr NTSTATUS STATUS_NO_EAS_ON_FILE = 0xC0000052L;
#else
static_assert(STATUS_NO_EAS_ON_FILE == 0xC0000052L, "");
#endif

#ifndef IO_REPARSE_TAG_LX_SYMLINK
constexpr ULONG IO_REPARSE_TAG_LX_SYMLINK = 0xA000001D;
static_assert(IsReparseTagMicrosoft(IO_REPARSE_TAG_LX_SYMLINK), "");
#else
static_assert(IO_REPARSE_TAG_LX_SYMLINK == 0xA000001D, "");
#endif

namespace Lxss
{
	constexpr uint32_t S_IFLNK = 0120000;
	constexpr uint32_t S_IFIFO = 010000;
	constexpr uint32_t S_ISUID = 04000;
	constexpr uint32_t S_ISGID = 02000;
	constexpr uint32_t S_ISVTX = 01000;
	constexpr uint32_t S_IRWXU = 0700;
	constexpr uint32_t S_IRUSR = 0400;
	constexpr uint32_t S_IWUSR = 0200;
	constexpr uint32_t S_IXUSR = 0100;
	constexpr uint32_t S_IRWXG = 070;
	constexpr uint32_t S_IRGRP = 040;
	constexpr uint32_t S_IWGRP = 020;
	constexpr uint32_t S_IXGRP = 010;
	constexpr uint32_t S_IRWXO = 07;
	constexpr uint32_t S_IROTH = 04;
	constexpr uint32_t S_IWOTH = 02;
	constexpr uint32_t S_IXOTH = 01;
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
	static bool inline S_ISFIFO(uint32_t st_mode) noexcept
	{
		return (st_mode & S_IFMT) == S_IFIFO;
	}
	struct stat
	{
		uint32_t st_dev;
		union
		{
			uint64_t st_ino;
			FILE_ID_128 FileId;
		};
		uint32_t st_nlink;
		struct _timespec64 st_atim;
		struct _timespec64 st_mtim;
		struct _timespec64 st_ctim;
		struct _timespec64 st_birthtim;
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
	std::array<char, 11> mode_tostring(uint32_t st_mode) noexcept;
	std::unordered_map<uint32_t, const std::string> ParsePasswdLikeFile(const std::wstring& file);
	PCSTR UserNameFromUID(uint32_t uid);
	PCSTR GroupNameFromGID(uint32_t gid);
#include <pshpack1.h>
	struct LXATTRB
	{
		uint32_t unknown1;
		uint32_t st_mode;
		uint32_t st_uid;
		uint32_t st_gid;
		uint32_t st_rdev;
		uint32_t atime_extra;
		uint32_t mtime_extra;
		uint32_t ctime_extra;
		uint64_t atime;
		uint64_t mtime;
		uint64_t ctime;
	};
#include <poppack.h>
	static_assert(sizeof(LXATTRB) == 56, "");

	constexpr char LxssEaName[] = "LXATTRB";

}