#pragma once
#define WIN32_LEAN_AND_MEAN
#define STRICT
#include <windows.h>
#include <winternl.h>
#include <array>
#include <string>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <sys/stat.h>

#ifndef STATUS_NO_EAS_ON_FILE
constexpr NTSTATUS STATUS_NO_EAS_ON_FILE = 0xC0000052L;
#else
static_assert(STATUS_NO_EAS_ON_FILE == 0xC0000052L, "");
#endif

namespace Lxss
{
	constexpr uint32_t S_IFLNK = 020000;
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
	static bool inline S_ISLNK(uint32_t st_mode)
	{
		return (st_mode & S_IFLNK) != 0;
	}
	static bool inline S_ISDIR(uint32_t st_mode)
	{
		return (st_mode & S_IFMT) == S_IFDIR;
	}
	static bool inline S_ISREG(uint32_t st_mode)
	{
		return (st_mode & S_IFMT) == S_IFREG;
	}
	static uint32_t inline major(uint32_t st_dev)
	{
		return HIWORD(st_dev);
	}
	static uint32_t inline minor(uint32_t st_dev)
	{
		return LOWORD(st_dev);
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
		uint32_t st_mode;
	};
	_Success_(return == 0) int stat(_In_z_ const wchar_t *__restrict path, _Out_ struct Lxss::stat *__restrict buf);
	std::wstring ConvertPOSIX2Windows(std::wstring posix_path);
	std::array<char, 11> mode_tostring(uint32_t st_mode);
#include <pshpack1.h>
	struct LXATTRB
	{
		uint32_t unknown1;
		union
		{
			uint32_t st_mode;
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
		};
		uint32_t st_uid;
		uint32_t st_gid;
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

	constexpr char LxssEaName[] = "LXATTRB";

}