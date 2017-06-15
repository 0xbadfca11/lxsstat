#define WIN32_LEAN_AND_MEAN
#define STRICT_GS_ENABLED
#define _ATL_NO_AUTOMATIC_NAMESPACE
#include <windows.h>
#include <pathcch.h>
#include <atlalloc.h>
#include <atlbase.h>
#include <atlconv.h>
#include <fcntl.h>
#include <io.h>
#include <cstdio>
#include <cstdlib>
#include <crtdbg.h>
#include "lxsstat.hpp"
#include "fileopen.hpp"

ATL::CHeapPtr<WCHAR> GetWindowsError(ULONG error_code = GetLastError())
{
	ATL::CHeapPtr<WCHAR> msg;
	ATLENSURE(msg.Allocate(USHRT_MAX));
	ATLENSURE(FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error_code, 0, msg, USHRT_MAX, nullptr));
	return msg;
}
int __cdecl wmain(int argc, wchar_t* argv[])
{
	_CrtSetDbgFlag(_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG) | _CRTDBG_LEAK_CHECK_DF);
	_CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
	_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG | _CRTDBG_MODE_FILE);
	_setmode(_fileno(stdout), _O_U8TEXT);
	_setmode(_fileno(stderr), _O_U8TEXT);
	if (argc <= 1)
	{
		fputws(L"lxsstat {POSIX_PATH|Windows_PATH} [...]\n", stderr);
		return EXIT_FAILURE;
	}

	for (int i = 1; i < argc; ++i)
	{
		auto windows_path = Lxss::realpath(argv[i]);
		struct Lxss::stat buf;
		if (Lxss::stat(windows_path.c_str(), &buf) != 0)
		{
			ULONG error = GetLastError();
			if (error == STATUS_NO_EAS_ON_FILE)
			{
				fwprintf(stderr, L"%ls\nThis file is not under the control of the Ubuntu on Windows\n", windows_path.c_str());
			}
			else
			{
				fwprintf(stderr, L"%ls\n%ls", windows_path.c_str(), (PCWSTR)GetWindowsError(error));
			}
		}
		else
		{
			wprintf(L"  File: '%ls'", argv[i]);
			if (Lxss::S_ISLNK(buf.st_mode))
			{
				if (buf.st_size <= PATHCCH_MAX_CCH)
				{
					ATL::CTempBuffer<CHAR> buffer(buf.st_size + 1);
					ULONG read_size;
					ATL::CHandle h(OpenFileCaseSensitive(windows_path.c_str()));
					if (h && ReadFile(h, buffer, (ULONG)buf.st_size + 1, &read_size, nullptr))
					{
						if (read_size == buf.st_size)
						{
							buffer[read_size] = '\0';
							ATL::CA2W path(buffer, CP_UTF8);
							wprintf(L"  ->  '%.*ls'\n", (int)wcslen(path), (PCWSTR)path);
						}
						else
						{
							wprintf(L"  ->  ?\?\?\?\?\?\?\?");
						}
					}
					else
					{
						wprintf(L"  ->  ?\?\?\?\?\?\?\?\n%ls", (PCWSTR)GetWindowsError());
					}
				}
				else
				{
					_putws(L"  ->  symlink too long");
				}
			}
			else
			{
				_putws(L"");
			}
			wprintf(
				L"  Size: %-15llu Blocks: %-10llu IO Block: %-6u ",
				buf.st_size,
				buf.st_blocks,
				buf.st_blksize
			);
			if (Lxss::S_ISLNK(buf.st_mode))
			{
				_putws(L"symbolic link");
			}
			else if (Lxss::S_ISDIR(buf.st_mode))
			{
				_putws(L"directory");
			}
			else if (Lxss::S_ISREG(buf.st_mode))
			{
				if (buf.st_size)
				{
					_putws(L"regular file");
				}
				else
				{
					_putws(L"regular empty file");
				}
			}
			else if (Lxss::S_ISCHR(buf.st_mode))
			{
				_putws(L"character special file");
			}
			else if (Lxss::S_ISFIFO(buf.st_mode))
			{
				_putws(L"fifo");
			}
			else
			{
				_putws(L"unknown");
			}
			wprintf(
				!Lxss::S_ISCHR(buf.st_mode)
				? L"Device: %xh/%ud   Inode: %llu  Links: %u\n"
				: L"Device: %xh/%ud   Inode: %llu  Links: %-5u Device type: %x,%x\n",
				buf.st_dev,
				buf.st_dev,
				buf.st_ino,
				buf.st_nlink,
				HIBYTE(buf.st_rdev),
				LOBYTE(buf.st_rdev)
			);
			wprintf(
				L"Access: (%04o/%hs)  Uid: (% 5u/% 8hs)   Gid: (% 5u/% 8hs)\n",
				buf.st_mode & 07777,
				Lxss::mode_tostring(buf.st_mode).data(),
				buf.st_uid,
				Lxss::UserNameFromUID(buf.st_uid),
				buf.st_gid,
				Lxss::GroupNameFromGID(buf.st_gid)
			);
			const struct _timespec64(&mactime)[3] = { buf.st_atim, buf.st_mtim ,buf.st_ctim };
			const PCSTR mactime_string[] = { "Access", "Modify", "Change" };
			for (int j = 0; j < _countof(mactime); ++j)
			{
				char str[80];
				strftime(
					str,
					sizeof str,
					"%F %T",
					__pragma(warning(suppress:4996)) gmtime(&mactime[j].tv_sec)
				);
				wprintf(L"%hs: %hs.%09lu +0000\n", mactime_string[j], str, mactime[j].tv_nsec);
			}
		}
	}
}