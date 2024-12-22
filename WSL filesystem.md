Mostly metadata stored into NTFS extended file attributes.  

# filesystems
## lxfs
The default file system for VolFs prior to version 1903.  
It exists for compatibility. You can not use this format newly.  

### Filename escaping
Invalid characters on Win32 namespace and ``#`` itself convert to ``#NNNN``. NNNN is upper case stringize hex value of unicode code point. (Converts one character to five characters.)  

### Extended file attributes
#### LXATTRB
Extended file attribute for storing basic file information.  
All timestamps are starting from UNIX Epoch time.  
Fixed size structure.  

|Offset|Size|Note|
|---|---|---|
|0|4|Always ``00 00 01 00``.|
|4|4|File type and permission. (st_mode)|
|8|4|UID (st_uid)|
|12|4|GID (st_gid)|
|16|4|Device ID (st_rdev)|
|20|4|Nano seconds of access time. (st_atim.tv_nsec)|
|24|4|Nano seconds of modification time. (st_mtim.tv_nsec)|
|28|4|Nano seconds of status change time. (st_ctim.tv_nsec)|
|32|8|Seconds of access time. (st_atim.tv_sec)|
|40|8|Seconds of modification time. (st_mtim.tv_sec)|
|48|8|Seconds of status change time. (st_ctim.tv_sec)|

#### LXXATTR
Extended file attribute for storing extended file attributes.  
All Linux extended file attributes in a file stored into single NTFS extended file attribute.  
Extended file attribute names are case sensitive.  
Even characters that can not be used as NTFS extended file attribute names can be used for Linux extended file attribute names.  
Variable size structure.  

|Offset|Size|Note|
|---|---|---|
|0|4|Always ``00 00 01 00``.|
|4|4|Next entry relative offset. Zero if last. (*A*)|
|8|2|Length of xattr value. (*B*)|
|10|1|Length of xattr name. (*C*)|
|11|*C*|xattr name. UTF-8. No null terminator.|
|11 + *C*|*B*|xattr value.|
|11 + *B* + *C*|1|Unknown. Even if change to a random value, WSL does not worry.|
|4 + *A*| |Repeat above six elements.|

### Symbolic link
File size equal to link target size.  
Target data exist in ``::$DATA`` stream.  
Variable size.  

|Offset|Size|Note|
|---|---|---|
|0|Whole|UTF-8. No null terminator.|

## wslfs
The default file system for VolFs since version 1903.  
Same format as DrvFs, see DrvFs.  
VolFs after ``wslconfig /upgrade`` or ``wsl --upgrade``.  
If any of the following conditions are met, upgrade will fail.
- Two or more extended file attribute names that differ only in case are present in a file.
- Characters that can not be used for NTFS extended file attribute name is used in Linux extended file attribute name.

## drvfs
All timestamps retrieves from NTFS, and calculate on demand.  
Special files/device files are represented by reparse point.  
Official document https://docs.microsoft.com/en-us/windows/wsl/file-permissions  

### Filename escaping
Invalid characters on Win32 namespace convert to ``U+F000 + code point``. (Converts one character to one character.)  

### Extended file attributes
#### $LXMOD
Extended file attributes for storing file type and permission.  
Fixed size.  

|Offset|Size|Note|
|---|---|---|
|0|4|File type and permission. (st_mode)|

#### $LXUID
Extended file attributes for storing UID.  
Fixed size.  

|Offset|Size|Note|
|---|---|---|
|0|4|UID (st_uid)|

#### $LXGID
Extended file attributes for storing GID.  
Fixed size.  

|Offset|Size|Note|
|---|---|---|
|0|4|GID (st_gid)|

#### $LXDEV
Extended file attributes for storing Device ID.  
Fixed size structure.  

|Offset|Size|Note|
|---|---|---|
|0|4|Major|
|4|4|Minor|

#### LX.*
Extended file attributes for storing extended file attributes.  
Each Linux extended file attribute is stored in a separate NTFS extended file attribute.  
All extended file attribute names are prefixed with ``LX.``. (e.g. ``user.xdg.origin.url`` in WSL, ``LX.USER.XDG.ORIGIN.URL`` on NTFS)  
Extended file attribute names are case insensitive.  
Extended file attribute names are enumerated as all lowercase letters.  
Unusable characters for the extended file attribute name are [same as NTFS](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/0eb94f48-6aac-41df-a878-79f4dcfd8989).  
Multibyte characters are written to NTFS in UTF-8 encoding as is.  
Variable size structure.  

|Offset|Size|Note|
|---|---|---|
|0|4|Always ``lxea``|
|4|EaValueLength - 4|xattr value|

### Reparse points
Socket and symlink may not have $LX* extended file attributes.  

#### IO_REPARSE_TAG_LX_SYMLINK
Symbolic link on DrvFs.  
Tag value is ``0xA000001D``.  
- Created by until version 1709
  
  File size equal to link target size.  
  Target data exist in ``::$DATA`` stream.  
  Variable size.  
  
  |Offset|Size|Note|
  |---|---|---|
  |0|Whole|UTF-8. No null terminator.|

- Created by started with version 1803
  
  File size is zero.  
  Target data exist in ``::$REPARSE_DATA`` stream.  
  Variable size structure.  

  |Offset|Size|Note|
  |---|---|---|
  |0|4|Always ``02 00 00 00``|
  |4|ReparseDataLength - 4|UTF-8. No null terminator.|
  
  This represents ``GenericReparseBuffer::DataBuffer`` of ``REPARSE_DATA_BUFFER``.  
  For ``REPARSE_GUID_DATA_BUFFER`` This data starts at the ``ReparseGuid`` position.  

#### IO_REPARSE_TAG_AF_UNIX
UNIX domain socket on DrvFs.  
Shared with Winsock's AF_UNIX.  
Tag value is ``0x80000023``.  

#### IO_REPARSE_TAG_LX_FIFO
Fifo on DrvFs.  
Tag value is ``0x80000024``.  

#### IO_REPARSE_TAG_LX_CHR
Character special file on DrvFs.  
Tag value is ``0x80000025``.  

#### IO_REPARSE_TAG_LX_BLK
Block special file on DrvFs.  
Tag value is ``0x80000026``.  

## tmpfs
Always same format as lxfs, even after VolFs upgrade to wslfs.  
Filename case sensitivity is buggy.  
