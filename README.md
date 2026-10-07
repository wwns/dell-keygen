# Dell 8FC8 BIOS Patcher

Windows tool for patching supported Dell Intel BIOS images that contain the
recognized 8FC8 patterns. The GUI can also write an optional Dell Service Tag
to AMI NVAR records.

This is an unofficial, community-made tool and is not affiliated with or
endorsed by Dell.

## Important safety notice

Modifying firmware can make a computer unbootable. Use this only on a device
you own or are authorized to service. Make and verify a complete backup of the
original BIOS before patching, and verify the output with suitable firmware
tools before any write or flash operation. Do not flash an image just because
this tool produced an output file.

The patcher has limited pattern and image-format support. It requires an Intel
signature near the beginning of the image and searches for supported patterns
within the first `0x160000` bytes. Compressed, unsupported, or otherwise
different BIOS layouts may not be recognized.

## Download

Download `Dell_8FC8_Patcher_v2.exe` from the
[latest GitHub release](https://github.com/wwns/dell-keygen/releases/latest).
The executable is a Windows GUI application and does not require a separate
Python installation.

## Use the GUI

1. Open the patcher and select a BIOS dump (`.bin`, `.rom`, or `.fd`).
2. Optionally enter a 5-7 character alphanumeric Service Tag.
3. Select **Patchuj BIOS** and review the log.
4. If supported patterns are found, the output is saved next to the input as
   `patched_<original filename>`.

The optional Service Tag update only applies when a compatible AMI NVAR
`ServiceTag` record is present. Review the log; a saved image does not
necessarily mean that the Service Tag was changed.

## Command-line version

Requires Python 3.9 or newer:

```powershell
python patcher.py path\to\bios.bin [SERVICE_TAG]
```

The command-line version writes `patched_<original filename>` to the current
working directory.

## Build the GUI from source

Requires Windows, Python 3.9 or newer, and PyInstaller:

```powershell
python -m pip install pyinstaller
pyinstaller --clean --noconfirm patcher_gui.spec
```

The built application is written to `dist\Dell_8FC8_Patcher.exe`.
