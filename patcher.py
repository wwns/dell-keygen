import sys
import re
from pathlib import Path

_NVAR_SIG = b"NVAR"
_ST_NAME = b"ServiceTag\x00"   # 11 bytes
_NVAR_HDR = 11                  # 4(sig)+2(size)+3(next)+1(attr)+1(guid_idx)


def convert_hex_string_to_bytes(hex_string: str) -> bytes:
    if len(hex_string) % 2 != 0:
        raise ValueError(f"Invalid hex string length: {hex_string}")
    return bytes.fromhex(hex_string)


def byte_array_to_string(b: bytes) -> str:
    return b.hex().upper()


def signo_at(source: bytes, pattern: bytes, limit: int = 0x1000):
    for i in range(min(len(source), limit)):
        if source[i:i + len(pattern)] == pattern:
            yield i


def pattern_at(source: bytes, pattern: str, start: int = 0, limit: int = 0x160000):
    """
    Szuka wzorca binarnego przez konwersje bajtow na hex-string.
    Region: od start do limit (domyslnie 0..0x160000 jak w oryginalnym VB).
    Wzorzec: 00 FC/FD AA [1-2B] 00 00 00 [1+B] -> min 8 bajtow.
    """
    regex = re.compile(pattern)
    end = min(len(source), start + limit)

    i = start
    while i < end - 8:
        # Sprawdz czy bajty i i i+1 to 00FC lub 00FD
        if source[i] == 0x00 and source[i+1] in (0xFC, 0xFD):
            # Probuj rozne dlugosci chunk (min 8, max 32 bajtow)
            for chunk_size in range(8, 33):
                if i + chunk_size > len(source):
                    break
                chunk = source[i:i + chunk_size]
                hex_chunk = byte_array_to_string(chunk)
                if regex.match(hex_chunk):
                    yield i
                    break
        i += 1


def _find_nvar_free_space(data: bytes, nvar_off: int) -> int:
    """
    Liniowo przechodzi NVAR rekordy od nvar_off.
    Zwraca offset pierwszego wolnego bajtu (0xFF) po łańcuchu.
    """
    i = nvar_off
    while i + 6 <= len(data):
        if data[i:i + 4] != _NVAR_SIG:
            break
        size = int.from_bytes(data[i + 4:i + 6], "little")
        if size < _NVAR_HDR or size > 0x8000:
            break
        i += size
    if i < len(data) and data[i] == 0xFF:
        return i
    return -1


def inject_service_tag(data: bytearray, tag: str) -> list[str]:
    """
    Wstrzykuje Service Tag do NVRAM (AMI NVAR) w obrazie BIOS Dell.
    Zwraca listę komunikatów (wyniki).
    """
    tag_upper = tag.upper().strip()
    if not re.match(r"^[A-Z0-9]{5,7}$", tag_upper):
        return [f"UWAGA: Service Tag '{tag}' ma nieprawidłowy format (oczekiwano 5-7 znaków)"]

    tag_bytes = tag_upper.encode("ascii") + b"\x00"
    msgs = []
    count = 0

    # --- Zbierz najpierw wszystkie oryginalne rekordy (przed modyfikacją) ---
    originals = []
    search = 0
    while True:
        idx = data.find(_ST_NAME, search)
        if idx == -1:
            break
        nvar_off = idx - _NVAR_HDR
        if nvar_off >= 0 and data[nvar_off:nvar_off + 4] == _NVAR_SIG:
            if data[nvar_off + 6:nvar_off + 9] == b"\xff\xff\xff":
                originals.append(nvar_off)
        search = idx + 1

    # --- Przetwarzaj zebrane rekordy ---
    for nvar_off in originals:
        attr = data[nvar_off + 9]
        guid_idx = data[nvar_off + 10]

        free_off = _find_nvar_free_space(data, nvar_off)
        if free_off < 0:
            msgs.append(f"WARN: Brak wolnego miejsca po ServiceTag @ 0x{nvar_off:X}")
            continue

        # Zbuduj nowy rekord NVAR
        new_size = _NVAR_HDR + len(_ST_NAME) + len(tag_bytes)
        new_rec = bytearray()
        new_rec += _NVAR_SIG
        new_rec += new_size.to_bytes(2, "little")
        new_rec += b"\xff\xff\xff"
        new_rec += bytes([attr])
        new_rec += bytes([guid_idx])
        new_rec += _ST_NAME
        new_rec += tag_bytes

        data[free_off:free_off + new_size] = new_rec

        rel_next = free_off - nvar_off
        data[nvar_off + 6:nvar_off + 9] = rel_next.to_bytes(3, "little")

        msgs.append(f"ServiceTag NVAR @ 0x{nvar_off:X} -> nowy @ 0x{free_off:X} (Next=0x{rel_next:X})")
        count += 1

    if count == 0:
        msgs.append("Nie znaleziono rekordu NVAR ServiceTag")

    return msgs


def main():
    if len(sys.argv) < 2:
        print("Usage: python patcher.py <bios.bin> [SERVICE_TAG]")
        return -1

    filepath = sys.argv[1]
    service_tag = sys.argv[2] if len(sys.argv) >= 3 else ""

    try:
        with open(filepath, "rb") as f:
            data = bytearray(f.read())
    except Exception as e:
        print(f"Error reading file: {e}")
        return -1

    print(f"Loaded: {filepath} ({len(data)} bytes)")
    filename = Path(filepath).name

    # --- Intel signature check ---
    signo = convert_hex_string_to_bytes("5AA5F00F03")
    found_signature = False
    for index in signo_at(data, signo):
        print(f"Intel signature found at offset 0x{index:X}")
        found_signature = True

    if not found_signature:
        print("Error: Intel signature not found")
        return -1

    # --- First pattern: 00FCAA[1-2B]000000[1+B] -> 00FC00 ---
    firstpattern = r"^00FCAA([0-9A-F]{2,4})000000([0-9A-F]{2,})$"
    replacefirst = convert_hex_string_to_bytes("00FC00")

    first_found = False
    for index in pattern_at(data, firstpattern):
        original = data[index:index+16].hex().upper()
        data[index:index + len(replacefirst)] = replacefirst
        print(f"Pattern1 found @ 0x{index:X}: {original} -> patched")
        first_found = True

    # --- Second pattern: 00FDAA[1-2B]000000[1+B] -> 00FD00 ---
    secondpattern = r"^00FDAA([0-9A-F]{2,4})000000([0-9A-F]{2,})$"
    replacesecond = convert_hex_string_to_bytes("00FD00")

    second_found = False
    for index in pattern_at(data, secondpattern):
        original = data[index:index+16].hex().upper()
        data[index:index + len(replacesecond)] = replacesecond
        print(f"Pattern2 found @ 0x{index:X}: {original} -> patched")
        second_found = True

    if first_found or second_found:
        # Service Tag injection
        if service_tag.strip():
            print(f"Wpisywanie Service Tag '{service_tag.upper()}'...")
            for msg in inject_service_tag(data, service_tag):
                print(f"  {msg}")

        out_path = f"patched_{filename}"
        try:
            with open(out_path, "wb") as f:
                f.write(data)
            print(f"Patched file saved as {out_path}")
        except Exception as e:
            print(f"Error writing file: {e}")
            return -1
        return 0
    else:
        print("No matching patterns found - this BIOS may not need 8FC8 patching")
        return -1


if __name__ == "__main__":
    sys.exit(main())
