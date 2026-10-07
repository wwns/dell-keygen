import sys
import re
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from threading import Thread


def _resource(name: str) -> str:
    """Ścieżka do zasobu działająca zarówno z PyInstaller (--onefile) jak i ze skryptu."""
    if getattr(sys, 'frozen', False):
        base = Path(sys._MEIPASS)  # type: ignore[attr-defined]
    else:
        base = Path(__file__).parent
    return str(base / name)

# ---------------------------------------------------------------------------
# Core logic (z patcher.py)
# ---------------------------------------------------------------------------

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
    regex = re.compile(pattern)
    end = min(len(source), start + limit)
    i = start
    while i < end - 8:
        if source[i] == 0x00 and source[i + 1] in (0xFC, 0xFD):
            for chunk_size in range(8, 33):
                if i + chunk_size > len(source):
                    break
                chunk = source[i:i + chunk_size]
                hex_chunk = byte_array_to_string(chunk)
                if regex.match(hex_chunk):
                    yield i
                    break
        i += 1


_NVAR_SIG = b"NVAR"
_ST_NAME = b"ServiceTag\x00"   # 11 bytes
_NVAR_HDR = 11                  # 4(sig)+2(size)+3(next)+1(attr)+1(guid_idx)


def _find_nvar_free_space(data: bytes, nvar_off: int) -> int:
    """
    Liniowo przechodzi NVAR rekordy od nvar_off do przodu.
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
    # sprawdz czy to faktycznie wolne (0xFF)
    if i < len(data) and data[i] == 0xFF:
        return i
    return -1


def write_service_tag(data: bytearray, tag: str, log) -> int:
    """
    Wstrzykuje Service Tag do NVRAM (AMI NVAR) w obrazie BIOS Dell.
    Dodaje nowy rekord NVAR z tagiem i uaktualnia wskaźnik Next starego.
    Zwraca liczbę zaktualizowanych kopii NVRAM (typowo 2: primary + backup).
    """
    tag_upper = tag.upper().strip()
    if not re.match(r"^[A-Z0-9]{5,7}$", tag_upper):
        log(f"  UWAGA: Service Tag '{tag}' ma nieprawidłowy format (oczekiwano 5-7 znaków)")
        return 0

    tag_bytes = tag_upper.encode("ascii") + b"\x00"
    count = 0

    # --- Zbierz najpierw wszystkie oryginalne rekordy ServiceTag (przed modyfikacją) ---
    originals = []
    search = 0
    while True:
        idx = data.find(_ST_NAME, search)
        if idx == -1:
            break
        nvar_off = idx - _NVAR_HDR
        if nvar_off >= 0 and data[nvar_off:nvar_off + 4] == _NVAR_SIG:
            next_bytes = data[nvar_off + 6:nvar_off + 9]
            if next_bytes == b"\xff\xff\xff":
                originals.append(nvar_off)
        search = idx + 1

    # --- Teraz przetwarzaj zebrane rekordy ---
    for nvar_off in originals:
        attr = data[nvar_off + 9]
        guid_idx = data[nvar_off + 10]

        # Znajdź wolne miejsce po tym NVAR (koniec łańcucha NVAR)
        free_off = _find_nvar_free_space(data, nvar_off)
        if free_off < 0:
            log(f"  WARN: Brak wolnego miejsca po ServiceTag @ 0x{nvar_off:X}")
            continue

        # Sprawdź czy tag nie jest już wpisany
        cur_size = int.from_bytes(data[nvar_off + 4:nvar_off + 6], "little")
        existing_data = data[nvar_off + _NVAR_HDR + len(_ST_NAME):nvar_off + cur_size]
        if existing_data.rstrip(b"\x00\x01") == tag_bytes.rstrip(b"\x00"):
            log(f"  Service Tag '{tag_upper}' już obecny @ 0x{nvar_off:X}")
            continue

        # Zbuduj nowy rekord NVAR
        new_size = _NVAR_HDR + len(_ST_NAME) + len(tag_bytes)
        new_rec = bytearray()
        new_rec += _NVAR_SIG
        new_rec += new_size.to_bytes(2, "little")
        new_rec += b"\xff\xff\xff"      # Next = koniec łańcucha
        new_rec += bytes([attr])
        new_rec += bytes([guid_idx])
        new_rec += _ST_NAME
        new_rec += tag_bytes

        # Zapisz nowy rekord w wolnym miejscu
        data[free_off:free_off + new_size] = new_rec

        # Zaktualizuj Next starego rekordu (self-relative offset)
        rel_next = free_off - nvar_off
        data[nvar_off + 6:nvar_off + 9] = rel_next.to_bytes(3, "little")

        log(f"  NVAR ServiceTag @ 0x{nvar_off:X} -> nowy rekord @ 0x{free_off:X} (Next=0x{rel_next:X})")
        count += 1

    if count == 0:
        log("  Nie znaleziono rekordu NVAR ServiceTag — ten BIOS może używać innego formatu")

    return count


def patch_bios(filepath: str, service_tag: str, log) -> bool:
    try:
        with open(filepath, "rb") as f:
            data = bytearray(f.read())
    except Exception as e:
        log(f"Błąd odczytu pliku: {e}")
        return False

    filename = Path(filepath).name
    log(f"Wczytano: {filename} ({len(data):,} bajtów)")

    # Intel signature
    signo = convert_hex_string_to_bytes("5AA5F00F03")
    found_sig = False
    for index in signo_at(data, signo):
        log(f"Intel signature @ 0x{index:X}  [OK]")
        found_sig = True

    if not found_sig:
        log("BŁĄD: Intel signature nie znaleziona — to nie jest SPI dump Intel BIOS")
        return False

    # Pattern 1
    firstpattern = r"^00FCAA([0-9A-F]{2,4})000000([0-9A-F]{2,})$"
    replacefirst = convert_hex_string_to_bytes("00FC00")
    p1_count = 0
    for index in pattern_at(data, firstpattern, start=0, limit=0x160000):
        original = data[index:index + 16].hex().upper()
        data[index:index + len(replacefirst)] = replacefirst
        log(f"Pattern1 @ 0x{index:X}: {original[:12]}... -> 00FC00")
        p1_count += 1

    # Pattern 2
    secondpattern = r"^00FDAA([0-9A-F]{2,4})000000([0-9A-F]{2,})$"
    replacesecond = convert_hex_string_to_bytes("00FD00")
    p2_count = 0
    for index in pattern_at(data, secondpattern, start=0, limit=0x160000):
        original = data[index:index + 16].hex().upper()
        data[index:index + len(replacesecond)] = replacesecond
        log(f"Pattern2 @ 0x{index:X}: {original[:12]}... -> 00FD00")
        p2_count += 1

    if p1_count + p2_count == 0:
        log("Brak wzorców 8FC8 — ten BIOS nie wymaga patchowania lub wzorce są skompresowane.")
        return False

    log(f"Wzorce: Pattern1={p1_count}, Pattern2={p2_count}")

    # Service Tag
    tag = service_tag.strip()
    if tag:
        log(f"Wpisywanie Service Tag '{tag.upper()}'...")
        write_service_tag(data, tag, log)

    # Zapis
    out_path = Path(filepath).parent / f"patched_{filename}"
    try:
        with open(out_path, "wb") as f:
            f.write(data)
        log(f"Zapisano: {out_path}")
        return True
    except Exception as e:
        log(f"Błąd zapisu: {e}")
        return False


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class PatcherApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Dell 8FC8 BIOS Patcher")
        self.resizable(True, True)
        self.minsize(600, 420)
        try:
            self.iconbitmap(_resource("patcher.ico"))
        except Exception:
            pass
        self._build_ui()

    def _build_ui(self):
        pad = {"padx": 8, "pady": 4}

        # --- BIOS file row ---
        frm_file = ttk.LabelFrame(self, text="Plik BIOS (.bin / .rom)")
        frm_file.pack(fill="x", **pad)

        self.var_file = tk.StringVar()
        ttk.Entry(frm_file, textvariable=self.var_file, width=60).pack(
            side="left", fill="x", expand=True, padx=4, pady=4
        )
        ttk.Button(frm_file, text="Przeglądaj...", command=self._browse_file).pack(
            side="right", padx=4, pady=4
        )

        # --- Service Tag row ---
        frm_tag = ttk.LabelFrame(self, text="Service Tag (opcjonalnie — zostanie wpisany do BIOS-u)")
        frm_tag.pack(fill="x", **pad)

        self.var_tag = tk.StringVar()
        tag_entry = ttk.Entry(frm_tag, textvariable=self.var_tag, width=20,
                              font=("Consolas", 11))
        tag_entry.pack(side="left", padx=4, pady=4)
        ttk.Label(frm_tag, text="5-7 znaków, np. JJDPFB3", foreground="gray").pack(
            side="left", padx=8
        )

        # Validate uppercase on input
        vcmd = (self.register(self._validate_tag), "%P")
        tag_entry.config(validate="key", validatecommand=vcmd)

        # --- Buttons ---
        frm_btn = ttk.Frame(self)
        frm_btn.pack(fill="x", **pad)

        self.btn_patch = ttk.Button(frm_btn, text="Patchuj BIOS", command=self._start_patch)
        self.btn_patch.pack(side="left", padx=4, pady=4)

        ttk.Button(frm_btn, text="Wyczyść log", command=self._clear_log).pack(
            side="left", padx=4, pady=4
        )

        self.var_status = tk.StringVar(value="Gotowy")
        ttk.Label(frm_btn, textvariable=self.var_status, foreground="blue").pack(
            side="right", padx=8
        )

        # --- Hacker animation canvas ---
        self.anim_frame = tk.Frame(self, bg="#1e1e1e", height=28)
        self.anim_frame.pack(fill="x", padx=8)
        self.anim_frame.pack_forget()  # ukryty na start

        self.anim_label = tk.Label(
            self.anim_frame,
            text="",
            font=("Consolas", 9),
            bg="#1e1e1e",
            fg="#00ff41",
            anchor="w"
        )
        self.anim_label.pack(fill="x", padx=6)
        self._anim_job = None
        self._anim_step = 0

        # --- Log ---
        self._frm_log = ttk.LabelFrame(self, text="Log")
        self._frm_log.pack(fill="both", expand=True, **pad)

        self.log_text = tk.Text(self._frm_log, font=("Consolas", 9), state="disabled",
                                bg="#1e1e1e", fg="#d4d4d4", insertbackground="white")
        self.log_text.pack(side="left", fill="both", expand=True)

        sb = ttk.Scrollbar(self._frm_log, orient="vertical", command=self.log_text.yview)
        sb.pack(side="right", fill="y")
        self.log_text["yscrollcommand"] = sb.set

        # Tag colors
        self.log_text.tag_config("ok",    foreground="#4ec9b0")
        self.log_text.tag_config("warn",  foreground="#dcdcaa")
        self.log_text.tag_config("error", foreground="#f48771")
        self.log_text.tag_config("info",  foreground="#9cdcfe")

    # --- helpers ---

    def _validate_tag(self, new_val: str) -> bool:
        if new_val == "":
            return True
        return bool(re.match(r"^[A-Za-z0-9]{0,7}$", new_val))

    def _browse_file(self):
        path = filedialog.askopenfilename(
            title="Wybierz plik BIOS",
            filetypes=[("BIOS dump", "*.bin *.rom *.fd"), ("Wszystkie pliki", "*.*")]
        )
        if path:
            self.var_file.set(path)

    def _log(self, msg: str):
        tag = "info"
        ml = msg.lower()
        if "błąd" in ml or "error" in ml:
            tag = "error"
        elif "ok" in ml or "zapisano" in ml or "patched" in ml:
            tag = "ok"
        elif "uwaga" in ml or "brak" in ml or "nie znaleziono" in ml:
            tag = "warn"

        self.log_text.config(state="normal")
        self.log_text.insert("end", msg + "\n", tag)
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _clear_log(self):
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")

    # --- Animation ---

    _ANIM_LINES = [
        "[>] Skanowanie regionu SPI flash...",
        "[>] Szukanie wzorców 8FC8...",
        "[>] Rozkładanie struktury UEFI...",
        "[>] Analiza deskryptora Intel...",
        "[>] Łamanie zabezpieczeń DSM...",
        "[>] Omijanie Dell Security Manager...",
        "[>] Wydobywanie kluczy szyfrowania...",
        "[>] Neutralizowanie hooków 00FCAA...",
        "[>] Przepisywanie tablicy wektorów...",
        "[>] Rekonstrukcja obrazu BIOS...",
        "[>] Weryfikacja sumy kontrolnej...",
        "[>] Wstrzykiwanie łatki do NVRAM...",
        "[>] Synchronizacja z SMBIOS...",
    ]

    _HEX_CHARS = "0123456789ABCDEF"

    def _anim_tick(self):
        import random
        step = self._anim_step
        line = self._ANIM_LINES[step % len(self._ANIM_LINES)]
        # losowy ciąg hex na końcu dla efektu
        noise = " " + "".join(random.choices(self._HEX_CHARS, k=16))
        self.anim_label.config(text=line + noise)
        self._anim_step += 1
        self._anim_job = self.after(140, self._anim_tick)

    def _start_anim(self):
        self._anim_step = 0
        self.anim_frame.pack(fill="x", padx=8, before=self._frm_log)
        self._anim_tick()

    def _stop_anim(self):
        if self._anim_job:
            self.after_cancel(self._anim_job)
            self._anim_job = None
        self.anim_label.config(text="")
        self.anim_frame.pack_forget()

    def _set_busy(self, busy: bool):
        state = "disabled" if busy else "normal"
        self.btn_patch.config(state=state)
        self.var_status.set("Patchuję..." if busy else "Gotowy")
        if busy:
            self._start_anim()
        else:
            self._stop_anim()

    def _start_patch(self):
        filepath = self.var_file.get().strip()
        if not filepath:
            messagebox.showwarning("Brak pliku", "Wybierz plik BIOS przed patchowaniem.")
            return

        tag = self.var_tag.get().strip()
        self._set_busy(True)

        def worker():
            try:
                result = patch_bios(filepath, tag, self._log)
                status = "Sukces!" if result else "Brak wzorców / błąd"
                self.after(0, lambda: self.var_status.set(status))
            finally:
                self.after(0, lambda: self._set_busy(False))

        Thread(target=worker, daemon=True).start()


if __name__ == "__main__":
    app = PatcherApp()
    app.mainloop()
