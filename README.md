# ModemScan

**ModemScan** is a firmware fuzzing and dynamic analysis tool designed for MediaTek modem images. It leverages the power of Unicorn and AFL (via `unicornafl`) to emulate ARM-based baseband firmware and identify vulnerabilities or undocumented behavior in modem memory regions.

## 🚀 Features

- Emulates ARM & THUMB instructions using Unicorn Engine.
- Fuzzes inputs with AFL (American Fuzzy Lop) integration.
- Dynamically maps MediaTek-specific peripheral memory on access.
- Handles invalid instructions gracefully to allow continued fuzzing.
- Tries multiple entry points to find a valid execution start.
- Provides real-time hooks for:
  - Code execution
  - Basic block transitions
  - Invalid memory accesses
  - Unmapped memory handling
  - Invalid instructions

## 🧠 Use Case

This tool is particularly useful for reverse engineers and security researchers working with modem firmware, especially MediaTek-based devices.

## 🛠️ Requirements

- Python 3.6+
- [`unicornafl`](https://github.com/AFLplusplus/unicornafl)
- [`unicorn`](https://github.com/unicorn-engine/unicorn)

Install dependencies:

```bash
pip install unicornafl unicorn
```

## 📂 File Structure

- `main.py` — Core emulator and fuzzing logic.
- `input_seed` — Initial fuzzing input (automatically created if missing).
- `l_modem.img` — MediaTek firmware image (must be placed manually).

## ⚙️ Configuration

Set the path to your modem image in the script:

```python
FIRMWARE_PATH = "/home/bhavik/Desktop/task/l_modem.img"
```

Adjust memory regions and entry points if needed.

## 🧪 Running

To start fuzzing:

```bash
python3 main.py input_seed
```

It will attempt to emulate and fuzz the provided firmware using various entry points. If no valid entry is found, a default will be used.

## 🔍 Emulation Hooks

The following are tracked and logged during emulation:

- Executed instructions (`hook_code`)
- Block transitions (ARM ↔ THUMB) (`hook_block`)
- Invalid memory reads/writes (`hook_mem_invalid`)
- Invalid instructions (`hook_invalid_insn`)

---


## 🖥️Output

Below is a sample run of `ModemScan` showing memory setup, firmware loading, emulation, and fuzzing:

```
Memory regions mapped successfully
Successfully loaded firmware: /home/bhavik/Desktop/task/l_modem.img
Firmware size: 26214400 bytes

--- Trying entry point 0x400 ---
Executing ARM code block at 0x400
Executing instruction at 0x400
Executing instruction at 0x404
...
Executing instruction at 0x4c4
Emulation stopped: Unhandled CPU exception (UC_ERR_EXCEPTION)
Executed 114 instructions
Found promising entry point at 0x400

--- Starting fuzzing at entry point 0x400 ---
Processing round 0
Executing ARM code block at 0x400
Validating crash: type=21, address=0x41414141
```

This shows that `ModemScan`:
- Successfully identifies valid entry points
- Logs execution details for debugging
- Detects and validates crashes during fuzzing

## 📌 Notes

- Currently assumes a 32MB ROM and 16MB RAM layout.
- Maps peripheral regions on demand to simulate hardware behavior.
- `EXIT_ADDR = 0xDEADBEEF` is a placeholder for graceful exit detection.

