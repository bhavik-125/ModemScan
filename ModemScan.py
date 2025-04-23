import sys
import os
from unicornafl import Uc
from unicornafl.unicornafl import uc_afl_fuzz
from unicorn import (
    UC_ARCH_ARM, UC_MODE_ARM, UC_MODE_THUMB, UcError,
    UC_PROT_ALL, UC_PROT_NONE, UC_PROT_READ, UC_PROT_WRITE,
    UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED, UC_HOOK_INSN_INVALID,
    UC_MEM_WRITE_UNMAPPED, UC_MEM_READ_UNMAPPED, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
    UC_HOOK_BLOCK
)
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_CPSR

# === CONFIGURATION ===
ROM_START = 0x00000000
ROM_SIZE = 0x2000000  # 32 MB
RAM_START = 0x10000000
RAM_SIZE = 0x1000000  # 16 MB
INPUT_ADDR = 0x20000000
INPUT_SIZE = 0x1000  # 4 KB
FIRMWARE_PATH = "/home/bhavik/Desktop/task/l_modem.img" 
EXIT_ADDR = 0xDEADBEEF  # Placeholder

# MediaTek-specific memory regions
MTK_PERIPH_BASE = 0x04000000
MTK_PERIPH_SIZE = 0x1000000
MTK_MODEM_REGS = 0x70000000
MTK_MODEM_SIZE = 0x1000000

# MediaTek-specific entry points to try
ENTRY_POINTS = [
    0x400,   # Common MediaTek firmware entry point
    0x100,   # Alternative entry point
    0x1000,  # Another possible entry
    0x0      # Original starting point (least likely to work)
]

# Instruction tracking for debugging
executed_instructions = []
skip_instructions = True  # Set to True to skip invalid instructions
current_entry_point = None

def hook_code(uc, address, size, user_data):
    # Track executed instructions to identify crash location
    executed_instructions.append(address)
    if len(executed_instructions) <= 50:  # Limit output to avoid flooding
        print(f"Executing instruction at 0x{address:x}")

def hook_block(uc, address, size, user_data):
    # Monitor block execution to identify ARM/Thumb mode transitions
    if address & 1:
        print(f"Executing THUMB code block at 0x{address & ~1:x}")
    else:
        print(f"Executing ARM code block at 0x{address:x}")

def hook_invalid_insn(uc, user_data):
    pc = uc.reg_read(UC_ARM_REG_PC)
    print(f">>> Invalid instruction at 0x{pc:x}")
    
    # Read 4 bytes from PC to see the actual instruction
    try:
        insn = uc.mem_read(pc, 4)
        print(f">>> Instruction bytes: {insn.hex()}")
    except UcError:
        print(">>> Could not read instruction bytes")
    
    if skip_instructions:
        # Skip over problematic instruction
        next_pc = pc + 4  # Assume 32-bit ARM instruction
        print(f">>> Skipping to 0x{next_pc:x}")
        uc.reg_write(UC_ARM_REG_PC, next_pc)
        return True  # Continue execution
    
    return False  # Stop emulation if not skipping

def hook_mem_invalid(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE_UNMAPPED:
        print(f">>> Invalid WRITE at 0x{address:x}, data size = {size}, data value = 0x{value:x}")
        
        # Handle peripheral access
        if MTK_MODEM_REGS <= address < MTK_MODEM_REGS + MTK_MODEM_SIZE:
            # Map memory on demand for peripheral access
            aligned_addr = address & ~0xFFF  # 4KB alignment
            print(f">>> Mapping peripheral region at 0x{aligned_addr:x}")
            try:
                uc.mem_map(aligned_addr, 0x1000, UC_PROT_ALL)
                # Write the value anyway
                uc.mem_write(address, value.to_bytes(size, byteorder='little'))
                return True  # Continue execution
            except UcError as e:
                print(f">>> Failed to map memory: {e}")
    else:
        print(f">>> Invalid READ at 0x{address:x}, data size = {size}")
        
        # Handle peripheral read
        if MTK_MODEM_REGS <= address < MTK_MODEM_REGS + MTK_MODEM_SIZE:
            aligned_addr = address & ~0xFFF  # 4KB alignment
            print(f">>> Mapping peripheral region at 0x{aligned_addr:x}")
            try:
                uc.mem_map(aligned_addr, 0x1000, UC_PROT_ALL)
                # Return fake data (0x0)
                uc.mem_write(address, b'\x00' * size)
                return True  # Continue execution
            except UcError as e:
                print(f">>> Failed to map memory: {e}")
    
    return False  # Stop emulation if not handled

def setup_memory(uc):
    try:
        # Map base memory regions
        uc.mem_map(ROM_START, ROM_SIZE, UC_PROT_ALL)
        uc.mem_map(RAM_START, RAM_SIZE, UC_PROT_ALL)
        uc.mem_map(INPUT_ADDR, INPUT_SIZE, UC_PROT_ALL)
        uc.mem_map(INPUT_ADDR + INPUT_SIZE, 0x1000, UC_PROT_NONE)  # Guard page
        
        # Map MediaTek-specific memory regions
        uc.mem_map(MTK_PERIPH_BASE, MTK_PERIPH_SIZE, UC_PROT_ALL)
        
        # Initialize RAM with non-zero pattern to avoid null dereference
        uc.mem_write(RAM_START, b'\xAA' * RAM_SIZE)
        
        print("Memory regions mapped successfully")
    except UcError as e:
        print(f"Error mapping memory: {e}")
        sys.exit(1)

def load_firmware(uc, path):
    try:
        # Verify file exists with correct case sensitivity
        if not os.path.exists(path):
            print(f"ERROR: Could not find firmware file: {path}")
            print("Checking for alternative paths...")
            
            # Try different case variations of the filename
            directory = os.path.dirname(path)
            filename = os.path.basename(path)
            
            for file in os.listdir(directory):
                if file.lower() == filename.lower():
                    new_path = os.path.join(directory, file)
                    print(f"Found firmware at: {new_path}")
                    path = new_path
                    break
        
        with open(path, "rb") as f:
            fw = f.read()
            uc.mem_write(ROM_START, fw[:ROM_SIZE])
        print(f"Successfully loaded firmware: {path}")
        print(f"Firmware size: {len(fw)} bytes")
    except FileNotFoundError:
        print(f"ERROR: Could not find firmware file: {path}")
        print("Available files:")
        directory = os.path.dirname(path) or "."
        for file in os.listdir(directory):
            print(f" - {file}")
        sys.exit(1)
    except UcError as e:
        print(f"Error loading firmware: {e}")
        sys.exit(1)

def place_input(uc, inp, persistent_round, user_data):
    try:
        if persistent_round % 100 == 0:
            print(f"Processing round {persistent_round}")
        uc.mem_write(INPUT_ADDR, inp[:INPUT_SIZE])
        return True
    except UcError as e:
        print(f"[!] mem_write failed: {e}")
        return False

def try_entry_point(uc, entry_point):
    global current_entry_point
    current_entry_point = entry_point
    
    print(f"\n--- Trying entry point 0x{entry_point:x} ---")
    # Clear executed instructions for new attempt
    executed_instructions.clear()
    
    # Set PC to this entry point
    uc.reg_write(UC_ARM_REG_PC, entry_point)
    # Reset SP
    uc.reg_write(UC_ARM_REG_SP, RAM_START + RAM_SIZE - 4)
    
    # Set R0 and R1 to common parameter values
    uc.reg_write(UC_ARM_REG_R0, 0)
    uc.reg_write(UC_ARM_REG_R1, INPUT_ADDR)
    
    try:
        # Try to execute a small number of instructions to test this entry point
        uc.emu_start(entry_point, 0xFFFFFFFF, 0, 1000)
    except UcError as e:
        print(f"Emulation stopped: {e}")
        print(f"Executed {len(executed_instructions)} instructions")
        if len(executed_instructions) > 10:
            # If we executed several instructions, this might be a valid entry point
            return True
        return False

def validate_crash(uc, crash_type, crash_addr, input_data, user_data):
    # Handle crash_type (convert from C type if needed)
    try:
        if hasattr(crash_type, '_length_'):  # Is it a ctypes array?
            crash_type_bytes = bytes(crash_type)
            crash_type_str = str(int.from_bytes(crash_type_bytes, byteorder='little'))
        else:
            crash_type_str = str(crash_type)
    except Exception:
        crash_type_str = f"<error:{type(crash_type).__name__}>"
    
    # Handle crash_addr (convert from C type if needed)
    try:
        if hasattr(crash_addr, '_length_'):  # Is it a ctypes array?
            addr_bytes = bytes(crash_addr)
            # Try to interpret as a 32-bit address
            if len(addr_bytes) == 4:
                addr_int = int.from_bytes(addr_bytes, byteorder='little')
                addr_str = f"0x{addr_int:x}"
            else:
                addr_str = f"0x{addr_bytes.hex()}"
        elif hasattr(crash_addr, 'value'):  # Simple ctypes value
            addr_int = crash_addr.value
            addr_str = f"0x{addr_int:x}"
        else:
            # Try direct conversion
            addr_str = f"0x{int(crash_addr):x}"
    except Exception:
        addr_str = f"<error:{type(crash_addr).__name__}>"
    
    print(f"Validating crash: type={crash_type_str}, address={addr_str}")
    return True  # Consider all crashes valid for now




def main():
    # Create input seed if it doesn't exist
    if not os.path.exists("input_seed"):
        with open("input_seed", "wb") as f:
            f.write(b"AAAA")
        print("Created input_seed file")
    
    try:
        # Use both ARM and THUMB mode
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_THUMB)
        setup_memory(uc)
        load_firmware(uc, FIRMWARE_PATH)
        
        # Add hooks for debugging
        uc.hook_add(UC_HOOK_CODE, hook_code)
        uc.hook_add(UC_HOOK_BLOCK, hook_block)
        uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem_invalid)
        uc.hook_add(UC_HOOK_INSN_INVALID, hook_invalid_insn)
        
        # Try different entry points to find one that works
        successful_entry_point = None
        for entry in ENTRY_POINTS:
            if try_entry_point(uc, entry):
                successful_entry_point = entry
                print(f"Found promising entry point at 0x{entry:x}")
                break
        
        if successful_entry_point is None:
            print("Could not find a valid entry point. Using default 0x400")
            successful_entry_point = 0x400
        
        # Reset emulator for real fuzzing run
        uc.reg_write(UC_ARM_REG_PC, successful_entry_point)
        uc.reg_write(UC_ARM_REG_SP, RAM_START + RAM_SIZE - 4)
        
        # Start fuzzing with improved error handling
        try:
            print(f"\n--- Starting fuzzing at entry point 0x{successful_entry_point:x} ---")
            uc_afl_fuzz(
                uc,
                input_file=sys.argv[1] if len(sys.argv) > 1 else "input_seed",
                place_input_callback=place_input,
                exits=[EXIT_ADDR],
                persistent_iters=1000,
                validate_crash_callback=validate_crash  # FIXED: Use our validate_crash function
            )
        except Exception as e:
            print(f"Fuzzing error: {e}")
            print("Last executed addresses before crash:")
            for i, addr in enumerate(executed_instructions[-10:]):
                print(f"  {i}: 0x{addr:x}")
    except UcError as e:
        print(f"Unicorn initialization error: {e}")

if __name__ == "__main__":
    main()
