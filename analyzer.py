import socket
import struct

HOST = "127.0.0.1"
PORT = 28011

def sign_extend(imm):
    if imm & 0x8000:
        return imm - 0x10000
    return imm

def read_instruction(s, address):
    try:
        body = struct.pack("<BQ", 2, address)
        length_prefix = struct.pack("<I", len(body))
        s.sendall(length_prefix + body)
        resp_len_data = s.recv(4)
        if not resp_len_data:
            return None
        resp_len = struct.unpack("<I", resp_len_data)[0]
        data = s.recv(resp_len)
        if len(data) >= 5:
            return struct.unpack("<I", data[1:5])[0]
        return None
    except Exception:
        return None

def perform_scan(log_callback):
    found_base = None
    found_a0 = None
    found_a1 = None
    found_entry = None
    profile_type = "Standard ELF Initialization"
    sc1_val = None
    sc2_val = None

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3.0)
            s.connect((HOST, PORT))
            log_callback("[+] Connected to PCSX2 PINE server")
 
            curr = 0x00100000
            end_addr = 0x00300000
            
            block_start = curr
            block1_curr = None
            block2_curr = None
            
            block1_a0, block1_a1, block1_a3 = None, None, None
            block2_a0 = None

            while curr <= end_addr:
                val = read_instruction(s, curr)
                if val is not None:
                    opcode = (val >> 26) & 0x3F
                    funct = val & 0x3F

                    if opcode == 0 and funct == 0x0C:
                        detected_syscall_code = None
                        prev_val = read_instruction(s, curr - 4)
                        if prev_val is not None:
                            p_op = (prev_val >> 26) & 0x3F
                            p_imm = prev_val & 0xFFFF
                            if p_op == 0x09:
                                detected_syscall_code = p_imm

                        if detected_syscall_code == 0x3C and block1_curr is None:
                            sc1_val = 0x3C
                            block1_curr = curr
                            log_callback(f"[+] Syscall 0x3C (#1) located at address: 0x{curr:08X}")
                            
                            regs = {i: 0 for i in range(32)}
                            for addr in range(block_start, curr + 4, 4):
                                inst_val = read_instruction(s, addr)
                                if inst_val is not None:
                                    op = (inst_val >> 26) & 0x3F
                                    rs = (inst_val >> 21) & 0x1F
                                    rt = (inst_val >> 16) & 0x1F
                                    rd = (inst_val >> 11) & 0x1F
                                    imm = inst_val & 0xFFFF
                                    f = inst_val & 0x3F

                                    if op == 0x0F:
                                        regs[rt] = (imm << 16) & 0xFFFFFFFF
                                    elif op == 0x09:
                                        regs[rt] = (regs[rs] + sign_extend(imm)) & 0xFFFFFFFF
                                    elif op == 0x00 and f == 0x25:
                                        regs[rd] = (regs[rs] | regs[rt]) & 0xFFFFFFFF

                            block1_a0 = regs[4]
                            block1_a1 = regs[5]
                            block1_a3 = regs[7]
                            block_start = curr + 4

                        elif detected_syscall_code == 0x3D and block2_curr is None:
                            sc2_val = 0x3D
                            block2_curr = curr
                            log_callback(f"[+] Syscall 0x3D (#2) located at address: 0x{curr:08X}")
                            
                            regs = {i: 0 for i in range(32)}
                            for addr in range(block_start, curr + 4, 4):
                                inst_val = read_instruction(s, addr)
                                if inst_val is not None:
                                    op = (inst_val >> 26) & 0x3F
                                    rs = (inst_val >> 21) & 0x1F
                                    rt = (inst_val >> 16) & 0x1F
                                    rd = (inst_val >> 11) & 0x1F
                                    imm = inst_val & 0xFFFF
                                    f = inst_val & 0x3F

                                    if op == 0x0F:
                                        regs[rt] = (imm << 16) & 0xFFFFFFFF
                                    elif op == 0x09:
                                        regs[rt] = (regs[rs] + sign_extend(imm)) & 0xFFFFFFFF
                                    elif op == 0x00 and f == 0x25:
                                        regs[rd] = (regs[rs] | regs[rt]) & 0xFFFFFFFF

                            block2_a0 = regs[4]
                            break

                curr += 4

            sync_found = False
            if block1_curr is not None:
                scan_start = max(0x00100000, block1_curr - 250)
                sync_addr = block1_curr
                while sync_addr >= scan_start:
                    inst_val = read_instruction(s, sync_addr)
                    if inst_val is not None:
                        op = (inst_val >> 26) & 0x3F
                        f = inst_val & 0x3F
                        if op == 0x00 and f == 0x0F:
                            log_callback(f"[+] SYNC located upstream at: 0x{sync_addr:08X}")
                            sync_found = True
                            break
                    sync_addr -= 4

            if sync_found:
                profile_type = "SYNC + Dual-Syscall Initialization"
                regs = {i: 0 for i in range(32)}
                locked_v1 = None
                first_a0 = None

                for addr in range(sync_addr, block1_curr + 4, 4):
                    inst_val = read_instruction(s, addr)
                    if inst_val is not None:
                        op = (inst_val >> 26) & 0x3F
                        rs = (inst_val >> 21) & 0x1F
                        rt = (inst_val >> 16) & 0x1F
                        rd = (inst_val >> 11) & 0x1F
                        imm = inst_val & 0xFFFF
                        f = inst_val & 0x3F

                        if op == 0x0F:
                            regs[rt] = (imm << 16) & 0xFFFFFFFF
                        elif op == 0x09:
                            regs[rt] = (regs[rs] + sign_extend(imm)) & 0xFFFFFFFF
                        elif op == 0x00 and f == 0x25:
                            regs[rd] = (regs[rs] | regs[rt]) & 0xFFFFFFFF

                        if locked_v1 is None and op == 0x09 and rt == 3:
                            if rs != 0 or abs(sign_extend(imm)) > 0xFF:
                                locked_v1 = regs[3]

                        if first_a0 is None and op == 0x0F and rt == 4:
                            first_a0 = regs[4]

                found_base = locked_v1 if locked_v1 is not None else regs[3]
                found_a0 = first_a0 if first_a0 is not None else block1_a0
                found_a1 = block1_a1
                found_entry = block1_a3
            else:
                log_callback("[*] SYNC skipped. running targeted syscall scan...")
                found_a0 = block1_a0
                found_a1 = block1_a1
                found_entry = block1_a3
                
                if block2_a0 is not None:
                    found_base = block2_a0
                    profile_type = "Standard ELF Initialization"
                elif block1_a0 is not None:
                    found_base = block1_a0
                    profile_type = "Fallback Initialization"

        return found_base, found_a0, found_a1, found_entry, profile_type, sc1_val, sc2_val
    except Exception as e:
        raise e