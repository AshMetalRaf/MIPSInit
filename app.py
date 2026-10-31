import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from styles import (
    BG_DARK, BG_HEADER, BG_CARD, BORDER_COLOR, SECONDARY_TEXT, 
    TEXT_LIGHT, CONSOLE_BG, SUCCESS_COLOR, ACCENT_BLUE, 
    WARNING_YELLOW, apply_styles, create_copy_button
)
from analyzer import perform_scan

import sys
import os

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class PS2AnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MIPSInit")
        self.root.geometry("750x680")
        self.root.minsize(750, 680)
        self.root.configure(bg=BG_DARK)
        
        self.style = ttk.Style()
        apply_styles(self.style)

        try:
            self.root.iconbitmap(resource_path("icon.ico"))
        except Exception:
            pass
        
        self.root.option_add('*TCombobox*Listbox.background', '#1a1a1a')
        self.root.option_add('*TCombobox*Listbox.foreground', TEXT_LIGHT)
        self.root.option_add('*TCombobox*Listbox.selectBackground', '#009688')
        self.root.option_add('*TCombobox*Listbox.selectForeground', '#ffffff')
        self.root.option_add('*TCombobox*Listbox.font', ('Segoe UI', 9))
        
        header_frame = tk.Frame(root, bg=BG_HEADER, padx=20, pady=12, highlightbackground=BORDER_COLOR, highlightthickness=1)
        header_frame.pack(fill=tk.X)
        
        title_block = tk.Frame(header_frame, bg=BG_HEADER)
        title_block.pack(side=tk.LEFT)
        tk.Label(title_block, text="PS2 MIPS Initialization", fg=TEXT_LIGHT, bg=BG_HEADER, font=("Segoe UI", 12, "bold")).pack(anchor=tk.W)
        tk.Label(title_block, text="PCSX2 PINE Protocol", fg=SECONDARY_TEXT, bg=BG_HEADER, font=("Segoe UI", 8)).pack(anchor=tk.W, pady=(1, 0))
        
        notice_frame = tk.Frame(root, bg=BG_CARD, padx=14, pady=8, highlightbackground=BORDER_COLOR, highlightthickness=1)
        notice_frame.pack(fill=tk.X, padx=16, pady=(12, 0))
        tk.Label(
            notice_frame, 
            text="⚠️ Note: Make sure PINE is enabled in PCSX2 (Settings > Advanced > Enable PINE) and restart before scanning.", 
            fg=WARNING_YELLOW, 
            bg=BG_CARD, 
            font=("Segoe UI", 8)
        ).pack(anchor=tk.W)
        
        control_frame = tk.Frame(root, bg=BG_DARK)
        control_frame.pack(fill=tk.X, padx=16, pady=12)
        
        self.run_btn_container = tk.Frame(control_frame, bg="#3c3c3c", padx=1, pady=1)
        self.run_btn_container.pack(side=tk.LEFT)
        
        self.run_btn = tk.Button(
            self.run_btn_container, 
            text="Scan Memory", 
            bg=BG_DARK, 
            fg=TEXT_LIGHT, 
            activebackground=BG_DARK, 
            activeforeground=TEXT_LIGHT, 
            relief=tk.FLAT, 
            font=("Segoe UI", 9, "bold"), 
            padx=12,
            pady=3,
            cursor="hand2", 
            command=self.start_analysis_thread,
            highlightthickness=0
        )
        self.run_btn.pack(fill=tk.BOTH, expand=True)
        
        def on_enter(e):
            self.run_btn_container.config(bg="#00bfa5")
            
        def on_leave(e):
            self.run_btn_container.config(bg="#3c3c3c")
            
        self.run_btn.bind("<Enter>", on_enter)
        self.run_btn.bind("<Leave>", on_leave)
        self.run_btn_container.bind("<Enter>", on_enter)
        self.run_btn_container.bind("<Leave>", on_leave)
        
        self.status_lbl = tk.Label(control_frame, text="● Status: Ready", font=("Segoe UI", 9), fg="#ffb74d", bg=BG_DARK)
        self.status_lbl.pack(side=tk.RIGHT, padx=5)
        
        result_card = tk.Frame(root, bg=BG_CARD, padx=14, pady=12, highlightbackground=BORDER_COLOR, highlightthickness=1)
        result_card.pack(fill=tk.X, padx=16, pady=(0, 10))
        
        tk.Label(result_card, text="Start of Dynamic Memory", fg=TEXT_LIGHT, bg=BG_CARD, font=("Segoe UI", 9, "bold")).pack(anchor=tk.W)
        mem_row = tk.Frame(result_card, bg=BG_CARD)
        mem_row.pack(anchor=tk.W, pady=(2, 4))
        self.mem_result_lbl = tk.Label(mem_row, text="--", fg=SECONDARY_TEXT, bg=BG_CARD, font=("Consolas", 14, "bold"))
        self.mem_result_lbl.pack(side=tk.LEFT)
        self.mem_copy_btn = create_copy_button(mem_row, lambda: self.copy_to_clipboard(self.mem_result_lbl.cget("text"), self.mem_copy_btn))
        
        tk.Label(result_card, text="Base Address", fg=TEXT_LIGHT, bg=BG_CARD, font=("Segoe UI", 9, "bold")).pack(anchor=tk.W, pady=(2, 0))
        a0_row = tk.Frame(result_card, bg=BG_CARD)
        a0_row.pack(anchor=tk.W, pady=(2, 4))
        self.a0_result_lbl = tk.Label(a0_row, text="--", fg=SECONDARY_TEXT, bg=BG_CARD, font=("Consolas", 12, "bold"))
        self.a0_result_lbl.pack(side=tk.LEFT)
        self.a0_copy_btn = create_copy_button(a0_row, lambda: self.copy_to_clipboard(self.a0_result_lbl.cget("text"), self.a0_copy_btn))
        
        tk.Label(result_card, text="Stack Boundary", fg=TEXT_LIGHT, bg=BG_CARD, font=("Segoe UI", 9, "bold")).pack(anchor=tk.W, pady=(2, 0))
        a1_row = tk.Frame(result_card, bg=BG_CARD)
        a1_row.pack(anchor=tk.W, pady=(2, 4))
        self.a1_result_lbl = tk.Label(a1_row, text="--", fg=SECONDARY_TEXT, bg=BG_CARD, font=("Consolas", 12, "bold"))
        self.a1_result_lbl.pack(side=tk.LEFT)
        self.a1_copy_btn = create_copy_button(a1_row, lambda: self.copy_to_clipboard(self.a1_result_lbl.cget("text"), self.a1_copy_btn))
        
        tk.Label(result_card, text="Entry Point", fg=TEXT_LIGHT, bg=BG_CARD, font=("Segoe UI", 9, "bold")).pack(anchor=tk.W, pady=(2, 0))
        entry_row = tk.Frame(result_card, bg=BG_CARD)
        entry_row.pack(anchor=tk.W, pady=(2, 4))
        self.entry_result_lbl = tk.Label(entry_row, text="--", fg=SECONDARY_TEXT, bg=BG_CARD, font=("Consolas", 12, "bold"))
        self.entry_result_lbl.pack(side=tk.LEFT)
        self.entry_copy_btn = create_copy_button(entry_row, lambda: self.copy_to_clipboard(self.entry_result_lbl.cget("text"), self.entry_copy_btn))
        
        sep = tk.Frame(result_card, bg=BORDER_COLOR, height=1)
        sep.pack(fill=tk.X, pady=(8, 8))
        
        tk.Label(result_card, text="Generate a custom Code Note", fg=TEXT_LIGHT, bg=BG_CARD, font=("Segoe UI", 9, "bold")).pack(anchor=tk.W)
        ra_row = tk.Frame(result_card, bg=BG_CARD)
        ra_row.pack(fill=tk.X, pady=(4, 2))
        
        self.note_type_var = tk.StringVar(value="")
        self.note_dropdown = ttk.Combobox(
            ra_row, 
            textvariable=self.note_type_var, 
            values=["Start of dynamic memory", "Main function entrypoint"], 
            state="readonly", 
            width=26,
            font=("Segoe UI", 9)
        )
        self.note_dropdown.pack(side=tk.LEFT)
        
        self.ra_copy_btn = create_copy_button(ra_row, self.copy_ra_note, text="Copy Note", font_size=8, extra_padx=10, extra_pady=2, bold=True)
        
        self.profile_lbl = tk.Label(result_card, text="Profile: Waiting to scan...", fg=SECONDARY_TEXT, bg=BG_CARD, font=("Segoe UI", 9))
        self.profile_lbl.pack(anchor=tk.W, pady=(8, 0))
        
        log_outer = ttk.Frame(root, padding=(16, 0, 16, 12))
        log_outer.pack(fill=tk.BOTH, expand=True)
        
        log_frame = tk.Frame(log_outer, bg=CONSOLE_BG, highlightbackground=BORDER_COLOR, highlightthickness=1)
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.text_area = scrolledtext.ScrolledText(
            log_frame, 
            wrap=tk.WORD, 
            bg=CONSOLE_BG, 
            fg=TEXT_LIGHT, 
            insertbackground=TEXT_LIGHT, 
            font=("Consolas", 9),
            padx=8,
            pady=8,
            borderwidth=0,
            highlightthickness=0,
            height=3
        )
        self.text_area.pack(fill=tk.BOTH, expand=True)
        
        self.text_area.tag_config("info", foreground="#38bdf8")
        self.text_area.tag_config("plus", foreground="#009688")
        self.text_area.tag_config("success", foreground="#4caf50")
        self.text_area.tag_config("warning", foreground="#ffb74d")
        self.text_area.tag_config("error", foreground="#ef4444")
        self.text_area.tag_config("normal", foreground=TEXT_LIGHT)
        
        self.log("[INFO] Ready. Click 'Scan Memory' to connect to PCSX2 (127.0.0.1:28011).")
        self.text_area.config(state=tk.DISABLED)
        
    def copy_to_clipboard(self, val, btn):
        if val and not val.startswith("--") and not val.startswith("Scanning") and not val.startswith("Not Found") and not val.startswith("Connection Error"):
            self.root.clipboard_clear()
            self.root.clipboard_append(val)
            btn.config(text="Copied!")
            self.root.after(1500, lambda: btn.config(text="Copy", fg=TEXT_LIGHT))

    def copy_ra_note(self):
        note_type = self.note_type_var.get()
        if not note_type:
            note_type = "Start of Dynamic Memory"
            
        if note_type == "Start of Dynamic Memory":
            label_text = "start of dynamic memory"
        else:
            label_text = "main function entrypoint"
            
        centered_label = label_text.center(36, "\u00A0")
        box_str = f"╔════════════════════════════════════╗\n║{centered_label}║\n╚════════════════════════════════════╝"
        
        self.root.clipboard_clear()
        self.root.clipboard_append(box_str)
        
        original_text = self.ra_copy_btn.cget("text")
        self.ra_copy_btn.config(text="Copied!")
        self.root.after(1500, lambda: self.ra_copy_btn.config(text=original_text, fg=TEXT_LIGHT))

    def log(self, message):
        self.text_area.config(state=tk.NORMAL)
        
        if message.startswith("[INFO]"):
            self.text_area.insert(tk.END, "[INFO]", "info")
            self.text_area.insert(tk.END, message[6:] + "\n", "normal")
        elif message.startswith("[+]"):
            self.text_area.insert(tk.END, "[+]", "plus")
            self.text_area.insert(tk.END, message[3:] + "\n", "normal")
        elif message.startswith("[SUCCESS]"):
            self.text_area.insert(tk.END, "[SUCCESS]", "success")
            self.text_area.insert(tk.END, message[9:] + "\n", "normal")
        elif message.startswith("[!]"):
            self.text_area.insert(tk.END, "[!]", "warning")
            self.text_area.insert(tk.END, message[3:] + "\n", "normal")
        elif message.startswith("[ERROR]"):
            self.text_area.insert(tk.END, "[ERROR]", "error")
            self.text_area.insert(tk.END, message[7:] + "\n", "normal")
        else:
            self.text_area.insert(tk.END, message + "\n", "normal")
            
        self.text_area.see(tk.END)
        self.text_area.config(state=tk.DISABLED)
        
    def start_analysis_thread(self):
        self.mem_copy_btn.pack_forget()
        self.a0_copy_btn.pack_forget()
        self.a1_copy_btn.pack_forget()
        self.entry_copy_btn.pack_forget()
        self.ra_copy_btn.pack_forget()

        self.run_btn.config(state=tk.DISABLED)
        self.status_lbl.config(text="● Status: Scanning...", fg="#ffb74d")
        self.mem_result_lbl.config(text="Scanning...", fg=SECONDARY_TEXT)
        self.a0_result_lbl.config(text="Scanning...", fg=SECONDARY_TEXT)
        self.a1_result_lbl.config(text="Scanning...", fg=SECONDARY_TEXT)
        self.entry_result_lbl.config(text="Scanning...", fg=SECONDARY_TEXT)
        self.profile_lbl.config(text="Analyzing startup blocks...")
        threading.Thread(target=self.run_analysis, daemon=True).start()
        
    def run_analysis(self):
        try:
            found_base, found_a0, found_a1, found_entry, profile_type, sc1, sc2 = perform_scan(self.log)
            
            if found_base is not None:
                res_str = f"0x{found_base:08X}"
                a0_str = f"0x{found_a0:08X}" if found_a0 is not None else "N/A"
                a1_str = f"0x{found_a1:08X}" if found_a1 is not None else "N/A"
                entry_str = f"0x{found_entry:08X}" if found_entry is not None else "N/A"
                
                self.mem_result_lbl.config(text=res_str, fg=SUCCESS_COLOR)
                self.a0_result_lbl.config(text=a0_str, fg=TEXT_LIGHT)
                self.a1_result_lbl.config(text=a1_str, fg=TEXT_LIGHT)
                self.entry_result_lbl.config(text=entry_str, fg=ACCENT_BLUE)
                self.profile_lbl.config(text=f"Profile Detected: {profile_type}", fg=SECONDARY_TEXT)
                
                self.mem_copy_btn.pack(side=tk.LEFT, padx=(8, 0))
                self.a0_copy_btn.pack(side=tk.LEFT, padx=(8, 0))
                self.a1_copy_btn.pack(side=tk.LEFT, padx=(8, 0))
                self.entry_copy_btn.pack(side=tk.LEFT, padx=(8, 0))
                self.ra_copy_btn.pack(side=tk.LEFT, padx=(10, 0))
                
                self.log(f"[SUCCESS] Base: {res_str} | a0: {a0_str} | a1: {a1_str} | Entry: {entry_str} ({profile_type})")
                self.status_lbl.config(text="● Status: Complete", fg="#4caf50")
            else:
                self.mem_result_lbl.config(text="Not Found", fg=SECONDARY_TEXT)
                self.a0_result_lbl.config(text="Not Found", fg=SECONDARY_TEXT)
                self.a1_result_lbl.config(text="Not Found", fg=SECONDARY_TEXT)
                self.entry_result_lbl.config(text="Not Found", fg=SECONDARY_TEXT)
                self.profile_lbl.config(text="Could not match standard or custom signatures.", fg=SECONDARY_TEXT)
                self.log("[!] Scan finished, but no valid base address was identified.")
                self.status_lbl.config(text="● Status: Finished (No match)", fg=SECONDARY_TEXT)

        except Exception as e:
            self.mem_result_lbl.config(text="Connection Error", fg=SECONDARY_TEXT)
            self.a0_result_lbl.config(text="Connection Error", fg=SECONDARY_TEXT)
            self.a1_result_lbl.config(text="Connection Error", fg=SECONDARY_TEXT)
            self.entry_result_lbl.config(text="Connection Error", fg=SECONDARY_TEXT)
            self.profile_lbl.config(text="Check if PCSX2 and PINE are running.", fg=SECONDARY_TEXT)
            self.log(f"[ERROR] {e}")
            self.status_lbl.config(text="● Status: Error", fg="#ef4444")
            messagebox.showerror("Connection Error", f"Could not connect to PCSX2.\n\nDetails: {e}")
        finally:
            self.run_btn.config(state=tk.NORMAL)

if __name__ == "__main__":
    root = tk.Tk()
    app = PS2AnalyzerApp(root)
    root.mainloop()