import tkinter as tk

BG_DARK = "#202020"
BG_HEADER = "#2d2d2d"
BG_CARD = "#262626"
BORDER_COLOR = "#3c3c3c"
TEXT_LIGHT = "#e0e0e0"
SECONDARY_TEXT = "#9e9e9e"
CONSOLE_BG = "#1a1a1a"

BTN_BG = "#009688"
BTN_HOVER = "#00bfa5"
ACCENT_BLUE = "#2196f3"
SUCCESS_COLOR = "#4caf50"
WARNING_YELLOW = "#ffb74d"

def apply_styles(style):
    style.theme_use("clam")
    
    style.configure(".", background=BG_DARK, foreground=TEXT_LIGHT, font=("Segoe UI", 9))
    style.configure("TFrame", background=BG_DARK)
    style.configure("Card.TFrame", background=BG_CARD)
    style.configure("TLabel", background=BG_DARK, foreground=TEXT_LIGHT)
    style.configure("Card.TLabel", background=BG_CARD, foreground=SECONDARY_TEXT)
    
    style.configure(
        "Accent.TButton", 
        font=("Segoe UI", 9, "bold"), 
        foreground="#ffffff", 
        background=BTN_BG, 
        borderwidth=0,
        focuscolor="none",
        padding=(12, 5)
    )
    style.map("Accent.TButton", background=[("active", BTN_HOVER), ("pressed", "#00796b")])
    
    style.configure(
        "TCombobox", 
        fieldbackground="#1a1a1a", 
        background="#333333", 
        foreground=TEXT_LIGHT, 
        darkcolor="#1a1a1a", 
        lightcolor="#1a1a1a", 
        bordercolor=BORDER_COLOR, 
        arrowcolor=TEXT_LIGHT,
        font=("Segoe UI", 9)
    )
    style.map("TCombobox", fieldbackground=[("readonly", "#1a1a1a")])

def create_copy_button(parent, command, text="Copy", width=6, font_size=8, extra_padx=4, extra_pady=2, bold=False):
    font_weight = "bold" if bold else "normal"
    btn = tk.Button(
        parent, 
        text=text, 
        bg="#333333", 
        fg=TEXT_LIGHT, 
        activebackground="#424242", 
        activeforeground="#ffffff", 
        relief=tk.SOLID, 
        bd=1,
        font=("Segoe UI", font_size, font_weight), 
        width=width, 
        padx=extra_padx,
        pady=extra_pady,
        cursor="hand2", 
        command=command,
        highlightthickness=0
    )
    return btn