import tkinter as tk
from tkinter import ttk, font as tkfont

from password_analyzer import STRENGTH_COLORS, analyze_password


class PasswordStrengthApp:
    BG = "#0f1419"
    CARD = "#1a222c"
    CARD_ALT = "#151b24"
    ACCENT = "#14b8a6"
    ACCENT_DIM = "#0d9488"
    ACCENT_GLOW = "#2dd4bf"
    TEXT = "#f1f5f9"
    MUTED = "#94a3b8"
    INPUT_BG = "#0a0e13"
    INPUT_BORDER = "#334155"
    PASS_COLOR = "#34d399"
    FAIL_COLOR = "#f87171"
    DIVIDER = "#2d3748"

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Password Strength Analyzer")
        self.root.geometry("640x760")
        self.root.minsize(540, 620)
        self.root.configure(bg=self.BG)

        self._show_password = tk.BooleanVar(value=False)
        self._build_ui()
        self._analyze()

    def _make_card(self, parent: tk.Widget, accent: str | None = None, **pack_kw) -> tk.Frame:
        outer = tk.Frame(parent, bg=self.BG)
        outer.pack(fill=tk.X, padx=24, **pack_kw)

        if accent:
            tk.Frame(outer, bg=accent, width=4).pack(side=tk.LEFT, fill=tk.Y)

        card = tk.Frame(outer, bg=self.CARD, padx=20, pady=16)
        card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        return card

    def _build_ui(self) -> None:
        title_font = tkfont.Font(family="Segoe UI", size=24, weight="bold")
        subtitle_font = tkfont.Font(family="Segoe UI", size=10)
        body_font = tkfont.Font(family="Segoe UI", size=10)
        section_font = tkfont.Font(family="Segoe UI", size=12, weight="bold")
        mono_font = tkfont.Font(family="Consolas", size=12)

        # Header
        header = tk.Frame(self.root, bg=self.BG)
        header.pack(fill=tk.X, padx=24, pady=(24, 8))

        title_row = tk.Frame(header, bg=self.BG)
        title_row.pack(anchor=tk.W)

        tk.Label(
            title_row,
            text="🔐",
            font=tkfont.Font(family="Segoe UI Emoji", size=22),
            fg=self.ACCENT,
            bg=self.BG,
        ).pack(side=tk.LEFT, padx=(0, 10))

        title_block = tk.Frame(title_row, bg=self.BG)
        title_block.pack(side=tk.LEFT)

        tk.Label(
            title_block,
            text="Password Strength Analyzer",
            font=title_font,
            fg=self.TEXT,
            bg=self.BG,
        ).pack(anchor=tk.W)

        tk.Label(
            title_block,
            text="Evaluate your password against security best practices",
            font=subtitle_font,
            fg=self.MUTED,
            bg=self.BG,
        ).pack(anchor=tk.W, pady=(4, 0))

        tk.Frame(header, bg=self.ACCENT, height=2).pack(fill=tk.X, pady=(16, 0))

        # Password input card
        input_card = self._make_card(self.root, accent=self.ACCENT, pady=(16, 10))

        tk.Label(
            input_card,
            text="Enter Password",
            font=section_font,
            fg=self.TEXT,
            bg=self.CARD,
        ).pack(anchor=tk.W)

        input_wrap = tk.Frame(input_card, bg=self.INPUT_BORDER, padx=1, pady=1)
        input_wrap.pack(fill=tk.X, pady=(10, 0))

        input_row = tk.Frame(input_wrap, bg=self.INPUT_BG)
        input_row.pack(fill=tk.X)

        self.password_entry = tk.Entry(
            input_row,
            font=mono_font,
            bg=self.INPUT_BG,
            fg=self.TEXT,
            insertbackground=self.ACCENT_GLOW,
            relief=tk.FLAT,
            show="•",
            highlightthickness=0,
        )
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=10, padx=(12, 8))
        self.password_entry.bind("<KeyRelease>", lambda _: self._analyze())
        self.password_entry.bind("<FocusIn>", lambda _: input_wrap.config(bg=self.ACCENT))
        self.password_entry.bind("<FocusOut>", lambda _: input_wrap.config(bg=self.INPUT_BORDER))

        self.toggle_btn = tk.Button(
            input_row,
            text="Show",
            font=body_font,
            bg=self.ACCENT_DIM,
            fg=self.TEXT,
            activebackground=self.ACCENT,
            activeforeground=self.TEXT,
            relief=tk.FLAT,
            padx=14,
            pady=6,
            cursor="hand2",
            borderwidth=0,
            command=self._toggle_visibility,
        )
        self.toggle_btn.pack(side=tk.RIGHT, padx=8, pady=6)

        # Strength meter card
        meter_card = self._make_card(self.root, accent=self.ACCENT_GLOW, pady=(0, 10))

        score_row = tk.Frame(meter_card, bg=self.CARD)
        score_row.pack(fill=tk.X)

        self.strength_label = tk.Label(
            score_row,
            text="Strength: —",
            font=tkfont.Font(family="Segoe UI", size=15, weight="bold"),
            fg=self.MUTED,
            bg=self.CARD,
        )
        self.strength_label.pack(side=tk.LEFT)

        self.score_badge = tk.Label(
            score_row,
            text="0 / 100",
            font=tkfont.Font(family="Consolas", size=11, weight="bold"),
            fg=self.ACCENT_GLOW,
            bg=self.CARD_ALT,
            padx=10,
            pady=4,
        )
        self.score_badge.pack(side=tk.RIGHT)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Strength.Horizontal.TProgressbar",
            troughcolor=self.INPUT_BG,
            background=self.FAIL_COLOR,
            thickness=18,
            borderwidth=0,
            lightcolor=self.ACCENT,
            darkcolor=self.ACCENT,
        )

        self.progress = ttk.Progressbar(
            meter_card,
            style="Strength.Horizontal.TProgressbar",
            orient=tk.HORIZONTAL,
            length=400,
            mode="determinate",
            maximum=100,
        )
        self.progress.pack(fill=tk.X, pady=(14, 0))

        self.length_label = tk.Label(
            meter_card,
            text="Length: 0 characters",
            font=body_font,
            fg=self.MUTED,
            bg=self.CARD,
        )
        self.length_label.pack(anchor=tk.W, pady=(10, 0))

        # Criteria card
        criteria_outer = tk.Frame(self.root, bg=self.BG)
        criteria_outer.pack(fill=tk.BOTH, expand=True, padx=24, pady=(0, 10))

        tk.Frame(criteria_outer, bg=self.PASS_COLOR, width=4).pack(side=tk.LEFT, fill=tk.Y)
        criteria_card = tk.Frame(criteria_outer, bg=self.CARD, padx=20, pady=16)
        criteria_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(
            criteria_card,
            text="✓  Security Criteria",
            font=section_font,
            fg=self.TEXT,
            bg=self.CARD,
        ).pack(anchor=tk.W)

        self.criteria_frame = tk.Frame(criteria_card, bg=self.CARD)
        self.criteria_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        # Recommendations card
        rec_outer = tk.Frame(self.root, bg=self.BG)
        rec_outer.pack(fill=tk.BOTH, expand=True, padx=24, pady=(0, 24))

        tk.Frame(rec_outer, bg="#fbbf24", width=4).pack(side=tk.LEFT, fill=tk.Y)
        rec_card = tk.Frame(rec_outer, bg=self.CARD, padx=20, pady=16)
        rec_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tk.Label(
            rec_card,
            text="💡  Recommendations",
            font=section_font,
            fg=self.TEXT,
            bg=self.CARD,
        ).pack(anchor=tk.W)

        rec_container = tk.Frame(rec_card, bg=self.INPUT_BG, padx=1, pady=1)
        rec_container.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        inner_rec = tk.Frame(rec_container, bg=self.INPUT_BG)
        inner_rec.pack(fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(inner_rec, bg=self.CARD_ALT, troughcolor=self.INPUT_BG)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.rec_text = tk.Text(
            inner_rec,
            font=body_font,
            bg=self.INPUT_BG,
            fg=self.TEXT,
            relief=tk.FLAT,
            wrap=tk.WORD,
            height=5,
            padx=12,
            pady=12,
            state=tk.DISABLED,
            yscrollcommand=scrollbar.set,
            highlightthickness=0,
        )
        self.rec_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.rec_text.yview)

        self.rec_text.tag_configure("accent", foreground=self.ACCENT_GLOW)

    def _toggle_visibility(self) -> None:
        self._show_password.set(not self._show_password.get())
        if self._show_password.get():
            self.password_entry.config(show="")
            self.toggle_btn.config(text="Hide", bg=self.ACCENT)
        else:
            self.password_entry.config(show="•")
            self.toggle_btn.config(text="Show", bg=self.ACCENT_DIM)

    def _analyze(self) -> None:
        password = self.password_entry.get()
        result = analyze_password(password)

        color = STRENGTH_COLORS[result.strength]
        self.strength_label.config(
            text=f"Strength: {result.strength.value}",
            fg=color,
        )
        self.score_badge.config(text=f"{result.score} / {result.max_score}", fg=color)
        self.length_label.config(text=f"Length: {result.length} characters")

        self.progress["value"] = result.score
        style = ttk.Style()
        style.configure("Strength.Horizontal.TProgressbar", background=color)

        self._render_criteria(result)
        self._render_recommendations(result)

    def _render_criteria(self, result) -> None:
        for widget in self.criteria_frame.winfo_children():
            widget.destroy()

        body_font = tkfont.Font(family="Segoe UI", size=10)

        for i, criterion in enumerate(result.criteria):
            row_bg = self.CARD_ALT if i % 2 == 0 else self.CARD
            row = tk.Frame(self.criteria_frame, bg=row_bg, padx=8, pady=5)
            row.pack(fill=tk.X, pady=1)

            passed = criterion.passed
            icon = "✓" if passed else "✗"
            color = self.PASS_COLOR if passed else self.FAIL_COLOR
            badge_bg = "#064e3b" if passed else "#450a0a"

            badge = tk.Label(
                row,
                text=icon,
                font=tkfont.Font(family="Segoe UI", size=9, weight="bold"),
                fg=color,
                bg=badge_bg,
                width=2,
                padx=4,
                pady=1,
            )
            badge.pack(side=tk.LEFT)

            tk.Label(
                row,
                text=criterion.name,
                font=body_font,
                fg=self.TEXT,
                bg=row_bg,
            ).pack(side=tk.LEFT, padx=(8, 0))

            tk.Label(
                row,
                text=criterion.message,
                font=body_font,
                fg=self.MUTED,
                bg=row_bg,
            ).pack(side=tk.RIGHT)

    def _render_recommendations(self, result) -> None:
        self.rec_text.config(state=tk.NORMAL)
        self.rec_text.delete("1.0", tk.END)

        if not result.recommendations:
            self.rec_text.insert(tk.END, "✓  No recommendations — your password looks good!")
            self.rec_text.tag_add("accent", "1.0", "1.2")
        else:
            for i, rec in enumerate(result.recommendations, 1):
                self.rec_text.insert(tk.END, f"  {i}. ", "accent")
                self.rec_text.insert(tk.END, f"{rec}\n")

        self.rec_text.config(state=tk.DISABLED)


def main() -> None:
    root = tk.Tk()
    PasswordStrengthApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
