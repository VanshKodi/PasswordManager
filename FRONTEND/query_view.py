# FRONTEND/query_view.py

import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

from BACKEND import database

class QueryView(ttk.Toplevel):
    """A modal window for executing raw SQL queries."""

    def __init__(self, master):
        super().__init__(master)
        self.title("Database Query Panel")
        self.geometry("800x600")
        self.transient(master)
        self.grab_set()

        self._create_widgets()

        self.master.wait_window(self)

    def _create_widgets(self):
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill=BOTH, expand=True)

        # --- Top frame for query input ---
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=X, pady=(0, 10))

        ttk.Label(input_frame, text="Enter SQL Query:", font="-weight bold").pack(anchor=W)
        self.query_text = ScrolledText(input_frame, height=10, wrap=tk.WORD, relief=tk.SOLID, borderwidth=1)
        self.query_text.pack(fill=X, expand=True, pady=5)
        
        ttk.Label(input_frame, 
                  text="⚠️ WARNING: Direct queries can permanently delete or corrupt data.",
                  bootstyle="danger").pack(anchor=W, pady=(0, 5))

        button_frame = ttk.Frame(input_frame)
        button_frame.pack(fill=X)
        ttk.Button(button_frame, text="Execute Query", command=self._run_query, bootstyle=SUCCESS).pack(side=LEFT)
        ttk.Button(button_frame, text="Clear", command=lambda: self.query_text.delete('1.0', tk.END)).pack(side=LEFT, padx=10)

        # --- Bottom frame for results ---
        results_frame = ttk.Labelframe(main_frame, text="Results", padding=10)
        results_frame.pack(fill=BOTH, expand=True)

        self.status_label = ttk.Label(results_frame, text="Ready.", bootstyle="secondary")
        self.status_label.pack(anchor=W, pady=(0, 5))

        tree_container = ttk.Frame(results_frame)
        tree_container.pack(fill=BOTH, expand=True)
        
        self.results_tree = ttk.Treeview(tree_container, show="headings", selectmode="browse")
        
        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=self.results_tree.yview)
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        vsb.pack(side=RIGHT, fill=Y)
        hsb.pack(side=BOTTOM, fill=X)
        self.results_tree.pack(fill=BOTH, expand=True)
        
    def _run_query(self):
        """Executes the query and displays the results."""
        # Clear previous results first
        self.results_tree.delete(*self.results_tree.get_children())
        self.results_tree["columns"] = []
        self.status_label.config(text="")

        query_string = self.query_text.get('1.0', tk.END)
        columns, rows, message, error = database.execute_raw_query(query_string)

        if error:
            self.status_label.config(text=error, bootstyle="danger")
            return
        
        self.status_label.config(text=message, bootstyle="success")

        if columns is not None and rows is not None:
            self.results_tree["columns"] = columns
            for col in columns:
                self.results_tree.heading(col, text=col)
                self.results_tree.column(col, width=120, anchor=W)
            
            for row in rows:
                self.results_tree.insert("", END, values=list(row))