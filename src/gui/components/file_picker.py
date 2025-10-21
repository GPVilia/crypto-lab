"""
Componente de seleção de ficheiros para a interface gráfica.
"""
import customtkinter as ctk
from tkinter import filedialog
from typing import Callable, Optional


class FilePicker(ctk.CTkFrame):
    """Frame com campo de texto e botão para selecionar ficheiros."""
    
    def __init__(self, master, label: str, mode: str = "open", file_types: Optional[list] = None, 
                 on_file_selected: Optional[Callable[[str], None]] = None, **kwargs):
        """
        Inicializa o componente de seleção de ficheiros.
        
        Args:
            master: Widget pai.
            label (str): Texto do label.
            mode (str): 'open' para abrir, 'save' para guardar.
            file_types (list): Lista de tipos de ficheiro, ex: [("Todos", "*.*"), ("Texto", "*.txt")].
            on_file_selected (Callable): Callback chamado quando um ficheiro é selecionado.
        """
        super().__init__(master, **kwargs)
        
        self.mode = mode
        self.file_types = file_types or [("Todos os ficheiros", "*.*")]
        self.on_file_selected = on_file_selected
        
        # Label
        self.label = ctk.CTkLabel(self, text=label, anchor="w")
        self.label.grid(row=0, column=0, sticky="w", padx=5, pady=(5, 0))
        
        # Frame para o entry e botão
        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        self.input_frame.grid_columnconfigure(0, weight=1)
        
        # Entry para mostrar o caminho
        self.path_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Nenhum ficheiro selecionado")
        self.path_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        
        # Botão para abrir diálogo
        self.browse_button = ctk.CTkButton(
            self.input_frame, 
            text="Procurar...", 
            width=100,
            command=self._browse_file
        )
        self.browse_button.grid(row=0, column=1)
        
        self.grid_columnconfigure(0, weight=1)
    
    def _browse_file(self):
        """Abre o diálogo de seleção de ficheiro."""
        if self.mode == "open":
            filepath = filedialog.askopenfilename(filetypes=self.file_types)
        else:
            filepath = filedialog.asksaveasfilename(filetypes=self.file_types, defaultextension=self.file_types[0][1])
        
        if filepath:
            self.path_entry.delete(0, "end")
            self.path_entry.insert(0, filepath)
            
            if self.on_file_selected:
                self.on_file_selected(filepath)
    
    def get_path(self) -> str:
        """Retorna o caminho do ficheiro selecionado."""
        return self.path_entry.get()
    
    def set_path(self, path: str):
        """Define o caminho do ficheiro."""
        self.path_entry.delete(0, "end")
        self.path_entry.insert(0, path)
    
    def clear(self):
        """Limpa o campo de entrada."""
        self.path_entry.delete(0, "end")
