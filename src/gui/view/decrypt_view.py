"""
View para desencriptação de ficheiros (AES-GCM e 3DES-CBC).
"""
import customtkinter as ctk
from tkinter import messagebox
import os
import sys

# Adicionar o diretório src ao path para importar os módulos crypto
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
src_path = os.path.join(project_root, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from crypto.symmetric import decrypt_file_aes, decrypt_file_3des
from gui.components.file_picker import FilePicker


class DecryptView(ctk.CTkFrame):
    """View para desencriptar ficheiros."""
    
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        
        # Configuração da grid
        self.grid_columnconfigure(0, weight=1)
        
        # Título
        title = ctk.CTkLabel(
            self, 
            text="🔓 Desencriptação de Ficheiros", 
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")
        
        # Descrição
        desc = ctk.CTkLabel(
            self, 
            text="Desencripte ficheiros usando AES-256-GCM ou 3DES-CBC",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        desc.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="w")
        
        # Frame principal
        main_frame = ctk.CTkFrame(self)
        main_frame.grid(row=2, column=0, padx=20, pady=10, sticky="nsew")
        main_frame.grid_columnconfigure(0, weight=1)
        
        # Seleção de algoritmo
        algo_label = ctk.CTkLabel(main_frame, text="Algoritmo:", anchor="w")
        algo_label.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="w")
        
        self.algorithm_var = ctk.StringVar(value="AES-256-GCM")
        algo_menu = ctk.CTkOptionMenu(
            main_frame,
            values=["AES-256-GCM", "3DES-CBC"],
            variable=self.algorithm_var,
            width=200
        )
        algo_menu.grid(row=1, column=0, padx=10, pady=(0, 15), sticky="w")
        
        # Ficheiro de entrada (encriptado)
        self.input_picker = FilePicker(
            main_frame,
            label="Ficheiro Encriptado:",
            mode="open",
            file_types=[("Ficheiro encriptado", "*.enc"), ("Todos os ficheiros", "*.*")]
        )
        self.input_picker.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
        
        # Ficheiro de saída (desencriptado)
        self.output_picker = FilePicker(
            main_frame,
            label="Ficheiro de Saída:",
            mode="save",
            file_types=[("Todos os ficheiros", "*.*")]
        )
        self.output_picker.grid(row=3, column=0, padx=10, pady=10, sticky="ew")
        
        # Password
        pwd_label = ctk.CTkLabel(main_frame, text="Password:", anchor="w")
        pwd_label.grid(row=4, column=0, padx=10, pady=(10, 5), sticky="w")
        
        self.password_entry = ctk.CTkEntry(main_frame, show="*", placeholder_text="Digite a password")
        self.password_entry.grid(row=5, column=0, padx=10, pady=(0, 15), sticky="ew")
        
        # Botões
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.grid(row=6, column=0, padx=10, pady=15, sticky="ew")
        button_frame.grid_columnconfigure(0, weight=1)
        
        self.decrypt_button = ctk.CTkButton(
            button_frame,
            text="🔓 Desencriptar",
            command=self._decrypt,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.decrypt_button.grid(row=0, column=0, padx=5, sticky="ew")
        
        self.clear_button = ctk.CTkButton(
            button_frame,
            text="Limpar",
            command=self._clear,
            height=40,
            fg_color="gray",
            hover_color="darkgray"
        )
        self.clear_button.grid(row=0, column=1, padx=5, sticky="ew")
        
        # Status
        self.status_label = ctk.CTkLabel(
            main_frame, 
            text="", 
            font=ctk.CTkFont(size=12),
            text_color="green"
        )
        self.status_label.grid(row=7, column=0, padx=10, pady=(0, 10), sticky="w")
    
    def _decrypt(self):
        """Executa a desencriptação."""
        # Validações
        input_path = self.input_picker.get_path()
        output_path = self.output_picker.get_path()
        password = self.password_entry.get()
        algorithm = self.algorithm_var.get()
        
        if not input_path:
            messagebox.showerror("Erro", "Por favor, selecione o ficheiro encriptado.")
            return
        
        if not os.path.exists(input_path):
            messagebox.showerror("Erro", "O ficheiro encriptado não existe.")
            return
        
        if not output_path:
            messagebox.showerror("Erro", "Por favor, selecione o ficheiro de saída.")
            return
        
        if not password:
            messagebox.showerror("Erro", "Por favor, digite a password.")
            return
        
        try:
            self.status_label.configure(text="A desencriptar...", text_color="orange")
            self.update()
            
            # Desencriptar com o algoritmo selecionado
            if algorithm == "AES-256-GCM":
                decrypt_file_aes(input_path, output_path, password)
            else:  # 3DES-CBC
                decrypt_file_3des(input_path, output_path, password)
            
            self.status_label.configure(text="✅ Ficheiro desencriptado com sucesso!", text_color="green")
            messagebox.showinfo("Sucesso", f"Ficheiro desencriptado com {algorithm}!\nGuardado em: {output_path}")
            
        except Exception as e:
            self.status_label.configure(text="❌ Erro na desencriptação", text_color="red")
            messagebox.showerror("Erro", f"Erro ao desencriptar o ficheiro:\n{str(e)}\n\nVerifique se a password está correta e se o algoritmo corresponde ao usado na encriptação.")
    
    def _clear(self):
        """Limpa todos os campos."""
        self.input_picker.clear()
        self.output_picker.clear()
        self.password_entry.delete(0, "end")
        self.status_label.configure(text="")
        self.algorithm_var.set("AES-256-GCM")
