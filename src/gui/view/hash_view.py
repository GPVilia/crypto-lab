"""
View para calcular hashes de ficheiros e texto.
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

from crypto.hashing import hash_data, hash_file, hmac_data
from gui.components.file_picker import FilePicker


class HashView(ctk.CTkFrame):
    """View para calcular hashes."""
    
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        
        # Configuração da grid
        self.grid_columnconfigure(0, weight=1)
        
        # Título
        title = ctk.CTkLabel(
            self, 
            text="🔐 Hashing", 
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")
        
        # Descrição
        desc = ctk.CTkLabel(
            self, 
            text="Calcule hashes criptográficos de ficheiros ou texto",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        desc.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="w")
        
        # Frame principal
        main_frame = ctk.CTkFrame(self)
        main_frame.grid(row=2, column=0, padx=20, pady=10, sticky="nsew")
        main_frame.grid_columnconfigure(0, weight=1)
        
        # Modo (Ficheiro ou Texto)
        mode_label = ctk.CTkLabel(main_frame, text="Modo:", anchor="w")
        mode_label.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="w")
        
        self.mode_var = ctk.StringVar(value="Ficheiro")
        mode_menu = ctk.CTkOptionMenu(
            main_frame,
            values=["Ficheiro", "Texto", "HMAC"],
            variable=self.mode_var,
            width=200,
            command=self._on_mode_change
        )
        mode_menu.grid(row=1, column=0, padx=10, pady=(0, 15), sticky="w")
        
        # Algoritmo
        algo_label = ctk.CTkLabel(main_frame, text="Algoritmo:", anchor="w")
        algo_label.grid(row=2, column=0, padx=10, pady=(10, 5), sticky="w")
        
        self.algorithm_var = ctk.StringVar(value="sha256")
        algo_menu = ctk.CTkOptionMenu(
            main_frame,
            values=["md5", "sha1", "sha256", "sha512", "sha3_256", "sha3_512"],
            variable=self.algorithm_var,
            width=200
        )
        algo_menu.grid(row=3, column=0, padx=10, pady=(0, 15), sticky="w")
        
        # Ficheiro de entrada (visível apenas em modo Ficheiro)
        self.file_picker = FilePicker(
            main_frame,
            label="Ficheiro:",
            mode="open",
            file_types=[("Todos os ficheiros", "*.*")]
        )
        self.file_picker.grid(row=4, column=0, padx=10, pady=10, sticky="ew")
        
        # Texto de entrada (visível apenas em modo Texto ou HMAC)
        self.text_label = ctk.CTkLabel(main_frame, text="Texto:", anchor="w")
        self.text_label.grid(row=5, column=0, padx=10, pady=(10, 5), sticky="w")
        self.text_label.grid_remove()
        
        self.text_input = ctk.CTkTextbox(main_frame, height=100)
        self.text_input.grid(row=6, column=0, padx=10, pady=(0, 15), sticky="ew")
        self.text_input.grid_remove()
        
        # Chave HMAC (visível apenas em modo HMAC)
        self.hmac_key_label = ctk.CTkLabel(main_frame, text="Chave HMAC (hex):", anchor="w")
        self.hmac_key_label.grid(row=7, column=0, padx=10, pady=(10, 5), sticky="w")
        self.hmac_key_label.grid_remove()
        
        self.hmac_key_entry = ctk.CTkEntry(main_frame, placeholder_text="Digite a chave em hexadecimal ou deixe vazio para gerar")
        self.hmac_key_entry.grid(row=8, column=0, padx=10, pady=(0, 15), sticky="ew")
        self.hmac_key_entry.grid_remove()
        
        # Botões
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.grid(row=9, column=0, padx=10, pady=15, sticky="ew")
        button_frame.grid_columnconfigure(0, weight=1)
        
        self.hash_button = ctk.CTkButton(
            button_frame,
            text="🔐 Calcular Hash",
            command=self._calculate_hash,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.hash_button.grid(row=0, column=0, padx=5, sticky="ew")
        
        self.clear_button = ctk.CTkButton(
            button_frame,
            text="Limpar",
            command=self._clear,
            height=40,
            fg_color="gray",
            hover_color="darkgray"
        )
        self.clear_button.grid(row=0, column=1, padx=5, sticky="ew")
        
        # Resultado
        result_label = ctk.CTkLabel(main_frame, text="Resultado:", anchor="w", font=ctk.CTkFont(weight="bold"))
        result_label.grid(row=10, column=0, padx=10, pady=(15, 5), sticky="w")
        
        self.result_text = ctk.CTkTextbox(main_frame, height=80, state="disabled")
        self.result_text.grid(row=11, column=0, padx=10, pady=(0, 10), sticky="ew")
        
        # Botão copiar
        self.copy_button = ctk.CTkButton(
            main_frame,
            text="📋 Copiar",
            command=self._copy_result,
            height=30,
            width=100,
            fg_color="darkblue",
            hover_color="blue"
        )
        self.copy_button.grid(row=12, column=0, padx=10, pady=(0, 10), sticky="e")
    
    def _on_mode_change(self, choice):
        """Altera a visibilidade dos campos conforme o modo selecionado."""
        if choice == "Ficheiro":
            self.file_picker.grid()
            self.text_label.grid_remove()
            self.text_input.grid_remove()
            self.hmac_key_label.grid_remove()
            self.hmac_key_entry.grid_remove()
        elif choice == "Texto":
            self.file_picker.grid_remove()
            self.text_label.grid()
            self.text_input.grid()
            self.hmac_key_label.grid_remove()
            self.hmac_key_entry.grid_remove()
        else:  # HMAC
            self.file_picker.grid_remove()
            self.text_label.grid()
            self.text_input.grid()
            self.hmac_key_label.grid()
            self.hmac_key_entry.grid()
    
    def _calculate_hash(self):
        """Calcula o hash."""
        mode = self.mode_var.get()
        algorithm = self.algorithm_var.get()
        
        try:
            if mode == "Ficheiro":
                file_path = self.file_picker.get_path()
                if not file_path:
                    messagebox.showerror("Erro", "Por favor, selecione um ficheiro.")
                    return
                if not os.path.exists(file_path):
                    messagebox.showerror("Erro", "O ficheiro não existe.")
                    return
                
                result = hash_file(file_path, algorithm)
                self._show_result(f"{algorithm.upper()}: {result}")
                
            elif mode == "Texto":
                text = self.text_input.get("1.0", "end-1c")
                if not text:
                    messagebox.showerror("Erro", "Por favor, digite algum texto.")
                    return
                
                result = hash_data(text.encode('utf-8'), algorithm)
                self._show_result(f"{algorithm.upper()}: {result.hex()}")
                
            else:  # HMAC
                text = self.text_input.get("1.0", "end-1c")
                if not text:
                    messagebox.showerror("Erro", "Por favor, digite algum texto.")
                    return
                
                key_hex = self.hmac_key_entry.get()
                if key_hex:
                    try:
                        key = bytes.fromhex(key_hex)
                    except ValueError:
                        messagebox.showerror("Erro", "Chave inválida. Use formato hexadecimal.")
                        return
                else:
                    # Gera chave aleatória
                    import os as os_module
                    key = os_module.urandom(32)
                    self.hmac_key_entry.delete(0, "end")
                    self.hmac_key_entry.insert(0, key.hex())
                
                result = hmac_data(key, text.encode('utf-8'), algorithm)
                self._show_result(f"HMAC-{algorithm.upper()}: {result.hex()}\n\nChave usada: {key.hex()}")
                
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao calcular hash:\n{str(e)}")
    
    def _show_result(self, text):
        """Mostra o resultado no textbox."""
        self.result_text.configure(state="normal")
        self.result_text.delete("1.0", "end")
        self.result_text.insert("1.0", text)
        self.result_text.configure(state="disabled")
    
    def _copy_result(self):
        """Copia o resultado para a área de transferência."""
        result = self.result_text.get("1.0", "end-1c")
        if result:
            self.clipboard_clear()
            self.clipboard_append(result)
            messagebox.showinfo("Copiado", "Resultado copiado para a área de transferência!")
    
    def _clear(self):
        """Limpa todos os campos."""
        self.file_picker.clear()
        self.text_input.delete("1.0", "end")
        self.hmac_key_entry.delete(0, "end")
        self.result_text.configure(state="normal")
        self.result_text.delete("1.0", "end")
        self.result_text.configure(state="disabled")
        self.mode_var.set("Ficheiro")
        self.algorithm_var.set("sha256")
        self._on_mode_change("Ficheiro")
