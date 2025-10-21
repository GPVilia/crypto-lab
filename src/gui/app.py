"""
Aplicação principal - Crypto Lab
Interface gráfica para criptografia simétrica, hashing e assinaturas digitais.
"""
import customtkinter as ctk
import os
import sys

# Adicionar o diretório src ao path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
src_path = os.path.join(project_root, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from gui.view.encrypt_view import EncryptView
from gui.view.decrypt_view import DecryptView
from gui.view.hash_view import HashView
from gui.view.sign_verify_view import SignVerifyView


class CryptoLabApp(ctk.CTk):
    """Aplicação principal do Crypto Lab."""
    
    def __init__(self):
        super().__init__()
        
        # Configuração da janela
        self.title("🔐 Crypto Lab")
        self.geometry("950x850")
        
        # Configurar tema (apenas escuro)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Configurar grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # Header
        self._create_header()
        
        # Tabview principal
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")
        
        # Adicionar tabs
        self.tabview.add("🔒 Encriptar")
        self.tabview.add("🔓 Desencriptar")
        self.tabview.add("🔐 Hashing")
        self.tabview.add("✍️ Assinaturas")
        
        # Configurar grid das tabs
        for tab_name in ["🔒 Encriptar", "🔓 Desencriptar", "🔐 Hashing", "✍️ Assinaturas"]:
            self.tabview.tab(tab_name).grid_columnconfigure(0, weight=1)
            self.tabview.tab(tab_name).grid_rowconfigure(0, weight=1)
        
        # Criar views
        self.encrypt_view = EncryptView(self.tabview.tab("🔒 Encriptar"))
        self.encrypt_view.grid(row=0, column=0, sticky="nsew")
        
        self.decrypt_view = DecryptView(self.tabview.tab("🔓 Desencriptar"))
        self.decrypt_view.grid(row=0, column=0, sticky="nsew")
        
        self.hash_view = HashView(self.tabview.tab("🔐 Hashing"))
        self.hash_view.grid(row=0, column=0, sticky="nsew")
        
        self.sign_view = SignVerifyView(self.tabview.tab("✍️ Assinaturas"))
        self.sign_view.grid(row=0, column=0, sticky="nsew")
        
        # Footer
        self._create_footer()
    
    def _create_header(self):
        """Cria o cabeçalho da aplicação."""
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=20, pady=20, sticky="ew")
        header_frame.grid_columnconfigure(1, weight=1)
        
        # Logo/Título
        title = ctk.CTkLabel(
            header_frame,
            text="🔐 Crypto Lab",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.grid(row=0, column=0, sticky="w")
        
        # Subtítulo
        subtitle = ctk.CTkLabel(
            header_frame,
            text="Laboratório de Criptografia",
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        subtitle.grid(row=1, column=0, sticky="w", pady=(0, 5))
    
    def _create_footer(self):
        """Cria o rodapé da aplicação."""
        footer_frame = ctk.CTkFrame(self, height=40, fg_color="transparent")
        footer_frame.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="ew")
        
        footer_text = ctk.CTkLabel(
            footer_frame,
            text="Crypto Lab © 2025 | Criptografia Simétrica, Hashing e Assinaturas Digitais",
            font=ctk.CTkFont(size=10),
            text_color="gray"
        )
        footer_text.pack()


def main():
    """Função principal para iniciar a aplicação."""
    app = CryptoLabApp()
    app.mainloop()


if __name__ == "__main__":
    main()
