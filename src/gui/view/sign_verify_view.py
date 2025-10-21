"""
View para assinaturas digitais RSA.
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

from crypto.asymmetric import generate_rsa_keypair
from crypto.signatures import sign_message_rsa, verify_signature_rsa
from crypto.utils import serialize_private_key, serialize_public_key, deserialize_private_key, deserialize_public_key, read_file_bytes, write_file_bytes
from gui.components.file_picker import FilePicker


class SignVerifyView(ctk.CTkFrame):
    """View para assinar e verificar assinaturas digitais."""
    
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        
        # Configuração da grid
        self.grid_columnconfigure(0, weight=1)
        
        # Título
        title = ctk.CTkLabel(
            self, 
            text="✍️ Assinaturas Digitais", 
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")
        
        # Descrição
        desc = ctk.CTkLabel(
            self, 
            text="Gere chaves RSA, assine ficheiros e verifique assinaturas",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        desc.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="w")
        
        # Tabview para separar as funcionalidades
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=2, column=0, padx=20, pady=10, sticky="nsew")
        
        # Tabs
        self.tabview.add("Gerar Chaves")
        self.tabview.add("Assinar")
        self.tabview.add("Verificar")
        
        # Configurar grid das tabs
        self.tabview.tab("Gerar Chaves").grid_columnconfigure(0, weight=1)
        self.tabview.tab("Assinar").grid_columnconfigure(0, weight=1)
        self.tabview.tab("Verificar").grid_columnconfigure(0, weight=1)
        
        self._setup_generate_keys_tab()
        self._setup_sign_tab()
        self._setup_verify_tab()
    
    def _setup_generate_keys_tab(self):
        """Configura o tab de geração de chaves."""
        tab = self.tabview.tab("Gerar Chaves")
        
        frame = ctk.CTkFrame(tab)
        frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        
        # Tamanho da chave
        size_label = ctk.CTkLabel(frame, text="Tamanho da Chave (bits):", anchor="w")
        size_label.grid(row=0, column=0, padx=10, pady=(10, 5), sticky="w")
        
        self.key_size_var = ctk.StringVar(value="2048")
        size_menu = ctk.CTkOptionMenu(
            frame,
            values=["1024", "2048", "3072", "4096"],
            variable=self.key_size_var,
            width=200
        )
        size_menu.grid(row=1, column=0, padx=10, pady=(0, 15), sticky="w")
        
        # Diretório para salvar
        self.save_dir_picker = FilePicker(
            frame,
            label="Pasta para Guardar as Chaves:",
            mode="open",
            file_types=[("Todos os ficheiros", "*.*")]
        )
        self.save_dir_picker.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
        
        # Nota
        note = ctk.CTkLabel(
            frame,
            text="Nota: As chaves serão guardadas como 'private_key.pem' e 'public_key.pem'",
            font=ctk.CTkFont(size=10),
            text_color="gray"
        )
        note.grid(row=3, column=0, padx=10, pady=5, sticky="w")
        
        # Botão gerar
        gen_button = ctk.CTkButton(
            frame,
            text="🔑 Gerar Par de Chaves RSA",
            command=self._generate_keys,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        gen_button.grid(row=4, column=0, padx=10, pady=15, sticky="ew")
        
        # Status
        self.gen_status = ctk.CTkLabel(frame, text="", font=ctk.CTkFont(size=12))
        self.gen_status.grid(row=5, column=0, padx=10, pady=(0, 10), sticky="w")
    
    def _setup_sign_tab(self):
        """Configura o tab de assinatura."""
        tab = self.tabview.tab("Assinar")
        
        frame = ctk.CTkFrame(tab)
        frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        
        # Chave privada
        self.sign_key_picker = FilePicker(
            frame,
            label="Chave Privada (PEM):",
            mode="open",
            file_types=[("Ficheiro PEM", "*.pem"), ("Todos os ficheiros", "*.*")]
        )
        self.sign_key_picker.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        
        # Ficheiro a assinar
        self.sign_file_picker = FilePicker(
            frame,
            label="Ficheiro a Assinar:",
            mode="open",
            file_types=[("Todos os ficheiros", "*.*")]
        )
        self.sign_file_picker.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        
        # Ficheiro de saída da assinatura
        self.sign_output_picker = FilePicker(
            frame,
            label="Guardar Assinatura Como:",
            mode="save",
            file_types=[("Ficheiro de assinatura", "*.sig"), ("Todos os ficheiros", "*.*")]
        )
        self.sign_output_picker.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
        
        # Botão assinar
        sign_button = ctk.CTkButton(
            frame,
            text="✍️ Assinar Ficheiro",
            command=self._sign_file,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        sign_button.grid(row=3, column=0, padx=10, pady=15, sticky="ew")
        
        # Status
        self.sign_status = ctk.CTkLabel(frame, text="", font=ctk.CTkFont(size=12))
        self.sign_status.grid(row=4, column=0, padx=10, pady=(0, 10), sticky="w")
    
    def _setup_verify_tab(self):
        """Configura o tab de verificação."""
        tab = self.tabview.tab("Verificar")
        
        frame = ctk.CTkFrame(tab)
        frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        frame.grid_columnconfigure(0, weight=1)
        
        # Chave pública
        self.verify_key_picker = FilePicker(
            frame,
            label="Chave Pública (PEM):",
            mode="open",
            file_types=[("Ficheiro PEM", "*.pem"), ("Todos os ficheiros", "*.*")]
        )
        self.verify_key_picker.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        
        # Ficheiro original
        self.verify_file_picker = FilePicker(
            frame,
            label="Ficheiro Original:",
            mode="open",
            file_types=[("Todos os ficheiros", "*.*")]
        )
        self.verify_file_picker.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        
        # Ficheiro de assinatura
        self.verify_sig_picker = FilePicker(
            frame,
            label="Ficheiro de Assinatura:",
            mode="open",
            file_types=[("Ficheiro de assinatura", "*.sig"), ("Todos os ficheiros", "*.*")]
        )
        self.verify_sig_picker.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
        
        # Botão verificar
        verify_button = ctk.CTkButton(
            frame,
            text="✅ Verificar Assinatura",
            command=self._verify_signature,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        verify_button.grid(row=3, column=0, padx=10, pady=15, sticky="ew")
        
        # Status
        self.verify_status = ctk.CTkLabel(frame, text="", font=ctk.CTkFont(size=12))
        self.verify_status.grid(row=4, column=0, padx=10, pady=(0, 10), sticky="w")
    
    def _generate_keys(self):
        """Gera par de chaves RSA."""
        save_path = self.save_dir_picker.get_path()
        if not save_path:
            messagebox.showerror("Erro", "Por favor, selecione uma pasta para guardar as chaves.")
            return
        
        # Se selecionou um ficheiro, usar o diretório pai
        if os.path.isfile(save_path):
            save_dir = os.path.dirname(save_path)
        else:
            save_dir = save_path
        
        if not os.path.exists(save_dir):
            messagebox.showerror("Erro", "O diretório selecionado não existe.")
            return
        
        try:
            key_size = int(self.key_size_var.get())
            
            self.gen_status.configure(text="A gerar chaves...", text_color="orange")
            self.update()
            
            # Gerar par de chaves
            private_key, public_key = generate_rsa_keypair(key_size)
            
            # Serializar
            private_pem = serialize_private_key(private_key)
            public_pem = serialize_public_key(public_key)
            
            # Guardar ficheiros
            private_path = os.path.join(save_dir, "private_key.pem")
            public_path = os.path.join(save_dir, "public_key.pem")
            
            write_file_bytes(private_path, private_pem)
            write_file_bytes(public_path, public_pem)
            
            self.gen_status.configure(text=f"✅ Chaves geradas com sucesso! ({key_size} bits)", text_color="green")
            messagebox.showinfo("Sucesso", f"Chaves RSA geradas!\n\nChave privada: {private_path}\nChave pública: {public_path}")
            
        except Exception as e:
            self.gen_status.configure(text="❌ Erro ao gerar chaves", text_color="red")
            messagebox.showerror("Erro", f"Erro ao gerar chaves:\n{str(e)}")
    
    def _sign_file(self):
        """Assina um ficheiro."""
        key_path = self.sign_key_picker.get_path()
        file_path = self.sign_file_picker.get_path()
        sig_path = self.sign_output_picker.get_path()
        
        if not key_path or not os.path.exists(key_path):
            messagebox.showerror("Erro", "Por favor, selecione a chave privada.")
            return
        
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Erro", "Por favor, selecione o ficheiro a assinar.")
            return
        
        if not sig_path:
            messagebox.showerror("Erro", "Por favor, defina onde guardar a assinatura.")
            return
        
        try:
            self.sign_status.configure(text="A assinar...", text_color="orange")
            self.update()
            
            # Ler chave privada
            private_pem = read_file_bytes(key_path)
            private_key = deserialize_private_key(private_pem)
            
            # Ler ficheiro
            file_data = read_file_bytes(file_path)
            
            # Assinar
            signature = sign_message_rsa(private_key, file_data) #type: ignore
            
            # Guardar assinatura
            write_file_bytes(sig_path, signature)
            
            self.sign_status.configure(text="✅ Ficheiro assinado com sucesso!", text_color="green")
            messagebox.showinfo("Sucesso", f"Ficheiro assinado!\nAssinatura guardada em: {sig_path}")
            
        except Exception as e:
            self.sign_status.configure(text="❌ Erro ao assinar", text_color="red")
            messagebox.showerror("Erro", f"Erro ao assinar o ficheiro:\n{str(e)}")
    
    def _verify_signature(self):
        """Verifica uma assinatura."""
        key_path = self.verify_key_picker.get_path()
        file_path = self.verify_file_picker.get_path()
        sig_path = self.verify_sig_picker.get_path()
        
        if not key_path or not os.path.exists(key_path):
            messagebox.showerror("Erro", "Por favor, selecione a chave pública.")
            return
        
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Erro", "Por favor, selecione o ficheiro original.")
            return
        
        if not sig_path or not os.path.exists(sig_path):
            messagebox.showerror("Erro", "Por favor, selecione o ficheiro de assinatura.")
            return
        
        try:
            self.verify_status.configure(text="A verificar...", text_color="orange")
            self.update()
            
            # Ler chave pública
            public_pem = read_file_bytes(key_path)
            public_key = deserialize_public_key(public_pem)
            
            # Ler ficheiro e assinatura
            file_data = read_file_bytes(file_path)
            signature = read_file_bytes(sig_path)
            
            # Verificar
            is_valid = verify_signature_rsa(public_key, file_data, signature) #type: ignore
            
            if is_valid:
                self.verify_status.configure(text="✅ Assinatura VÁLIDA!", text_color="green")
                messagebox.showinfo("Válida", "✅ A assinatura é VÁLIDA!\n\nO ficheiro é autêntico e não foi modificado.")
            else:
                self.verify_status.configure(text="❌ Assinatura INVÁLIDA!", text_color="red")
                messagebox.showerror("Inválida", "❌ A assinatura é INVÁLIDA!\n\nO ficheiro pode ter sido modificado ou a assinatura não corresponde.")
            
        except Exception as e:
            self.verify_status.configure(text="❌ Erro ao verificar", text_color="red")
            messagebox.showerror("Erro", f"Erro ao verificar a assinatura:\n{str(e)}")
