
# 🔐 Crypto Lab — Ferramenta Educativa de Criptografia em Python

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Ativo-success)

Este projeto implementa, de forma **educativa e modular**, diversos algoritmos criptográficos em Python.  
O objetivo é compreender e demonstrar como funcionam **as principais técnicas de criptografia moderna**, incluindo cifras simétricas, assimétricas, assinaturas digitais e funções de hash.

---

## 🧠 Objetivos

- Implementar e compreender algoritmos de **cifra e decifra** (AES, 3DES, RSA, etc.)
- Demonstrar a **derivação segura de chaves** com Scrypt (KDF)
- Explorar **assinaturas digitais** e verificação de integridade
- OPT: Estruturar o projeto de forma **modular e escalável**
- OPT: Desenvolver uma **interface gráfica (CustomTkinter)** para interação simples e intuitiva

---

## 🧩 Estrutura do Projeto

```
crypto_lab/
│
├── src/
│   ├── crypto/               # Módulos de criptografia
│   │   ├── symmetric.py      # AES-GCM, 3DES, Scrypt (KDF)
│   │   ├── asymmetric.py     # RSA, ECDH
│   │   ├── signatures.py     # Assinaturas digitais
│   │   ├── hashing.py        # Hash e HMAC
│   │   └── utils.py          # Funções auxiliares
│   │
│   ├── gui/                  # Interface Tkinter
│   │   ├── app.py
│   │   └── views/
│   │       ├── encrypt_view.py
│   │       ├── decrypt_view.py
│   │       └── hash_view.py
│   │
│   └── tests/                # Testes automatizados
│       ├── test_symmetric.py
│       └── tmp/              # Ficheiros temporários
│
├── .env                      # Configuração local (VS Code)
├── .gitignore
├── LICENSE
├── README.md
└── requirements.txt
```

---

## ⚙️ Instalação e Execução

### 1️⃣ Clonar o repositório

```bash
git clone https://github.com/GPVilia/crypto-lab.git
cd crypto-lab
```

### 2️⃣ Criar ambiente virtual

```bash
python -m venv .venv
# Ativar:
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate
```

### 3️⃣ Instalar dependências

```bash
pip install -r requirements.txt
```

### 4️⃣ Executar os testes de criptografia simétrica

```bash
py -m src.tests.test_symmetric
py -m src.tests.test_asymmetric
py -m src.tests.test_hashing
py -m src.tests.test_signatures
```
Ou se preferir correr a interface gráfica:
```bash
py .\src\main.py
```

---

## 🔐 Funcionalidades Implementadas

| Categoria | Algoritmos | Descrição |
|------------|-------------|------------|
| **Cifras Simétricas** | AES, 3DES | Cifra e decifra de ficheiros com chaves derivadas (Scrypt) |
| **Cifras Assimétricas** | RSA, ECDH | Geração de pares de chaves, cifra e decifra |
| **Assinaturas Digitais** | RSA-PSS, DSA, ECDSA | Assinar e verificar mensagens e ficheiros |
| **Hash e HMAC** | MD5, SHA-2, SHA-3, HMAC-SHA256 | Integridade e autenticação |
| **Interface Gráfica** | CustomTkinter | GUI moderna com modo escuro e ações de cifra/decifra |

---

## 🧪 Testes

Os testes são executados automaticamente a partir da pasta `src/tests/`:

```bash
py -m src.tests.test_symmetric
```

Isto cria e decifra ficheiros temporários dentro de `src/tests/tmp/` para validar:
- Derivação de chave (scrypt)
- Cifra e decifra AES-GCM
- Cifra e decifra 3DES-CBC

---

## 🧾 Licença

Este projeto é distribuído sob a licença **MIT** — consulta o ficheiro [LICENSE](./LICENSE) para mais detalhes.

## ⭐ Contribuições

Este projeto é aberto a melhorias.  
Sugestões, correções ou novas funcionalidades são bem-vindas através de *Pull Requests* ou *Issues*.

## 📚
Licenciatura em Gestão de Sistemas e Computação
Universidade Altântica


---
