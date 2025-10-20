
# 🔐 Crypto Lab — Ferramenta Educativa de Criptografia em Python

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-In%20Development-yellow)

Este projeto implementa, de forma **educativa e modular**, diversos algoritmos criptográficos em Python.  
O objetivo é compreender e demonstrar como funcionam **as principais técnicas de criptografia moderna**, incluindo cifras simétricas, assimétricas, assinaturas digitais e funções de hash.

---

## 🧠 Objetivos

- Implementar e compreender algoritmos de **cifra e decifra** (AES, 3DES, RSA, etc.)
- Demonstrar a **derivação segura de chaves** com Scrypt (KDF)
- Explorar **assinaturas digitais** e verificação de integridade
- Estruturar o projeto de forma **modular e escalável**
- Desenvolver uma **interface gráfica (Tkinter)** para interação simples e intuitiva

---

## 🧩 Estrutura do Projeto

```
crypto_lab/
│
├── src/
│   ├── crypto/               # Módulos de criptografia
│   │   ├── symmetric.py      # AES-GCM, 3DES, Scrypt (KDF)
│   │   ├── asymmetric.py     # RSA, ECDH (futuro)
│   │   ├── signatures.py     # Assinaturas digitais (futuro)
│   │   ├── hashing.py        # Hash e HMAC (futuro)
│   │   └── utils.py          # Funções auxiliares
│   │
│   ├── gui/                  # Interface Tkinter (fase futura)
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
```

---

## 🔐 Funcionalidades Implementadas

| Categoria | Algoritmos | Descrição |
|------------|-------------|------------|
| **KDF (Derivação de Chave)** | Scrypt | Converte senhas em chaves seguras com salt aleatório |
| **Simétrica** | AES-256-GCM | Cifra autenticada moderna |
| | 3DES-CBC | Algoritmo legado para comparação |
| **Assimétrica** | RSA | Base para cifra híbrida e assinatura digital |
| | ECDH | Derivação de chave via curvas elípticas |
| **Assinatura Digital** | RSA-PSS / DSA | Assinar e verificar ficheiros |
| **Hash / HMAC** | MD5, SHA-2, SHA-3 | Integridade e autenticação |

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

---
