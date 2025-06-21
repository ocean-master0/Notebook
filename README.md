
---

# 🔐 Secure Notebook – Privacy-First Note-Taking App

A modern, private, and secure note-taking app built with **Flask**, featuring **AES encryption**, **no server-side data storage**, and a sleek **glassmorphism UI**.

---

## ✨ Core Highlights

### 🔒 Security & Privacy

* ✅ **AES-256 Encryption** (GCM) for text & files
* 🔑 **Password Strength Checker** with real-time feedback
* 🔐 **PBKDF2 Key Derivation** with SHA-256 & Salt
* 🚫 **No Server Storage** – Everything runs on the client
* 🧹 **Auto-Cleanup of Temporary Files**

### 📝 Rich Note-Taking

* 🖋️ **Rich Text Editor** with formatting tools
* 🔢 **Syntax Highlighting** & line numbers
* 🔄 **Undo/Redo**, word/char count
* ⬇️ **Export to .txt / .pdf**, 📋 **Copy to Clipboard**

### 📁 File Management

* 📤 **Encrypt/Decrypt .txt files**
* 🔄 **Drag & Drop Uploads**
* 🔐 **Manual or File-based Decryption**

### 🎨 UI & UX

* 🧊 **Glassmorphism Design**
* 🌙 **Dark/Light Theme Toggle**
* 📱 **Responsive Layout** for all screen sizes
* 🔔 **Toast Notifications** & keyboard shortcuts

---

## 🚀 Quick Start

```bash
git clone https://github.com/ocean-master0/Notebook.git
cd secure-notebook
pip install -r requirements.txt
python app.py
```

➡️ Open your browser: `http://localhost:5000`

---

## 🔧 Tech Stack

* **Python** + **Flask**
* **JavaScript**, **HTML/CSS**
* `cryptography`, `PyPDF2`, `reportlab`

---

## 🔐 Security Internals

| Feature           | Details                                    |
| ----------------- | ------------------------------------------ |
| 🔐 **Encryption** | AES-256 GCM, PBKDF2 (SHA-256, 100k rounds) |
| 🔑 **Passwords**  | Entropy check, pattern detection, criteria |
| 🧾 **Integrity**  | Authenticated encryption with nonce/salt   |
| 🚫 **Storage**    | Client-side only, no persistent data saved |

---

## 🔁 Hot Shortcuts

* `Ctrl+S` – Save Note
* `Ctrl+N` – New Note
* `Ctrl+Z` / `Ctrl+Y` – Undo / Redo
* `Alt+1` to `Alt+5` – Section navigation

---

## 🧪 Manual Tests Checklist

✅ Password strength checker
✅ Encrypt/decrypt .txt files
✅ Export PDF, verify styling
✅ Mobile and tablet responsiveness
✅ Keyboard shortcuts work

---

## 🛠 Deployment

**Dev Mode:**

```bash
python app.py
```

**Prod with Gunicorn:**

```bash
gunicorn -c gunicorn_config.py app:app
```

**Docker:**

```dockerfile
FROM python:3.9-slim
...
```

---

## 🙏 Acknowledgments

* [Flask](https://flask.palletsprojects.com/)
* [Cryptography](https://cryptography.io/)
* [ReportLab](https://www.reportlab.com/)
* [Font Awesome](https://fontawesome.com/)

---

**Built with ❤️ for privacy-first users.**
*No cloud. No compromise. Just you and your notes.*

---


