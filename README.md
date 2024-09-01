### Overview of the Fortichat Project

**Fortichat** is a web application designed for secure communication through the obfuscation and encryption of messages, implemented using Python and the Flask framework. Below is a detailed breakdown of the project as outlined in the provided files.

### 1. Introduction

Fortichat is a secure messaging platform where users can register, log in, and exchange encrypted messages. The application uses AES encryption (Advanced Encryption Standard) for securing messages and SHA-256 hashing for password management. The purpose of this project is to provide a secure communication channel that protects user data and ensures privacy.

### 2. Getting Started

#### Prerequisites
- **Python 3.12** or higher
- **Flask 2.x**
- Additional Python libraries listed in `requirements.txt` (these should be installed during setup).

### 3. Installation

To install the Fortichat application, follow these steps:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/radik097/project-name.git
   ```
2. **Navigate to the project directory:**
   ```bash
   cd project-name
   ```
3. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # For Linux/macOS
   venv\Scripts\activate  # For Windows
   ```
4. **Install the required dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

### 4. Usage

To start the Fortichat application, use the following command:

```bash
python main.py
```

#### Command Line Options

The application does not explicitly mention command-line options, but the typical usage scenario involves starting the Flask server with the command above.

### 5. Support

For specific instructions on running the project, you can refer to the installation and usage sections. If you encounter any issues, the typical procedure involves checking the Flask server logs and ensuring that all dependencies are correctly installed.

### 6. Change Log

- **Version 0.5**
  - Initial release.

### 7. License

This project is licensed under the [MIT License](LICENSE). Refer to the `LICENSE` file for more details.

---

### Detailed Explanation of Project Files

- **`index.html`**: The main page where users can select a chat partner, send messages, and view the chat history. It includes placeholders for dynamic content like user avatars and chat messages. The JavaScript file `scripts.js` handles the encryption and decryption of messages using the `forge` library【9†source】【10†source】.

- **`login.html`**: The login page where users enter their credentials. Passwords are hashed using SHA-256 before being sent to the server, ensuring that sensitive data is not transmitted in plain text【11†source】.

- **`register.html`**: The registration page where new users can create accounts. It includes an option to upload a profile picture, which is encoded in Base64 and sent to the server along with the username and hashed password【12†source】.

- **`scripts.js`**: This JavaScript file contains the logic for encrypting/decrypting messages, handling user interactions, and communicating with the server via API calls. It uses the `forge` library for cryptographic operations【10†source】.

- **`forge.all.min.js`**: A minimized version of the `forge` JavaScript library, which provides various cryptographic functions such as AES encryption and SHA-256 hashing. This library is crucial for ensuring the security of user data in Fortichat【13†source】.

This structured approach in the `ReadMe.md` will help users understand the purpose, installation, and usage of the Fortichat project, while also giving them insight into the underlying technical details.
