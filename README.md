# Secure Login System

A secure login system built with Python that implements user authentication with hashed passwords, account management, and protection against common security vulnerabilities.

---

## Features

- User registration with email and password  
- Passwords hashed using **bcrypt** for security  
- Login authentication with session management  
- Protection against SQL injection and brute-force attacks  
- User-friendly CLI interface (can be extended to GUI or web)  
- Error handling for invalid login or registration attempts  
- Modular and easy-to-extend codebase  

---

## Clone the Repository

```bash
git clone https://github.com/LordAbdulla/secure-login-system
cd secure-login-system
python3 -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows
pip install -r requirements.txt
python main.py
