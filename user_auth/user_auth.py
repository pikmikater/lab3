import sqlite3
import hashlib

DB_NAME = 'users.db'

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_database():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (  
        login TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        full_name TEXT NOT NULL
    )''')
    conn.commit()
    conn.close()

def add_user(login, password, full_name):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (login, password, full_name) VALUES (?, ?, ?)',
                       (login, hash_password(password), full_name))
        conn.commit()
        print(f"User {login} added successfully.")
    except sqlite3.IntegrityError:
        print(f"User {login} already exists.")
    conn.close()

def update_password(login, new_password):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET password = ? WHERE login = ?',
                   (hash_password(new_password), login))
    if cursor.rowcount == 0:
        print(f"User {login} not found.")
    else:
        print(f"Password for user {login} updated successfully.")
    conn.commit()
    conn.close()

def authenticate_user(login):
    password = input("Enter password: ")
    hashed_password = hash_password(password)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE login = ? AND password = ?', (login, hashed_password))
    result = cursor.fetchone()
    conn.close()
    if result:
        print(f"User {login} authenticated successfully.")
    else:
        print("Authentication failed.")

if __name__ == "__main__":
    create_database()
    while True:
        print("\nMenu:")
        print("1. Add User")
        print("2. Update Password")
        print("3. Authenticate User")
        print("4. Exit")
        choice = input("Enter your choice: ")
        
        if choice == '1':
            login = input("Enter login: ")
            password = input("Enter password: ")
            full_name = input("Enter full name: ")
            add_user(login, password, full_name)
        elif choice == '2':
            login = input("Enter login: ")
            new_password = input("Enter new password: ")
            update_password(login, new_password)
        elif choice == '3':
            login = input("Enter login: ")
            authenticate_user(login)
        elif choice == '4':
            break
        else:
            print("Invalid choice. Please try again.")
