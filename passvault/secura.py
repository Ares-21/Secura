from array import array
from ctypes import alignment
import random
import sqlite3
import hashlib
from sqlite3.dbapi2 import Cursor
from tkinter import *
from tkinter import simpledialog
from tkinter.font import Font
from functools import partial
import uuid
import pyperclip
import base64
import os
from tkinter import ttk
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import tkinter
import customtkinter
from tkinter import messagebox

customtkinter.set_appearance_mode("system")  # Modes: system (default), light, dark
customtkinter.set_default_color_theme("dark-blue")  # Themes: blue (default), dark-blue, green

# left frame

encryptionkey = 0


def openVault():
    def on_closing():
        opnvault_btn['state'] = NORMAL
        window2.destroy()

    backend = default_backend()
    salt = b'2444'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )

    def encrypt(message: bytes, key: bytes) -> bytes:
        return Fernet(key).encrypt(message)

    def decrypt(message: bytes, token: bytes) -> bytes:
        return Fernet(token).decrypt(message)

    with sqlite3.connect("password-vault.db") as db:
        cursor = db.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS masterpassword( 
    id INTEGER PRIMARY KEY,
    password TEXT NOT NULL,
    recoverykey TEXT NOT NULL);
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vault(
    id INTEGER PRIMARY KEY,
    ACCOUNT TEXT NOT NULL,
    USERNAME TEXT NOT NULL,
    PASSWORD TEXT NOT NULL);
    """)

    def popUp(text, previous_txt=""):
        answer = simpledialog.askstring("input string", prompt=text, initialvalue=str(previous_txt))
        return answer

    window2 = customtkinter.CTkToplevel(window)
    window2.protocol("WM_DELETE_WINDOW", on_closing)

    window2.title("PASSWORD VAULT")

    def hashPassword(input):
        # hash=hashlib.sha256(input)
        # hash=hash.hexdigest()
        return hashlib.sha256(input).hexdigest()

    def firstScreen():
        for widget in window2.winfo_children():
            widget.destroy()
        window2.geometry("350x200")

        lbl = customtkinter.CTkLabel(window2, text="Create Master Password")
        lbl.configure(anchor=CENTER)
        lbl.pack()

        Mstr_pass_txt = customtkinter.CTkEntry(window2, width=160, show="*",
                                               placeholder_text_color="#3b8cc6",
                                               text_color="#3b8cc6", border_color="#3b8cc6", bg_color="#262626",
                                               fg_color="#262626")
        Mstr_pass_txt.pack()
        Mstr_pass_txt.focus()

        lbl1 = customtkinter.CTkLabel(window2, text="Confirm Master Password")
        lbl1.pack()

        Mstr_pass_txt2 = customtkinter.CTkEntry(window2, width=160, show="*",
                                                placeholder_text_color="#3b8cc6",
                                                text_color="#3b8cc6", border_color="#3b8cc6", bg_color="#262626",
                                                fg_color="#262626")
        Mstr_pass_txt2.pack()

        lbl2 = customtkinter.CTkLabel(window2, text="")
        lbl2.pack()

        def savePassword():
            if Mstr_pass_txt.get() == Mstr_pass_txt2.get():
                sql = "DELETE FROM masterpassword WHERE id=1"
                cursor.execute(sql)

                hashed_pass = hashPassword(Mstr_pass_txt.get().encode('utf-8'))
                key = str(uuid.uuid4().hex)

                recoverykey = hashPassword(key.encode('utf-8'))
                global encryptionkey
                encryptionkey = base64.urlsafe_b64encode(kdf.derive("PremWagh2210".encode('utf-8')))

                insert_pass = """INSERT INTO masterpassword(password,recoverykey)
                VALUES(?,?)"""
                cursor.execute(insert_pass, ((hashed_pass), (recoverykey)))
                db.commit()
                recoveryScreen(key)
            else:
                Mstr_pass_txt2.delete(0, 'end')
                lbl2.configure(text="TRY AGAIN !")

        btn = customtkinter.CTkButton(window2, text="SAVE", command=savePassword, width=160)
        btn.pack(pady=10, padx=5)

    def recoveryScreen(key):
        for widget in window2.winfo_children():
            widget.destroy()
        window2.geometry("320x150")

        lbl = customtkinter.CTkLabel(window2, text="Save Recovery Key")
        lbl.configure(anchor=CENTER)
        lbl.pack()

        lbl1 = customtkinter.CTkLabel(window2, text=key)
        lbl1.configure(anchor=CENTER)
        lbl1.pack()

        def copykey():
            pyperclip.copy(lbl1.cget("text"))

        btn = customtkinter.CTkButton(window2, text="Copy key", command=copykey)
        btn.pack(pady=10)

        def done():
            passwordvault()

        btn = customtkinter.CTkButton(window2, text="Done", command=done)
        btn.pack(pady=10)

    def resetScreen():
        for widget in window2.winfo_children():
            widget.destroy()
        window2.geometry("250x150")

        lbl = customtkinter.CTkLabel(window2, text="Enter Recovery Key")
        lbl.configure(anchor=CENTER)
        lbl.pack(padx=5, pady=5)
        txt = customtkinter.CTkEntry(window2, width=140,
                                     placeholder_text_color="#3b8cc6",
                                     text_color="#3b8cc6", border_color="#3b8cc6", bg_color="#262626",
                                     fg_color="#262626")
        txt.pack(padx=5, pady=5)
        txt.focus()

        lbl1 = customtkinter.CTkLabel(window2)
        lbl1.configure(anchor=CENTER)
        lbl1.pack()

        def getrecoverykey():
            recoverykeycheck = hashPassword((txt.get().encode('utf-8')))
            cursor.execute("SELECT * FROM masterpassword WHERE id=1 AND recoverykey=?", [(recoverykeycheck)])
            return cursor.fetchall()

        def checkRecovery():
            checked = getrecoverykey()
            if checked:
                firstScreen()
            else:
                txt.delete(0, 'end')
                lbl1.configure(text="wrong key")

        btn = customtkinter.CTkButton(window2, text="Check key", command=checkRecovery)
        btn.pack(pady=5, padx=5)

    def loginScreen():
        for widget in window2.winfo_children():
            widget.destroy()
        window2.geometry("250x200")

        lbl = customtkinter.CTkLabel(window2, text="Enter Master Password")
        lbl.configure(anchor=CENTER)
        lbl.pack()

        Mstr_pass_txt = customtkinter.CTkEntry(window2, width=140, show="*", placeholder_text="Enter Password",
                                               placeholder_text_color="#3b8cc6",
                                               text_color="#3b8cc6", border_color="#3b8cc6", bg_color="#262626",
                                               fg_color="#262626")
        Mstr_pass_txt.pack(pady=5, padx=5)
        Mstr_pass_txt.focus()

        lbl1 = customtkinter.CTkLabel(window2, text="")
        lbl1.pack()

        def getMasterPassword():
            checkHashedpass = hashPassword(Mstr_pass_txt.get().encode('utf-8'))
            cursor.execute("SELECT * FROM masterpassword WHERE id=1 AND password=?", [(checkHashedpass)])
            return cursor.fetchall()

        def checkPassword():

            match = getMasterPassword()
            if match:
                global encryptionkey
                encryptionkey = base64.urlsafe_b64encode(kdf.derive("PremWagh2210".encode('utf-8')))
                passwordvault()
            else:
                Mstr_pass_txt.delete(0, 'end')
                lbl1.configure(text="Wrong Password !")

        def resetPassword():
            resetScreen()

        login_btn = customtkinter.CTkButton(window2, text="Login", command=checkPassword)
        login_btn.pack(pady=5, padx=5, anchor=CENTER)

        login_btn = customtkinter.CTkButton(window2, text="Reset Password", command=resetPassword)
        login_btn.pack(pady=5, padx=5, anchor=CENTER)

    def passwordvault():
        for widget in window2.winfo_children():
            widget.destroy()

        def copyPass(password):
            password = decrypt(password, encryptionkey).decode('utf-8')
            pyperclip.copy(password)

        def copyursm(username):
            username = decrypt(username, encryptionkey).decode('utf-8')
            pyperclip.copy(username)

        def updateEntry(acc_id, account, username, password):
            prev_acc = decrypt(account, encryptionkey).decode('utf-8')
            prev_usnme = decrypt(username, encryptionkey).decode('utf-8')
            prev_pass = decrypt(password, encryptionkey).decode('utf-8')

            text1 = "UPDATE ACCOUNT"
            text2 = "UPDATE USERNAME"
            text3 = "UPDATE PASSWORD"
            account = encrypt(popUp(text1, prev_acc).encode('utf-8'), encryptionkey)
            username = encrypt(popUp(text2, prev_usnme).encode('utf-8'), encryptionkey)
            password = encrypt(popUp(text3, prev_pass).encode('utf-8'), encryptionkey)
            cursor.execute("UPDATE vault SET account=?, username=?, password=? WHERE id=?",
                           (account, username, password, acc_id))
            db.commit()
            passwordvault()

        def addEntry():
            text1 = "ACCOUNT"
            text2 = "USERNAME"
            text3 = "PASSWORD"
            account = encrypt(popUp(text1).encode('utf-8'), encryptionkey)
            username = encrypt(popUp(text2).encode('utf-8'), encryptionkey)
            password = encrypt(popUp(text3).encode('utf-8'), encryptionkey)

            insert_feild = """INSERT INTO vault(account,username,password)
            VALUES(?,?,?) """
            cursor.execute(insert_feild, (account, username, password))
            db.commit()
            passwordvault()

        def removeEntry(input):
            cursor.execute("DELETE FROM vault WHERE id=?", (input,))
            db.commit()
            passwordvault()

        window2.geometry("1020x450")
        # v=ttk.Scrollbar(window2,orient='vertical')
        # v.grid(row=0,column=8,sticky=NS)

        add_entry_btn = customtkinter.CTkButton(window2, text="ADD A NEW ENTRY", command=addEntry, width=180)
        add_entry_btn.grid(row=2, column=3, columnspan=2, pady=10)
        lbl = customtkinter.CTkLabel(window2, text="ACCOUNT")
        lbl.grid(row=2, column=0, padx=40, pady=20)
        lbl = customtkinter.CTkLabel(window2, text="USERNAME")
        lbl.grid(row=2, column=1, padx=40, pady=2)
        lbl = customtkinter.CTkLabel(window2, text="PASSWORD")
        lbl.grid(row=2, column=2, padx=40, pady=2)
        cursor.execute("SELECT * FROM vault")
        if (cursor.fetchall() != None):
            i = 0
            cursor.execute("SELECT id,account,username,password FROM vault")

            for row in cursor.fetchall():
                acc_lab1 = customtkinter.CTkLabel(window2, text=(decrypt(row[1], encryptionkey)))
                acc_lab1.grid(column=0, row=i + 3)
                ursm_lab1 = customtkinter.CTkLabel(window2, text=(decrypt(row[2], encryptionkey)))
                ursm_lab1.grid(column=1, row=i + 3)
                pass_lab1 = customtkinter.CTkLabel(window2, text='* ' * len((decrypt(row[3], encryptionkey))))
                pass_lab1.grid(column=2, row=i + 3)

                dlete_btn = customtkinter.CTkButton(window2, text="DELETE", width=100,
                                                    command=partial(removeEntry, row[0]))
                dlete_btn.grid(column=3, row=i + 3, pady=10, padx=10)

                update_btn = customtkinter.CTkButton(window2, text="UPDATE", width=100,
                                                     command=partial(updateEntry, *row))
                update_btn.grid(column=4, row=i + 3, pady=10, padx=10)

                cpy_btn = customtkinter.CTkButton(window2, text="COPY PASS", width=100,
                                                  command=partial(copyPass, row[3]))
                cpy_btn.grid(column=5, row=i + 3, pady=10, padx=10)

                cpy_btn = customtkinter.CTkButton(window2, text="COPY USERNAME", width=100,
                                                  command=partial(copyursm, row[2]))
                cpy_btn.grid(column=6, row=i + 3, pady=10, padx=10)

                i += 1

    cursor.execute('SELECT * FROM masterpassword')
    if cursor.fetchall():
        loginScreen()
    else:
        firstScreen()


# ================================================(PASSWORD GENERATOR)=================================================================
window = customtkinter.CTk()
window.geometry('730x330')
window.iconbitmap('lock.png')
window.configure(bg='grey92')
window.style = ttk.Style(window)
window.title("Secura")
# window.iconbitmap(True,'H:/prem college/qt_5.12/login_window_fl/login_img/f_logo.ico')
window.resizable(0, 0)

window.columnconfigure(1, weight=1)
window.rowconfigure(0, weight=1)

# right frame

frame_right = customtkinter.CTkFrame(master=window)
frame_right.grid(row=0, column=1, sticky="nswe", padx=20, pady=20)

frame_right.rowconfigure((0, 1, 2, 3), weight=1)
frame_right.rowconfigure(7, weight=10)
frame_right.columnconfigure((0, 1), weight=1)
frame_right.columnconfigure(2, weight=0)

# left frame

frame_left = customtkinter.CTkFrame(window, corner_radius=0, width=180, height=140)
frame_left.grid(row=0, column=0, sticky="nswe", )

frame_left.grid_rowconfigure(0, minsize=10)  # empty row with minsize as spacing
frame_left.grid_rowconfigure(5, weight=1)  # empty row as spacing
frame_left.grid_rowconfigure(8, minsize=20)  # empty row with minsize as spacing
frame_left.grid_rowconfigure(11, minsize=10)  # empty row with minsize as spacing

# password search bar frame

labelframe = customtkinter.CTkFrame(master=frame_right, corner_radius=10, width=600)
labelframe.grid(row=1, pady=2, columnspan=4, padx=10, sticky="nswe")

# password generator frame

labelframe1 = customtkinter.CTkFrame(master=frame_right, corner_radius=10, width=600)
labelframe1.grid(row=5, pady=2, columnspan=4, padx=10, sticky="nswe")

no_of_letters = IntVar()
no_of_letters.set(0)
no_of_digits = IntVar()
no_of_digits.set(0)
no_of_symbols = IntVar()
no_of_symbols.set(0)

heading = customtkinter.CTkLabel(master=frame_right, text='PASSWORD GENERATOR').grid(row=4, column=0, pady=5, padx=5)

letter_spinbox_label = customtkinter.CTkLabel(master=labelframe1, text="Select number of letters ",
                                              ).grid(row=5, column=1, pady=5, padx=21)
letter_spinbox = ttk.Spinbox(labelframe1, from_=0, to=11, textvariable=no_of_letters, width=5,
                             font=Font(family='Helvetica', size=12)).grid(row=5, column=2, pady=5, padx=21)

digit_spinbox_label = customtkinter.CTkLabel(master=labelframe1, text="Select number of digits ",
                                             ).grid(row=6, column=1, pady=5, padx=21)
digit_spinbox = ttk.Spinbox(master=labelframe1, from_=0, to=11, textvariable=no_of_digits, width=5,
                            font=Font(family='Helvetica', size=12)).grid(row=6, column=2, pady=5, padx=21)

symbol_spinbox_label = customtkinter.CTkLabel(master=labelframe1, text="Select number of symbols ",
                                              ).grid(row=7, column=1, pady=5, padx=21)
symbol_spinbox = ttk.Spinbox(labelframe1, from_=0, to=11, textvariable=no_of_symbols, width=5,
                             font=Font(family='Helvetica', size=12)).grid(row=7, column=2, pady=5, padx=21)

password_string = StringVar()


def Copy_password():
    pyperclip.copy(password_string.get())
    copy['state'] = DISABLED


def generate():
    copy['state'] = NORMAL
    password = []
    digits = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0']
    letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
               'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
               'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    symbols = ['#', '$', '%', '&', '(', ')', '*', '+', '-', '.', '/', ':', '<', '=', '>', '?', '@', '[', ']', '^', '_',
               '{', '}', '/']

    for x in range(no_of_letters.get()):
        password.append(random.choice(letters))
    for x in range(no_of_digits.get()):
        password.append(random.choice(digits))
    for x in range(no_of_symbols.get()):
        password.append(random.choice(symbols))

    random.shuffle(password)
    password_string.set("".join(password))


copy = customtkinter.CTkButton(labelframe1, width=160, text='COPY', command=Copy_password)


def disablebtn():
    opnvault_btn['state'] = DISABLED
    openVault()


opnvault_btn = customtkinter.CTkButton(master=frame_left, text="ACCESS VAULT", command=disablebtn)

generate_pass = customtkinter.CTkButton(labelframe1, width=160, text="GENERATE PASSWORD", command=generate).grid(row=5,
                                                                                                                 column=3,
                                                                                                                 pady=5,
                                                                                                                 padx=21)

customtkinter.CTkEntry(labelframe1, width=160, textvariable=password_string, placeholder_text_color="#3b8cc6",
                       text_color="#3b8cc6", border_color="#3b8cc6", bg_color="#262626", fg_color="#262626"
                       ).grid(row=6, column=3, pady=5, padx=21)

secura = customtkinter.CTkLabel(master=frame_left, text="SECURA ",
                                ).grid(row=0, column=0, pady=10, padx=10)

copy.grid(row=7, column=3, pady=5, padx=21)

opnvault_btn.grid(row=2, column=0, pady=2, padx=15)

# =================================================(PASSWORD CHECKER)======================================================================

heading1 = customtkinter.CTkLabel(frame_right, text='IS MY PASSWORD SECURE?').grid(row=0, column=0, pady=5, padx=170,
                                                                                   sticky="we")

# Load the database of most common passwords
with open('10-million-password-list-top-1000000.txt', 'r') as f:
    common_passwords = set([line.strip() for line in f.readlines()])


# Define a function to check if the password is in the database of common passwords
def check_password(password):
    if password in common_passwords:
        return "The password you entered has been compromised"
    else:
        return "The password you entered is not in the list of 1,000,000 common passwords."


# Define a function to be called when the button is clicked
def on_button_click():
    password = password_entry.get()
    result_label.configure(text=check_password(password))


# Create a window with a password entry field and a button

password_entry = customtkinter.CTkEntry(labelframe, show="*", width=325, placeholder_text="Search Your Password",
                                        placeholder_text_color="#3b8cc6",
                                        text_color="#3b8cc6", border_color="#3b8cc6", bg_color="#262626",
                                        fg_color="#262626")
password_entry.grid(row=0, column=1, pady=5, padx=5, )

check_button = customtkinter.CTkButton(labelframe, text="CHECK", command=on_button_click, width=155)
check_button.grid(sticky="nswe", row=0, column=2, pady=5, padx=5)

result_label = customtkinter.CTkLabel(labelframe, text="")
result_label.grid(row=3, column=0, columnspan=4, pady=5, padx=10)

window.mainloop()
