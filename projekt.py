#!/usr/bin/env python
# coding: utf-8

# In[1]:


import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
from tkinter import *
from tkinter import ttk, filedialog
    
def gen_kljuc():
    os.makedirs("kljucevi", exist_ok=True)

    tajni = os.urandom(32)
    iv = os.urandom(16)
    with open("kljucevi/tajni_kljuc.txt", "wb") as f:
        f.write(tajni)
        f.write(b'\n-----END KEY-----\n')
        f.write(iv)

    privatni = rsa.generate_private_key(public_exponent = 65537, key_size = 4096)
    javni = privatni.public_key()
    with open("kljucevi/privatni_kljuc.txt", "wb") as f:
        f.write(
            privatni.private_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm = serialization.NoEncryption()
            )
        )
    with open("kljucevi/javni_kljuc.txt", "wb") as f:
        f.write(
            javni.public_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

def sim_ct(poruka, kljuc):
    tajni, iv = kljuc.split(b'\n-----END KEY-----\n')

    cipher = Cipher(algorithms.AES(tajni), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(poruka) + encryptor.finalize()
    
    os.makedirs("sim", exist_ok=True)
    return ct

def sim_dt(ct, kljuc):
    tajni, iv = kljuc.split(b'\n-----END KEY-----\n')

    cipher = Cipher(algorithms.AES(tajni), modes.CFB(iv))
    decryptor = cipher.decryptor()
    dt = decryptor.update(ct) + decryptor.finalize()
    
    return dt

def asim_ct(poruka, javni):
    ct = javni.encrypt(
        poruka,
        padding.OAEP(
            mgf = padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None
        )
    )

    os.makedirs("asim", exist_ok=True)
    return ct

def asim_dt(ct, privatni):
    dt = privatni.decrypt(
        ct,
        padding.OAEP(
            mgf = padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None
        )
    )
    return dt

def sazmi(poruka):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(poruka)
    sazetak = digest.finalize()

    os.makedirs("potpis", exist_ok=True)
    return sazetak

def potpisi(sazetak, privatni):
    potpis = privatni.sign(
        sazetak,
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return potpis

def provjeri(poruka, javni, potpis):
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(poruka)
    sazetak = digest.finalize()
    """

    try:
        javni.verify(
            potpis,
            poruka,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return "Datoteka je ispravna!"
    except InvalidSignature:
        return "Datoteka je neispravna!"


class Kriptarko:
    def __init__(self, root):
        root.title("Kriptarko")
        root.geometry("480x320")
        mainframe = ttk.Frame(root, padding = "3 3 12 12")
        mainframe.grid(column = 0, row = 0, sticky = (N, W, E, S))
        mainframe.place(relx=.5, rely=.5, anchor= CENTER)
        root.columnconfigure(0, weight = 1)
        root.rowconfigure(0, weight = 1)
        
        self.gen_kljuc_button = ttk.Button(mainframe, text="Generiraj ključeve", command=self.gen_kljuc)
        self.sim_ct_button = ttk.Button(mainframe, text="Kriptiranje", command=self.sim_ct)
        self.sim_dt_button = ttk.Button(mainframe, text="Dekriptiranje", command=self.sim_dt, state="disabled")
        self.asim_ct_button = ttk.Button(mainframe, text="Kriptiranje", command=self.asim_ct)
        self.asim_dt_button = ttk.Button(mainframe, text="Dekriptiranje", command=self.asim_dt, state="disabled")
        self.sazmi_button = ttk.Button(mainframe, text="Izračunaj sažetak", command=self.sazmi)
        self.potpisi_button = ttk.Button(mainframe, text="Potpiši poruku", command=self.potpisi, state="disabled")
        self.provjeri_button = ttk.Button(mainframe, text="Provjeri poruku", command=self.provjeri, state="disabled")
        self.result = StringVar()
        self.rezultat_text = Text(mainframe, height=5, width=50, state="disabled")
        
        self.gen_kljuc_button.grid(column=2, row=1, sticky=(W,E))
        self.sim_ct_button.grid(column=1, row=2, sticky=(W,E))
        self.sim_dt_button.grid(column=3, row=2, sticky=(W,E))
        self.asim_ct_button.grid(column=1, row=3, sticky=(W,E))
        self.asim_dt_button.grid(column=3, row=3, sticky=(W,E))
        self.sazmi_button.grid(column=1, row=4, sticky=(W,E))
        self.potpisi_button.grid(column=2, row=4, sticky=(W,E))
        self.provjeri_button.grid(column=3, row=4, sticky=(W,E))
        self.rezultat_text.grid(column=1, row=6, columnspan=3, sticky=(N,S))
        
        ttk.Label(mainframe, text="<<< Simetrično >>>").grid(column=2, row=2, sticky=(N,S))
        ttk.Label(mainframe, text="<<< Asimetrično >>>").grid(column=2, row=3, sticky=(N,S))
        ttk.Label(mainframe, textvariable=self.result).grid(column=1, row=5, columnspan=3, sticky=(N,S))
        
        for child in mainframe.winfo_children(): 
            child.grid_configure(padx=5, pady=5)
        
    def putanja_poruke(self):
        try:
            putanja = filedialog.askopenfilename(title = "Odaberi poruku", initialdir = "Ivan_Simić_python")
            with open(putanja, "rb") as f:
                return f.read()
        except:
            return None
    
    def putanja_kljuca(self):
        try:
            putanja = filedialog.askopenfilename(title = "Odaberi ključ", initialdir = "kljucevi")
            if os.path.basename(putanja) == "tajni_kljuc.txt":
                with open(putanja, "rb") as f:
                    return f.read()
            elif os.path.basename(putanja) == "javni_kljuc.txt":
                with open(putanja, "rb") as f:
                    return serialization.load_pem_public_key(
                        f.read(),
                    )
            elif os.path.basename(putanja) == "privatni_kljuc.txt":
                with open(putanja, "rb") as f:
                    return serialization.load_pem_private_key(
                        f.read(),
                        password = None,
                    )
            else:
                raise Exception("Datoteka nije ključ!")
        except Exception as e:
            self.result.set(e)
            return None
        
    def putanja_simporuke(self):
        try:
            putanja = filedialog.askopenfilename(title = "Odaberi poruku", initialdir = "sim")
            with open(putanja, "rb") as f:
                return f.read()
        except:
            return None
        
    def putanja_asimporuke(self):
        try:
            putanja = filedialog.askopenfilename(title = "Odaberi poruku", initialdir = "asim")
            with open(putanja, "rb") as f:
                return f.read()
        except:
            return None
        
    def putanja_potpisa(self):
        try:
            putanja = filedialog.askopenfilename(title = "Odaberi poruku", initialdir = "potpis")
            with open(putanja, "rb") as f:
                return f.read()
        except:
            return None
        
    def gen_kljuc(self):
        try:
            gen_kljuc()
            self.result.set("Generiranje uspješno!")
        except Exception as e:
            self.result.set(e)

    def sim_ct(self):
        poruka = self.putanja_poruke()
        if poruka is None:
            return
        kljuc = self.putanja_kljuca()
        if kljuc is None:
            return
        try:
            ct = sim_ct(poruka, kljuc)
            datoteka = filedialog.asksaveasfilename(title = "Spremi poruku", initialdir = "sim")
            if datoteka:
                with open(datoteka, "wb") as f:
                    f.write(ct)
                self.result.set("Simetrično kriptiranje uspješno!")
                self.sim_dt_button["state"] = "normal"
            else:
                return
        except Exception as e:
            self.result.set(e)

    def sim_dt(self):
        poruka = self.putanja_simporuke()
        if poruka is None:
            return
        kljuc = self.putanja_kljuca()
        if kljuc is None:
            return
        try:
            dt = sim_dt(poruka, kljuc)
            datoteka = filedialog.asksaveasfilename(title = "Spremi poruku", initialdir = "sim")
            if datoteka:
                with open(datoteka, "wb") as f:
                    f.write(dt)
            self.result.set("Simetrično dekriptiranje uspješno!")
            self.rezultat_text["state"] = "normal"
            self.rezultat_text.delete(1.0, END)
            self.rezultat_text.insert("end", dt)
            self.rezultat_text["state"] = "disabled"
        except Exception as e:
            self.result.set(e)
        
    def asim_ct(self):
        poruka = self.putanja_poruke()
        if poruka is None:
            return
        kljuc = self.putanja_kljuca()
        if kljuc is None:
            return
        try:
            ct = asim_ct(poruka, kljuc)
            datoteka = filedialog.asksaveasfilename(title = "Spremi poruku", initialdir = "asim")
            if datoteka:
                with open(datoteka, "wb") as f:
                    f.write(ct)
                self.result.set("Simetrično kriptiranje uspješno!")
                self.asim_dt_button["state"] = "normal"
            else:
                return
        except Exception as e:
            self.result.set(e)

    def asim_dt(self):
        poruka = self.putanja_asimporuke()
        if poruka is None:
            return
        kljuc = self.putanja_kljuca()
        if kljuc is None:
            return
        try:
            dt = asim_dt(poruka, kljuc)
            datoteka = filedialog.asksaveasfilename(title = "Spremi poruku", initialdir = "asim")
            if datoteka:
                with open(datoteka, "wb") as f:
                    f.write(dt)
            self.result.set("Simetrično dekriptiranje uspješno!")
            self.rezultat_text["state"] = "normal"
            self.rezultat_text.delete(1.0, END)
            self.rezultat_text.insert("end", dt)
            self.rezultat_text["state"] = "disabled"
        except Exception as e:
            self.result.set(e)

    def sazmi(self):
        poruka = self.putanja_poruke()
        if poruka is None:
            return
        try:
            sazetak = sazmi(poruka)
            datoteka = filedialog.asksaveasfilename(title = "Spremi poruku", initialdir = "potpis")
            if datoteka:
                with open(datoteka, "wb") as f:
                    f.write(sazetak)
                self.result.set("Sažeto!")
                self.potpisi_button["state"] = "normal"
            else:
                return
        except Exception as e:
            self.result.set(e)

    def potpisi(self):
        poruka = self.putanja_poruke()
        if poruka is None:
            return
        kljuc = self.putanja_kljuca()
        if kljuc is None:
            return
        try:
            potpis = potpisi(poruka, kljuc)
            datoteka = filedialog.asksaveasfilename(title = "Spremi poruku", initialdir = "potpis")
            if datoteka:
                with open(datoteka, "wb") as f:
                    f.write(potpis)
                self.result.set("Potpisano!")
                self.provjeri_button["state"] = "normal"
            else:
                return
        except Exception as e:
            self.result.set(e)

    def provjeri(self):
        poruka = self.putanja_poruke()
        if poruka is None:
            return
        kljuc = self.putanja_kljuca()
        if kljuc is None:
            return
        potpis = self.putanja_potpisa()
        if potpis is None:
            return
        try:
            provjera = provjeri(poruka, kljuc, potpis)
            self.result.set(provjera)
        except Exception as e:
            self.result.set(e)

root = Tk()
Kriptarko(root)
root.mainloop()


# In[ ]:




