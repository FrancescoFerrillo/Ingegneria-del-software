from datetime import datetime
import pyotp, secrets, string
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId

from app import derive_key_from_password, os, Fernet



class Utente:
    def __init__(self, db, username, email, password, tipo_utente="standard"):
        self.db = db
        self.username = username
        self.email = email
        self.password = generate_password_hash(password)
        self.tipo_utente = tipo_utente
        self.salt = None
        self.data_key = None
        self.otp_seed = None

    def crea_account(self):
        salt = os.urandom(16)
        self.salt = salt.hex()
        self.data_key = derive_key_from_password(self.password, salt).decode()
        secret = pyotp.random_base32()
        encrypted_seed = Fernet(self.data_key.encode()).encrypt(secret.encode()).decode()
        self.otp_seed = encrypted_seed

        self.db.users.insert_one({
            'username': self.username,
            'email': self.email,
            'password': self.password,
            'salt': self.salt,
            'data_key': self.data_key,
            '2fa_seed': self.otp_seed,
            'tipo_utente': self.tipo_utente
        })

    def is_premium(self):
        return self.tipo_utente == "premium"

    def get_by_username(self, username):
        return self.db.users.find_one({"username": username})

    def get_by_id(self, user_id):
        return self.db.users.find_one({"_id": ObjectId(user_id)})

class Registrazione:
    def __init__(self, db):
        self.db = db

    def valida_username(self, username):
        return not self.db.users.find_one({"username": username})

    def valida_email(self, email):
        return not self.db.users.find_one({"email": email})

    def valida_password(self, password):
        return len(password) >= 8

    def genera_seed_2fa(self):
        return pyotp.random_base32()

class Login:
    def __init__(self, db):
        self.db = db

    def autenticati(self, username, password):
        user = self.db.users.find_one({"username": username})
        if user and check_password_hash(user['password'], password):
            return user
        return None

    def valida_2fa(self, user, code):
        seed = Fernet(user['data_key'].encode()).decrypt(user['2fa_seed'].encode()).decode()
        return pyotp.TOTP(seed).verify(code)

class Profilo:
    def __init__(self, db):
        self.db = db

    def cambia_password(self, user_id, password):
        hashed = generate_password_hash(password)
        self.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'password': hashed}})

    def cambia_username(self, user_id, username):
        self.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'username': username}})

    def cambia_email(self, user_id, email):
        self.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'email': email}})

class Cassaforte:
    def __init__(self, db, user_id):
        self.db = db
        self.user_id = user_id

    def crea_vault(self, name):
        collection_name = f"{self.user_id}_{name}"
        self.db.create_collection(collection_name)

    def elimina_vault(self, name):
        self.db.drop_collection(f"{self.user_id}_{name}")

    def importa_vault_criptato(self, name, data):
        collection = self.db[f"{self.user_id}_{name}"]
        collection.insert_many(data)

    def esporta_vault_criptato(self, name):
        return list(self.db[f"{self.user_id}_{name}"].find())

class Credenziali:
    def __init__(self, db, collection_name):
        self.db = db
        self.collection = db[collection_name]

    def aggiungi_credenziale(self, data):
        self.collection.insert_one(data)

    def elimina_credenziale(self, cred_id):
        self.collection.delete_one({"_id": ObjectId(cred_id)})

    def modifica_credenziale(self, cred_id, data):
        self.collection.update_one({"_id": ObjectId(cred_id)}, {"$set": data})

class Feedback:
    def __init__(self, db):
        self.db = db

    def invia_messaggio(self, user_id, messaggio):
        self.db.feedbacks.insert_one({
            "user_id": user_id,
            "message": messaggio,
            "timestamp": datetime.utcnow()
        })

class Abbonamento:
    def __init__(self, db):
        self.db = db

    def attiva_premium(self, user_id):
        self.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"tipo_utente": "premium", "data_inizio": datetime.utcnow()}})

class PagamentoPaypal:
    def __init__(self, email, password, id_transazione):
        self.email = email
        self.password = password
        self.id_transazione = id_transazione

    def effettua_transazione(self):
        return True

    def genera_ricevuta(self):
        return f"Ricevuta-{self.id_transazione}"

class GeneratorePassword:
    @staticmethod
    def genera_password_sicura():
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(characters) for _ in range(16))

    @staticmethod
    def copia_password(password):
        return password
