from flask import Flask, redirect, session, url_for, render_template, request, flash, send_file, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
from datetime import datetime, timedelta, timezone
from pymongo import MongoClient
from bson import ObjectId
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import json
from bson import json_util
from io import BytesIO
import os
import paypalrestsdk

from models import Utente, Registrazione, Login, Profilo, Cassaforte, Credenziali, Feedback, Abbonamento

app = Flask(__name__)
app.secret_key = os.urandom(16)

load_dotenv()

client = MongoClient(os.getenv('MONGODB_URL'))
db = client.passbox

PAYPAL_CLIENT_ID = os.getenv('PAYPAL_CLIENT_ID')
PAYPAL_SECRET = os.getenv('PAYPAL_SECRET')
PAYPAL_MODE = "sandbox"

paypalrestsdk.configure({
    "mode": PAYPAL_MODE,
    "client_id": PAYPAL_CLIENT_ID,
    "client_secret": PAYPAL_SECRET
})

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)




def is_logged_in():
    return 'user_id' in session


@app.route('/')
def homepage():
    if is_logged_in():
        session.permanent = True
        return redirect(url_for('home'))
    return redirect(url_for('login'))



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        password_confirm = request.form['password_confirm']

        registrazione = Registrazione(db)
        if not registrazione.valida_username(username):
            flash('Username già in uso!', 'danger')
            return redirect(url_for('register'))

        if not registrazione.valida_email(email):
            flash('Email già in uso!', 'danger')
            return redirect(url_for('register'))

        if password != password_confirm:
            flash('Le password non coincidono!', 'danger')
            return redirect(url_for('register'))

        utente = Utente(db, username, email, password)
        utente.crea_account()

        saved_user = utente.get_by_username(username)
        session['user_id'] = str(saved_user['_id'])
        return redirect(url_for('confirm_2fa'))

    return render_template('register.html')



@app.route('/login', methods=['POST', 'GET'])
def login():
    if is_logged_in():
        flash('Sei già loggato!')
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        login_manager = Login(db)
        user = login_manager.autenticati(username, password)

        if user:
            session['user_id'] = str(user['_id'])
            return redirect(url_for('verify_2fa'))
        else:
            flash('Username o password errati!', 'danger')

    return render_template('login.html')



@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if not is_logged_in():
        flash('Sessione scaduta!', 'danger')
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    user = db.users.find_one({'_id': ObjectId(user_id)})

    if request.method == 'POST':
        code = request.form['code']
        login_manager = Login(db)
        if login_manager.valida_2fa(user, code):
            return redirect(url_for('home'))
        else:
            flash('Codice errato o scaduto')

    return render_template('verify_2fa.html')



@app.route('/confirm_2fa', methods=['GET', 'POST'])
def confirm_2fa():
    if not is_logged_in():
        flash('Sessione scaduta!', 'danger')
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    user = db.users.find_one({'_id': ObjectId(user_id)})

    seed = Fernet(user['data_key'].encode()).decrypt(user['2fa_seed'].encode()).decode()
    totp = pyotp.TOTP(seed)
    qr_url = totp.provisioning_uri(name=user['username'], issuer_name="Passbox")

    if request.method == 'POST':
        code = request.form['code']
        if totp.verify(code):
            return redirect(url_for('login'))
        else:
            flash('Codice errato o scaduto', 'danger')

    return render_template('confirm_2fa.html', qr_url=qr_url)



@app.route('/profile', methods=['GET', 'POST'])
def profile():
    user_id = session.get('user_id')
    user = db.users.find_one({'_id': ObjectId(user_id)})

    if not user:
        return jsonify({'error': 'Utente non trovato'}), 404

    if request.method == 'POST':
        new_username = request.form.get('username')
        new_email = request.form.get('email')
        new_password = request.form.get('password')

        profilo = Profilo(db)

        if new_username:
            profilo.cambia_username(user_id, new_username)
        if new_email:
            profilo.cambia_email(user_id, new_email)
        if new_password:
            profilo.cambia_password(user_id, new_password)

        flash('Dati aggiornati. Le modifiche saranno attive dal prossimo login.', 'success')
        return redirect(url_for('home'))

    return render_template('profile.html', user=user)



@app.route('/vaults_list', methods=['GET'])
def vaults_list():
    if not is_logged_in():
        flash('Sessione scaduta!', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = db.users.find_one({'_id': ObjectId(user_id)})
    collections = db.list_collection_names()
    user_collections = [col for col in collections if user_id in col]
    return render_template('vaults_list.html', username=user['username'], user_collections=user_collections)



@app.route('/add_credentials/<collection_name>', methods=['POST'])
def add_credentials(collection_name):
    if not is_logged_in():
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = db.users.find_one({'_id': ObjectId(user_id)})
    credenziali = Credenziali(db, collection_name)

    title = request.form['title']
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    url = request.form['url']
    category = request.form['category']

    from cryptography.fernet import Fernet
    encrypted_password = Fernet(user['data_key'].encode()).encrypt(password.encode()).decode()
    encrypted_seed = Fernet(user['data_key'].encode()).encrypt(b'no_seed').decode()

    data = {
        'title': title,
        'username': username,
        'email': email,
        'password': encrypted_password,
        'url': url,
        'category': category,
        '2fa_seed': encrypted_seed,
        'psw_due_date': None
    }
    credenziali.aggiungi_credenziale(data)
    return redirect(url_for('vault_view', collection_name=collection_name))



@app.route('/vault_view/<collection_name>', methods=['GET', 'POST'])
def vault_view(collection_name):
    if not is_logged_in():
        flash('Sessione scaduta!', 'danger')
        return redirect(url_for('login'))

    if collection_name not in db.list_collection_names():
        return redirect(url_for('vaults_list'))

    title = request.args.get('title', '')
    username = request.args.get('username', '')
    email = request.args.get('email', '')
    category = request.args.get('category', '')

    query = {}
    if title:
        query['title'] = {'$regex': title, '$options': 'i'}
    if username:
        query['username'] = {'$regex': username, '$options': 'i'}
    if email:
        query['email'] = {'$regex': email, '$options': 'i'}
    if category:
        query['category'] = {'$regex': category, '$options': 'i'}

    credentials = list(db[collection_name].find(query))
    credentials_count = len(credentials)

    return render_template('vault_view.html', collection_name=collection_name, credentials=credentials, credentials_count=credentials_count)



@app.route('/modify_credential/<collection_name>/<cred_id>', methods=['GET', 'POST'])
def modify_credential(collection_name, cred_id):
    user_id = session.get('user_id')
    user = db.users.find_one({'_id': ObjectId(user_id)})
    credenziali = Credenziali(db, collection_name)

    credentials = db[collection_name].find_one({'_id': ObjectId(cred_id)})
    if not credentials:
        return redirect(url_for('vault_view', collection_name=collection_name))

    if request.method == 'POST':
        title = request.form.get('title')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        url = request.form.get('url')
        category = request.form.get('category')
        seed = request.form.get('2fa_seed')
        psw_due_date = request.form.get('psw_due_date')

        update_data = {}
        if seed:
            encrypted_seed = Fernet(user['data_key'].encode()).encrypt(seed.encode()).decode()
            update_data['2fa_seed'] = encrypted_seed
        if psw_due_date:
            update_data['psw_due_date'] = psw_due_date
        if title or username or email or password or url or category:
            encrypted_password = Fernet(user['data_key'].encode()).encrypt(password.encode()).decode()
            update_data.update({
                'title': title,
                'username': username,
                'email': email,
                'password': encrypted_password,
                'url': url,
                'category': category
            })

        credenziali.modifica_credenziale(cred_id, update_data)

    return redirect(url_for('vault_view', collection_name=collection_name))



@app.route('/generate_otp', methods=['POST'])
def generate_otp():
    user_id = session.get('user_id')
    user = db.users.find_one({'_id': ObjectId(user_id)})

    if user['tipo_utente'] != 'premium':
        return jsonify({"error": "Funzionalità riservata agli utenti premium"}), 403

    data = request.get_json()
    if not data or 'seed' not in data or 'cred_id' not in data or 'coll_name' not in data:
        return jsonify({"error": "Dati incompleti"}), 400

    seed = data['seed']
    collection_name = data['coll_name']
    cred_id = data['cred_id']

    totp = pyotp.TOTP(seed)
    otp = totp.now()
    time_remaining = totp.interval - (int(datetime.now().timestamp()) % totp.interval)
    qr_url = totp.provisioning_uri(name=f"{seed[:5]}...", issuer_name="Passbox")

    encrypted_seed = Fernet(user['data_key'].encode()).encrypt(seed.encode()).decode()
    db[collection_name].update_one({'_id': ObjectId(cred_id)}, {'$set': {'2fa_seed': encrypted_seed}})

    return jsonify({
        "otp": otp,
        "time_remaining": time_remaining,
        "qr_url": qr_url
    })



def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key



@app.route('/export_collection/<collection_name>', methods=['POST'])
def export_collection(collection_name):
    user_password = request.form.get('export_password')
    if not user_password:
        return redirect(url_for('vaults_list'))

    user_id = session.get('user_id')
    user = db.users.find_one({'_id': ObjectId(user_id)})

    if user['tipo_utente'] != 'premium':
        flash("Funzione riservata agli utenti Premium", 'danger')
        return redirect(url_for('vaults_list'))

    salt = bytes.fromhex(user['salt'])
    file_key = derive_key_from_password(user_password, salt)

    data = list(db[collection_name].find())
    export_data = []
    for item in data:
        temp = item.copy()
        temp['password'] = Fernet(user['data_key'].encode()).decrypt(temp['password'].encode()).decode()
        temp['2fa_seed'] = Fernet(user['data_key'].encode()).decrypt(temp['2fa_seed'].encode()).decode()
        export_data.append(temp)

    json_data = json.dumps(export_data, default=json_util.default)
    encrypted_data = Fernet(file_key).encrypt(json_data.encode())

    file_io = BytesIO(encrypted_data)
    file_io.seek(0)
    filename = f"{collection_name.split('_')[1]}_salt-{user['salt']}_backup.json"

    return send_file(file_io, as_attachment=True, download_name=filename, mimetype='application/octet-stream')



@app.route('/create_or_import_collection', methods=['POST'])
def create_or_import_collection():
    user_id = session.get('user_id')
    user = db.users.find_one({'_id': ObjectId(user_id)})
    salt = bytes.fromhex(user['salt'])

    collection_name = request.form['collection_name']
    collection_password = request.form['collection_password']
    action = request.form['action']
    full_collection_name = f"{user_id}_{collection_name}"

    if full_collection_name in db.list_collection_names():
        flash('Nome vault già esistente.', 'danger')
        return redirect(url_for('vaults_list'))

    if action == 'create':
        db.create_collection(full_collection_name)
        return redirect(url_for('vaults_list'))

    elif action == 'import':
        if user['tipo_utente'] != 'premium':
            flash("Import disponibile solo per utenti Premium", 'danger')
            return redirect(url_for('vaults_list'))

        import_file = request.files.get('import_file')
        if not import_file:
            flash("File non caricato", 'danger')
            return redirect(url_for('vaults_list'))

        try:
            file_key = derive_key_from_password(collection_password, salt)
            decrypted_data = Fernet(file_key).decrypt(import_file.read()).decode()
            items = json.loads(decrypted_data, object_hook=json_util.object_hook)

            secure_items = []
            for item in items:
                temp = item.copy()
                temp['password'] = Fernet(user['data_key'].encode()).encrypt(temp['password'].encode()).decode()
                temp['2fa_seed'] = Fernet(user['data_key'].encode()).encrypt(temp['2fa_seed'].encode()).decode()
                secure_items.append(temp)

            if isinstance(secure_items, list):
                db[full_collection_name].insert_many(secure_items)
            else:
                db[full_collection_name].insert_one(secure_items)

            return redirect(url_for('vaults_list'))

        except Exception as e:
            flash("Errore: password errata o file danneggiato", 'danger')
            return redirect(url_for('vaults_list'))



@app.route('/change-password', methods=['POST'])
def change_password():
    user_id = session.get('user_id')
    user = db.users.find_one({'_id': ObjectId(user_id)})
    salt = bytes.fromhex(user['salt'])
    new_password = request.form.get('new_password')

    if not new_password:
        flash('Password non valida.', 'danger')
        return redirect(url_for('profile'))

    new_data_key = derive_key_from_password(new_password, salt)
    for collection in db.list_collection_names():
        if user_id in collection:
            for doc in db[collection].find():
                decrypted_pw = Fernet(user['data_key'].encode()).decrypt(doc['password'].encode()).decode()
                decrypted_seed = Fernet(user['data_key'].encode()).decrypt(doc['2fa_seed'].encode()).decode()
                new_pw = Fernet(new_data_key).encrypt(decrypted_pw.encode()).decode()
                new_seed = Fernet(new_data_key).encrypt(decrypted_seed.encode()).decode()
                db[collection].update_one({'_id': doc['_id']}, {'$set': {'password': new_pw, '2fa_seed': new_seed}})

    decrypted_user_seed = Fernet(user['data_key'].encode()).decrypt(user['2fa_seed'].encode()).decode()
    encrypted_user_seed = Fernet(new_data_key).encrypt(decrypted_user_seed.encode()).decode()
    new_hashed_pw = generate_password_hash(new_password)

    db.users.update_one({'_id': ObjectId(user_id)}, {
        '$set': {
            'password': new_hashed_pw,
            '2fa_seed': encrypted_user_seed,
            'data_key': new_data_key.decode()
        }
    })

    flash("Password aggiornata.", 'success')
    return redirect(url_for('profile'))

# Verifica se l'utente può inviare feedback (1 ogni 30 giorni)
def can_submit_feedback(user_id):
    check_date = datetime.now(timezone.utc) - timedelta(days=30)
    last = db.feedbacks.find_one({"user_id": user_id, "timestamp": {"$gte": check_date}})
    return last is None



@app.route('/delete_collection/<collection_name>', methods=['POST', 'GET'])
def delete_collection(collection_name):
    if not is_logged_in():
        return redirect(url_for('login'))

    user_id = session['user_id']
    if user_id not in collection_name:
        return redirect(url_for('vaults_list'))

    cassaforte = Cassaforte(db, user_id)
    cassaforte.elimina_vault(collection_name.split(f"{user_id}_")[-1])
    return redirect(url_for('vaults_list'))



@app.route('/submit-feedback', methods=['POST'])
def submit_feedback():
    user_id = session.get('user_id')
    user = db.users.find_one({'_id': ObjectId(user_id)})
    username = user['username']

    feedback_message = request.form.get('feedback')
    if not feedback_message or len(feedback_message) > 500:
        return redirect(url_for('home'))

    if not can_submit_feedback(user_id):
        return redirect(url_for('home'))

    feedback = Feedback(db)
    feedback.invia_messaggio(user_id, feedback_message)
    return redirect(url_for('home'))



@app.route('/donate', methods=['POST'])
def donate():
    amount = request.form.get('amount')
    abbonamento = Abbonamento(db)

    payment = paypalrestsdk.Payment({
        "intent": "sale",
        "payer": {"payment_method": "paypal"},
        "redirect_urls": {
            "return_url": url_for('execute_payment', _external=True),
            "cancel_url": url_for('cancel_payment', _external=True)
        },
        "transactions": [{
            "amount": {"total": amount, "currency": "USD"},
            "description": "Donation for the project"
        }]
    })

    if payment.create():
        for link in payment.links:
            if link.rel == "approval_url":
                return redirect(link.href)
    flash('Errore nella creazione del pagamento')
    return redirect(url_for('home'))



@app.route('/payment/execute', methods=['GET'])
def execute_payment():
    payment_id = request.args.get('paymentId')
    payer_id = request.args.get('PayerID')

    payment = paypalrestsdk.Payment.find(payment_id)

    if payment.execute({"payer_id": payer_id}):
        user_id = session.get('user_id')
        abbonamento = Abbonamento(db)
        abbonamento.attiva_premium(user_id)
        flash("Grazie per il tuo supporto! Sei ora un utente Premium.", "success")
        return redirect(url_for('vaults_list'))
    else:
        flash("Errore durante l'esecuzione del pagamento", "danger")
        return redirect(url_for('vaults_list'))



@app.route('/payment/cancel', methods=['GET'])
def cancel_payment():
    flash('Pagamento annullato', 'warning')
    return redirect(url_for('home'))



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))



if __name__ == '__main__':
    app.run(debug=True)
