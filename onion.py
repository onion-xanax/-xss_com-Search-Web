from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import requests
import uuid
import csv
import re
import hashlib
import secrets
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['PERMANENT_SESSION_LIFETIME'] = 3600000

BASE_CSV = 'base.csv'

def init_csv():
    try:
        with open(BASE_CSV, 'x', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['username', 'password_hash', 'salt', 'ip', 'useragent', 'registration_date'])
    except FileExistsError:
        pass

init_csv()

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return salt, password_hash.hex()

def validate_username(username):
    if not username or len(username) < 3 or len(username) > 50:
        return False
    return re.match(r'^[a-zA-Z0-9_]+$', username) is not None

def validate_password(password):
    return len(password) >= 6 if password else False

def sanitize_input(text):
    if not text:
        return ""
    return re.sub(r'[<>"\']', '', text)

@app.route('/')
def index():
    if 'user_id' not in session:
        return render_template('index.html', logged_in=False)
    return render_template('index.html', logged_in=True, session=session)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'Неверный формат данных'})
    
    username = sanitize_input(data.get('username', ''))
    password = data.get('password', '')
    
    if not validate_username(username):
        return jsonify({'success': False, 'message': 'Логин должен содержать только латинские буквы, цифры и подчеркивания (3-50 символов)'})
    
    if not validate_password(password):
        return jsonify({'success': False, 'message': 'Пароль должен быть не менее 6 символов'})
    
    with open(BASE_CSV, 'r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row['username'] == username:
                return jsonify({'success': False, 'message': 'Пользователь уже существует'})
    
    user_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    registration_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    salt, password_hash = hash_password(password)
    
    with open(BASE_CSV, 'a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([
            username,
            password_hash,
            salt,
            user_ip,
            user_agent,
            registration_date
        ])
    
    session['user_id'] = str(uuid.uuid4())
    session['username'] = username
    session.permanent = True
    
    return jsonify({'success': True, 'message': 'Регистрация успешна!'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'Неверный формат данных'})
    
    username = sanitize_input(data.get('username', ''))
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Заполните все поля'})
    
    with open(BASE_CSV, 'r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row['username'] == username:
                salt = row['salt']
                stored_hash = row['password_hash']
                _, calculated_hash = hash_password(password, salt)
                
                if secrets.compare_digest(stored_hash, calculated_hash):
                    session['user_id'] = str(uuid.uuid4())
                    session['username'] = username
                    session.permanent = True
                    return jsonify({'success': True, 'message': 'Вход выполнен!'})
                else:
                    return jsonify({'success': False, 'message': 'Неверный пароль'})
    
    return jsonify({'success': False, 'message': 'Пользователь не найден'})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/search_ip')
def search_ip():
    if 'user_id' not in session:
        return jsonify({'error': 'Требуется авторизация!'}), 403
    
    ip = request.args.get('ip', '')
    if not ip or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return jsonify({'error': 'Неверный формат IP'}), 400
    
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        return jsonify(response.json())
    except requests.RequestException:
        return jsonify({'error': 'Ошибка при запросе к API'}), 500

@app.route('/search_phone')
def search_phone():
    if 'user_id' not in session:
        return jsonify({'error': 'Требуется авторизация!'}), 403
    
    phone = request.args.get('phone', '')
    if not phone or not re.match(r'^\+?[78][-\(]?\d{3}\)?-?\d{3}-?\d{2}-?\d{2}$', phone):
        return jsonify({'error': 'Неверный формат телефона'}), 400
    
    try:
        response = requests.get(
            f"https://api.depsearch.digital/quest={phone}?token=30L5ZJxVhQjNnMynqSYvGND80Gj3Xx7x&lang=ru",
            timeout=10
        )
        return jsonify(response.json())
    except requests.RequestException:
        return jsonify({'error': 'Ошибка при запросе к API'}), 500

@app.route('/search_email')
def search_email():
    if 'user_id' not in session:
        return jsonify({'error': 'Требуется авторизация!'}), 403
    
    email = request.args.get('email', '')
    if not email or not re.match(r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', email):
        return jsonify({'error': 'Неверный формат email'}), 400
    
    try:
        response = requests.get(
            f"https://api.depsearch.digital/quest={email}?token=30L5ZJxVhQjNnMynqSYvGND80Gj3Xx7x&lang=ru",
            timeout=10
        )
        return jsonify(response.json())
    except requests.RequestException:
        return jsonify({'error': 'Ошибка при запросе к API'}), 500

@app.route('/check_auth')
def check_auth():
    return jsonify({'logged_in': 'user_id' in session})

@app.route('/static/<path:filename>')
def static_files(filename):
    return app.send_static_file(filename)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
