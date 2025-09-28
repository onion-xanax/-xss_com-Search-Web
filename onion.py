# onion.py
from flask import Flask, request, jsonify, session, send_file
import requests
import uuid
import csv
import re
import hashlib
import secrets
import os
import json
import phonenumbers
from datetime import datetime
from functools import wraps
import time
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

BASE_CSV = 'base.csv'

RATE_LIMITS = {}
MAX_REQUESTS_PER_MINUTE = 10
MAX_REQUESTS_PER_HOUR = 100

def init_csv():
    try:
        with open(BASE_CSV, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            if 'email' not in reader.fieldnames:
                raise ValueError("Old CSV format")
    except (FileNotFoundError, ValueError):
        with open(BASE_CSV, 'w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['email', 'password_hash', 'salt', 'ip', 'useragent', 'registration_date'])

init_csv()

def rate_limit(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr
        now = time.time()
        
        if ip not in RATE_LIMITS:
            RATE_LIMITS[ip] = {'minute': [], 'hour': []}
        
        minute_requests = [req_time for req_time in RATE_LIMITS[ip]['minute'] if now - req_time < 60]
        hour_requests = [req_time for req_time in RATE_LIMITS[ip]['hour'] if now - req_time < 3600]
        
        if len(minute_requests) >= MAX_REQUESTS_PER_MINUTE:
            return jsonify({'error': 'Слишком много запросов. Попробуйте позже.'}), 429
        if len(hour_requests) >= MAX_REQUESTS_PER_HOUR:
            return jsonify({'error': 'Превышен лимит запросов в час.'}), 429
        
        RATE_LIMITS[ip]['minute'].append(now)
        RATE_LIMITS[ip]['hour'].append(now)
        
        return func(*args, **kwargs)
    return wrapper

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return salt, password_hash.hex()

def validate_email(email):
    if not email or not isinstance(email, str):
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if len(email) > 254:
        return False
    if not re.match(pattern, email):
        return False
    if re.search(r'[<>()\[\]\\;:,]', email):
        return False
    domain = email.split('@')[1]
    if len(domain) < 4:
        return False
    return True

def sanitize_input(text):
    if not text:
        return ""
    text = str(text)
    text = re.sub(r'[<>"\']', '', text)
    text = re.sub(r'[\x00-\x1F\x7F]', '', text)
    text = text.strip()
    return text[:500]

def validate_phone_manual(phone_str):
    cleaned = re.sub(r'[^\d+]', '', phone_str)
    if not cleaned:
        return None, None, None
    patterns = [
        (r'^\+7(\d{10})$', '+7 {} {} {}', [0, 3, 3, 4]),
        (r'^8(\d{10})$', '+7 {} {} {}', [0, 3, 3, 4]),
        (r'^(\d{10})$', '+7 {} {} {}', [0, 3, 3, 4]),
    ]
    for pattern, format_template, groups in patterns:
        match = re.match(pattern, cleaned)
        if match:
            formatted = format_template.format(*[match.group(i) for i in groups if i < len(match.groups()) + 1])
            digits_only = re.sub(r'\D', '', formatted)
            if len(digits_only) not in [10, 11, 12]:
                continue
            russian_operators = {
                '79': 'МТС', '91': 'МТС', '98': 'МТС',
                '90': 'Билайн', '96': 'Билайн',
                '92': 'МегаФон', '93': 'МегаФон', '95': 'МегаФон',
                '98': 'ЮТел', '99': 'ЮТел',
            }
            operator = "Неизвестный оператор"
            for prefix, op in russian_operators.items():
                if digits_only.startswith(prefix):
                    operator = op
                    break
            return formatted, operator, "Россия"
    return None, None, None

def extract_phones_from_text(text):
    found_phones = []
    if not text or not isinstance(text, str):
        return found_phones
    patterns = [
        r'\+7\s?[\(\-]?\d{3}[\)\-]?\s?\d{3}[\-]?\d{2}[\-]?\d{2}', 
        r'8\s?[\(\-]?\d{3}[\)\-]?\s?\d{3}[\-]?\d{2}[\-]?\d{2}',   
        r'\b\d{3}[\-]\d{3}[\-]\d{2}[\-]\d{2}\b',                  
        r'\b\d{11,15}\b',                                        
    ]
    for pattern in patterns:
        matches = re.finditer(pattern, text)
        for match in matches:
            phone_str = match.group()
            formatted, operator, region = validate_phone_manual(phone_str)
            if formatted:
                phone_info = {
                    'number': formatted,
                    'operator': operator,
                    'region': region,
                    'original': phone_str
                }
                if not any(p['number'] == formatted for p in found_phones):
                    found_phones.append(phone_info)
    return found_phones

def create_search_report(query, data, search_type="phone"):
    names_data = []
    phones_data = []
    emails_data = []
    formatted_results = []
    
    try:
        json_data = json.loads(data)
        if 'results' in json_data and json_data['results']:
            for result in json_data['results']:
                source = sanitize_input(result.get('🏫Источник', 'Неизвестный источник'))
                formatted_result = f'<div class="database-block">'
                formatted_result += f'<div class="database-header">📊 База: <span class="source-highlight">{source}</span></div>'
                keys = [k for k in result.keys() if k != '🏫Источник']
                for j, key in enumerate(keys):
                    value = sanitize_input(result.get(key, ''))
                    if value:
                        prefix = "├" if j < len(keys) - 1 else "└"
                        formatted_result += f'<div class="data-line">{prefix} <span class="key">{sanitize_input(key)}:</span> <span class="value">{value}</span></div>'
                formatted_result += '</div>'
                formatted_results.append(formatted_result)
                name_fields = ['👤Фамилия', '👤Имя', '👤Отчество', '👤ФИО', '🔸Никнейм']
                for field in name_fields:
                    if field in result and result[field]:
                        names_data.append(f"{field}: {sanitize_input(result[field])}")
                for key, value in result.items():
                    if isinstance(value, str):
                        found_phones = extract_phones_from_text(value)
                        for phone_info in found_phones:
                            if not any(p['number'] == phone_info['number'] for p in phones_data):
                                if len(phones_data) < 5:
                                    phones_data.append(phone_info)
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                for key, value in result.items():
                    if isinstance(value, str):
                        emails_found = re.findall(email_pattern, value)
                        for email in emails_found:
                            if validate_email(email):
                                emails_data.append(f"{sanitize_input(key)}: {email}")
    except Exception as e:
        formatted_results = [f'<div class="database-block"><div class="database-header">📊 Raw данные</div><div class="data-line">└ <span class="value">{sanitize_input(data)}</span></div></div>']

    if search_type == "phone":
        title = f"Результаты поиска по номеру {sanitize_input(query)}"
        format_data = "Номер телефона"
        icon = "📱"
    elif search_type == "email":
        title = f"Результаты поиска по почте {sanitize_input(query)}"
        format_data = "Email"
        icon = "✉️"
    elif search_type == "vk":
        title = f"Результаты поиска по Вконтакте {sanitize_input(query)}"
        format_data = "VK"
        icon = "🔵"
    elif search_type == "ok":
        title = f"Результаты поиска по Одноклассникам {sanitize_input(query)}"
        format_data = "OK"
        icon = "🟠"
    elif search_type == "fc":
        title = f"Результаты поиска по Facebook {sanitize_input(query)}"
        format_data = "Facebook"
        icon = "🔷"
    elif search_type == "inn":
        title = f"Результаты поиска по ИНН {sanitize_input(query)}"
        format_data = "ИНН"
        icon = "🔢"
    elif search_type == "snils":
        title = f"Результаты поиска по СНИЛС {sanitize_input(query)}"
        format_data = "СНИЛС"
        icon = "🆔"
    elif search_type == "nick":
        title = f"Результаты поиска по нику {sanitize_input(query)}"
        format_data = "Никнейм"
        icon = "🔸"
    elif search_type == "ogrn":
        title = f"Результаты поиска по ОГРН {sanitize_input(query)}"
        format_data = "ОГРН"
        icon = "📊"
    else:
        title = f"Результаты поиска {sanitize_input(query)}"
        format_data = "Неизвестно"
        icon = "🔍"

    html_content = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Report - {sanitize_input(query)}</title>
    <link rel="stylesheet" href="/onion.css">
    <script src="https://cdn.jsdelivr.net/npm/particles.js@2.0.0/particles.min.js"></script>
    <style>
        .report-container {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: transparent;
            z-index: 1000;
            overflow-y: auto;
        }}
        .report-header {{
            background: linear-gradient(145deg, rgba(40, 40, 40, 0.95), rgba(25, 25, 25, 0.98));
            padding: 20px;
            border-bottom: 1px solid rgba(0, 255, 136, 0.2);
            backdrop-filter: blur(10px);
            margin: 20px;
            border-radius: 16px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        .report-content {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
        }}
        .back-btn {{
            background: linear-gradient(135deg, #00ff88, #00cc6a);
            color: #000;
            border: none;
            padding: 12px 24px;
            border-radius: 12px;
            font-weight: 600;
            cursor: pointer;
            margin-bottom: 20px;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .back-btn:hover {{
            background: linear-gradient(135deg, #00cc6a, #00aa55);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0, 255, 136, 0.4);
        }}
        .stats-grid {{
            grid-column: 1 / -1;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .stat-card {{
            background: linear-gradient(145deg, rgba(40, 40, 40, 0.8), rgba(25, 25, 25, 0.9));
            border-radius: 16px;
            padding: 20px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            transition: all 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94);
        }}
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 15px 40px rgba(0, 255, 136, 0.2), 0 0 0 1px rgba(0, 255, 136, 0.1);
        }}
        .stat-number {{
            font-size: 2em;
            font-weight: 700;
            background: linear-gradient(135deg, #00ff88, #00cc6a);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin: 10px 0;
        }}
        .main-data-section {{
            background: linear-gradient(145deg, rgba(40, 40, 40, 0.8), rgba(25, 25, 25, 0.9));
            border-radius: 16px;
            padding: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            margin-bottom: 20px;
            transition: all 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94);
            width: 900px;
            max-height: 600px;
            overflow-y: auto;
        }}
        .main-data-section:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }}
        .database-block {{
            background: linear-gradient(145deg, rgba(50, 50, 50, 0.6), rgba(35, 35, 35, 0.7));
            border-radius: 12px;
            padding: 15px;
            border: 1px solid rgba(255, 255, 255, 0.05);
            margin-bottom: 15px;
        }}
        .database-header {{
            color: #00ff88;
            font-size: 1.1em;
            font-weight: 600;
            margin-bottom: 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding-bottom: 8px;
        }}
        .source-highlight {{
            color: #ff6b6b;
            font-weight: 600;
        }}
        .data-line {{
            margin: 6px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            line-height: 1.4;
            color: #ffffff;
            padding: 4px;
            border-radius: 4px;
            transition: background-color 0.3s ease;
        }}
        .data-line:hover {{
            background: rgba(255, 255, 255, 0.05);
        }}
        .key {{
            color: #00ff88;
            font-weight: 500;
        }}
        .value {{
            color: #ffffff;
        }}
        .phone-operator {{
            color: #00ff88;
            font-size: 0.8em;
            margin-left: 10px;
            background: rgba(0, 255, 136, 0.1);
            padding: 2px 6px;
            border-radius: 4px;
        }}
        .phone-region {{
            color: #0088ff;
            font-size: 0.8em;
            margin-left: 5px;
            background: rgba(0, 136, 255, 0.1);
            padding: 2px 6px;
            border-radius: 4px;
        }}
        .no-data {{
            text-align: center;
            color: rgba(255, 255, 255, 0.5);
            font-style: italic;
            padding: 20px;
        }}
        .data-section {{
            background: linear-gradient(145deg, rgba(40, 40, 40, 0.8), rgba(25, 25, 25, 0.9));
            border-radius: 16px;
            padding: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            margin-bottom: 20px;
            transition: all 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94);
        }}
        .data-section:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }}
        .section-title {{
            color: #00ff88;
            font-size: 1.2em;
            font-weight: 600;
            margin-bottom: 15px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        @media (max-width: 1024px) {{
            .report-content {{
                grid-template-columns: 1fr;
            }}
            .main-data-section {{
                width: 100%;
                max-width: 100%;
            }}
        }}
    </style>
</head>
<body>
    <div id="particles-js"></div>
    
    <div class="report-container">
        <div class="report-header">
            <button class="back-btn" onclick="closeReport()">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                    <path d="M11.354 1.646a.5.5 0 0 1 0 .708L5.707 8l5.647 5.646a.5.5 0 0 1-.708.708l-6-6a.5.5 0 0 1 0-.708l6-6a.5.5 0 0 1 .708 0z"/>
                </svg>
                Назад к поиску
            </button>
            <h1 style="color: #00ff88; margin: 0; display: flex; align-items: center; gap: 10px;">
                <span>{icon}</span>
                <span>{title}</span>
            </h1>
        </div>
        
        <div class="report-content">
            <div class="stats-grid">
                <div class="stat-card">
                    <div style="color: rgba(255, 255, 255, 0.7);">📊 Всего записей</div>
                    <div class="stat-number" id="totalCount">{len(formatted_results)}</div>
                </div>
                <div class="stat-card">
                    <div style="color: rgba(255, 255, 255, 0.7);">👤 Имен</div>
                    <div class="stat-number" id="nameCount">{len(names_data)}</div>
                </div>
                <div class="stat-card">
                    <div style="color: rgba(255, 255, 255, 0.7);">📱 Телефонов</div>
                    <div class="stat-number" id="phoneCount">{len(phones_data)}</div>
                </div>
                <div class="stat-card">
                    <div style="color: rgba(255, 255, 255, 0.7);">📨 Email</div>
                    <div class="stat-number" id="emailCount">{len(emails_data)}</div>
                </div>
            </div>
            
            <div class="left-column">
                <div class="main-data-section">
                    <div class="section-title">
                        <span>📋</span>
                        <span>Основные данные</span>
                    </div>
                    {"".join(formatted_results) or '<div class="no-data">Данные не найдены</div>'}
                </div>
            </div>
            
            <div class="right-column">
                <div class="data-section">
                    <div class="section-title">
                        <span>ℹ️</span>
                        <span>Информация</span>
                    </div>
                    <div class="data-line">• Запрос: {sanitize_input(query)}</div>
                    <div class="data-line">• Время: <span id="currentTime"></span></div>
                    <div class="data-line">• Найдено баз: {len(formatted_results)}</div>
                </div>
                
                <div class="data-section">
                    <div class="section-title">
                        <span>📞</span>
                        <span>Телефоны</span>
                    </div>
                    {"".join([f'<div class="data-line">• {phone["number"]}<span class="phone-operator">{phone["operator"]}</span><span class="phone-region">{phone["region"]}</span></div>' for phone in phones_data]) or '<div class="no-data">Телефоны не найдены</div>'}
                </div>
                
                <div class="data-section">
                    <div class="section-title">
                        <span>📧</span>
                        <span>Email адреса</span>
                    </div>
                    {"".join([f'<div class="data-line">• {email}</div>' for email in emails_data[:5]]) or '<div class="no-data">Email не найдены</div>'}
                </div>
            </div>
        </div>
    </div>

    <script>
        particlesJS('particles-js', {{
            particles: {{
                number: {{ value: 80, density: {{ enable: true, value_area: 800 }} }},
                color: {{ value: '#00ff88' }},
                opacity: {{ value: 0.5, random: true, anim: {{ enable: true, speed: 1 }} }},
                size: {{ value: 3, random: true, anim: {{ enable: true, speed: 2 }} }},
                line_linked: {{ enable: true, distance: 150, color: '#00ff88', opacity: 0.2, width: 1 }},
                move: {{ enable: true, speed: 1, direction: 'none', random: true }}
            }},
            interactivity: {{
                detect_on: 'canvas',
                events: {{ onhover: {{ enable: true, mode: 'grab' }}, onclick: {{ enable: true, mode: 'push' }} }},
                modes: {{ grab: {{ distance: 200, line_linked: {{ opacity: 0.3 }} }}, push: {{ particles_nb: 4 }} }}
            }},
            retina_detect: true
        }});
        
        document.getElementById('currentTime').textContent = new Date().toLocaleString();
        
        function closeReport() {{
            window.close();
        }}
        
        function animateCounter(elementId, finalValue, duration = 1000) {{
            let element = document.getElementById(elementId);
            let start = 0;
            let increment = finalValue / (duration / 16);
            let current = 0;
            
            function update() {{
                current += increment;
                if (current < finalValue) {{
                    element.textContent = Math.floor(current);
                    requestAnimationFrame(update);
                }} else {{
                    element.textContent = finalValue;
                }}
            }}
            update();
        }}
        
        setTimeout(() => {{
            animateCounter('totalCount', {len(formatted_results)});
            animateCounter('nameCount', {len(names_data)});
            animateCounter('phoneCount', {len(phones_data)});
            animateCounter('emailCount', {len(emails_data)});
        }}, 500);
        
        document.addEventListener('DOMContentLoaded', function() {{
            const elements = document.querySelectorAll('.database-block, .data-section, .stat-card, .main-data-section');
            elements.forEach((element, index) => {{
                element.style.opacity = '0';
                element.style.transform = 'translateY(20px)';
                setTimeout(() => {{
                    element.style.transition = 'all 0.5s ease';
                    element.style.opacity = '1';
                    element.style.transform = 'translateY(0)';
                }}, index * 100);
            }});
        }});
    </script>
</body>
</html>
"""
    return html_content

@app.route('/')
@limiter.limit("10 per minute")
def index():
    return send_file('onion.html')

@app.route('/onion.css')
@limiter.limit("20 per minute")
def serve_css():
    return send_file('onion.css', mimetype='text/css')

@app.route('/onion.js')
@limiter.limit("20 per minute")
def serve_js():
    return send_file('onion.js', mimetype='application/javascript')

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
@rate_limit
def register():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'Некорректные данные'})
    
    email = sanitize_input(data.get('email', '')).lower().strip()
    password = data.get('password', '')
    
    if not validate_email(email):
        return jsonify({'success': False, 'message': 'Неверный формат email адреса'})
    
    if len(password) < 6:
        return jsonify({'success': False, 'message': 'Пароль должен содержать минимум 6 символов'})
    
    try:
        with open(BASE_CSV, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row.get('email') == email:
                    return jsonify({'success': False, 'message': 'Пользователь с таким email уже существует'})
    except FileNotFoundError:
        pass
    
    salt, password_hash = hash_password(password)
    with open(BASE_CSV, 'a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([
            email, password_hash, salt, 
            request.remote_addr, request.headers.get('User-Agent', ''),
            datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    session['user_id'] = str(uuid.uuid4())
    session['email'] = email
    return jsonify({'success': True, 'message': 'Регистрация успешна!'})

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
@rate_limit
def login():
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'Некорректные данные'})
    
    email = sanitize_input(data.get('email', '')).lower().strip()
    password = data.get('password', '')
    
    if not validate_email(email):
        return jsonify({'success': False, 'message': 'Неверный формат email адреса'})
    
    try:
        with open(BASE_CSV, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                if row.get('email') == email:
                    _, calculated_hash = hash_password(password, row.get('salt'))
                    if secrets.compare_digest(row.get('password_hash', ''), calculated_hash):
                        session['user_id'] = str(uuid.uuid4())
                        session['email'] = email
                        return jsonify({'success': True, 'message': 'Вход выполнен!'})
                    return jsonify({'success': False, 'message': 'Неверный пароль'})
    except FileNotFoundError:
        pass
    
    return jsonify({'success': False, 'message': 'Пользователь не найден'})

@app.route('/logout')
@limiter.limit("10 per minute")
def logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/check_auth')
@limiter.limit("20 per minute")
def check_auth():
    return jsonify({'logged_in': 'user_id' in session})

@app.route('/get_user_info')
@limiter.limit("20 per minute")
def get_user_info():
    if 'user_id' in session:
        return jsonify({'email': session.get('email', 'Гость')})
    return jsonify({'email': 'Гость'})

@app.route('/search_<search_type>')
@limiter.limit("10 per minute")
@rate_limit
def search(search_type):
    if 'user_id' not in session:
        return jsonify({'error': 'Требуется авторизация'}), 403
    
    query = request.args.get(search_type, '')
    if not query:
        return jsonify({'error': 'Пустой запрос'}), 400
    
    query = sanitize_input(query)
    
    try:
        if search_type == "nick":
            github_data = requests.get(f"https://api.github.com/users/{query}", timeout=10)
            social_links = {
                "ВКонтакте": f"https://vk.com/{query}",
                "GitHub": f"https://github.com/{query}",
                "Twitch": f"https://twitch.tv/{query}",
                "Steam": f"https://steamcommunity.com/id/{query}",
                "Pinterest": f"https://pinterest.com/{query}",
                "DevTo": f"https://dev.to/{query}",
                "Producthunt": f"https://www.producthunt.com/@{query}"
            }
            
            results = []
            if github_data.status_code == 200:
                github_json = github_data.json()
                results.append({
                    "🏫Источник": "GitHub",
                    "👤Логин": github_json.get('login'),
                    "🏢Компания": github_json.get('company'),
                    "📍Местоположение": github_json.get('location'),
                    "🌐Веб-сайт": github_json.get('blog'),
                    "📂Публичные репозитории": github_json.get('public_repos'),
                    "🎁Подарки": github_json.get('public_gists'),
                    "👥Подписчики": github_json.get('followers'),
                    "🔔Подписки": github_json.get('following'),
                    "📅Создан": github_json.get('created_at'),
                    "🔄Обновлен": github_json.get('updated_at'),
                    "🔧Тип": github_json.get('type'),
                    "🔗Профиль": github_json.get('html_url')
                })
            
            for platform, url in social_links.items():
                try:
                    response = requests.head(url, timeout=5, allow_redirects=True)
                    if response.status_code == 200:
                        results.append({
                            "🏫Источник": platform,
                            "👤Профиль": url,
                            "🔗Ссылка": url
                        })
                except:
                    continue
            
            response_data = {"results": results}
            
        elif search_type == "ogrn":
            ofdata_response = requests.get(
                f"https://api.ofdata.ru/v2/company?key=DiC9ALodH5T12BfR&ogrn={query}",
                timeout=10
            )
            if ofdata_response.status_code == 200:
                ofdata_json = ofdata_response.json()
                results = [{
                    "🏫Источник": "OFDATA",
                    "📊ОГРН": ofdata_json.get('data', {}).get('ОГРН'),
                    "🔢ИНН": ofdata_json.get('data', {}).get('ИНН'),
                    "🏢Наименование": ofdata_json.get('data', {}).get('НаимПолн'),
                    "📍Адрес": ofdata_json.get('data', {}).get('ЮрАдрес', {}).get('АдресРФ'),
                    "📅Дата регистрации": ofdata_json.get('data', {}).get('ДатаРег'),
                    "👤Руководитель": ofdata_json.get('data', {}).get('Руковод', [{}])[0].get('ФИО') if ofdata_json.get('data', {}).get('Руковод') else None,
                    "💼Статус": ofdata_json.get('data', {}).get('Статус', {}).get('Наим'),
                    "📞Телефоны": ", ".join(ofdata_json.get('data', {}).get('Контакты', {}).get('Тел', [])),
                    "📧Email": ", ".join(ofdata_json.get('data', {}).get('Контакты', {}).get('Емэйл', []))
                }]
                response_data = {"results": results}
            else:
                response_data = {"results": []}
        else:
            response = requests.get(
                f"https://api.depsearch.digital/quest={query}?token=30L5ZJxVhQjNnMynqSYvGND80Gj3Xx7x&lang=ru",
                timeout=10
            )
            response_data = response.json()
        
        report_html = create_search_report(query, json.dumps(response_data), search_type)
        return report_html
        
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Ошибка API: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Внутренняя ошибка: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
