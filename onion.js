// onion.js
particlesJS('particles-js', {
    particles: {
        number: { value: 80, density: { enable: true, value_area: 800 }},
        color: { value: '#00ff88' },
        opacity: { value: 0.5, random: true, anim: { enable: true, speed: 1 }},
        size: { value: 3, random: true, anim: { enable: true, speed: 2 }},
        line_linked: { enable: true, distance: 150, color: '#00ff88', opacity: 0.2, width: 1 },
        move: { enable: true, speed: 1, direction: 'none', random: true }
    },
    interactivity: {
        detect_on: 'canvas',
        events: { onhover: { enable: true, mode: 'grab' }, onclick: { enable: true, mode: 'push' }},
        modes: { grab: { distance: 200, line_linked: { opacity: 0.3 }}, push: { particles_nb: 4 }}
    },
    retina_detect: true
});

document.addEventListener('DOMContentLoaded', function() {
    const authModal = document.getElementById('authModal');
    const mainInterface = document.querySelector('.main-interface');
    const loginBtn = document.getElementById('loginBtn');
    const registerBtn = document.getElementById('registerBtn');
    const logoutBtn = document.getElementById('logoutBtn');
    const authMessage = document.getElementById('authMessage');
    const userEmail = document.getElementById('userEmail');

    checkAuthStatus();

    loginBtn.addEventListener('click', function() {
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        
        if (!validateEmail(email)) {
            showAuthMessage('Пожалуйста, введите корректный email адрес', 'error');
            return;
        }
        
        authenticate('/login', email, password);
    });

    registerBtn.addEventListener('click', function() {
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        
        if (!validateEmail(email)) {
            showAuthMessage('Пожалуйста, введите корректный email адрес', 'error');
            return;
        }
        
        if (password.length < 6) {
            showAuthMessage('Пароль должен содержать минимум 6 символов', 'error');
            return;
        }
        
        authenticate('/register', email, password);
    });

    function validateEmail(email) {
        const pattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        return pattern.test(email) && email.length <= 254;
    }

    const emailInput = document.getElementById('email');
    emailInput.addEventListener('input', function() {
        if (this.value) {
            if (!validateEmail(this.value)) {
                this.style.borderColor = '#ff6b6b';
                this.style.boxShadow = '0 0 0 3px rgba(255, 107, 107, 0.2)';
            } else {
                this.style.borderColor = '#00ff88';
                this.style.boxShadow = '0 0 0 3px rgba(0, 255, 136, 0.2)';
            }
        } else {
            this.style.borderColor = 'rgba(255, 255, 255, 0.2)';
            this.style.boxShadow = 'none';
        }
    });

    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            e.preventDefault();
            fetch('/logout', { method: 'GET' })
                .then(() => {
                    location.reload();
                });
        });
    }

    function authenticate(endpoint, email, password) {
        fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                showAuthMessage(data.message, 'error');
            }
        })
        .catch(error => {
            showAuthMessage('Ошибка сети', 'error');
        });
    }

    function checkAuthStatus() {
        fetch('/check_auth')
            .then(response => response.json())
            .then(data => {
                if (data.logged_in) {
                    authModal.style.display = 'none';
                    mainInterface.style.display = 'block';
                    getUserInfo();
                } else {
                    authModal.style.display = 'flex';
                    mainInterface.style.display = 'none';
                }
            });
    }

    function getUserInfo() {
        fetch('/get_user_info')
            .then(response => response.json())
            .then(data => {
                if (data.email) {
                    userEmail.textContent = data.email;
                }
            })
            .catch(() => {});
    }

    function showAuthMessage(message, type) {
        authMessage.textContent = message;
        authMessage.className = `auth-message ${type}`;
        setTimeout(() => {
            authMessage.textContent = '';
            authMessage.className = 'auth-message';
        }, 3000);
    }

    const searchButtons = document.querySelectorAll('.search-btn');
    
    searchButtons.forEach(button => {
        button.addEventListener('click', function() {
            const square = this.closest('.square');
            const input = square.querySelector('.search-input');
            const title = square.querySelector('.square-title').textContent;
            
            if (input.value.trim()) {
                performSearch(input.value, title);
            } else {
                showNotification('Введите данные для поиска', 'error');
            }
        });
        
        const input = button.previousElementSibling;
        input.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                button.click();
            }
        });
    });

    function performSearch(query, type) {
        const searchType = type.toLowerCase()
            .replace('search by ', '')
            .replace(' ', '_')
            .replace('.ru', '');
        
        showNotification(`🔍 Поиск ${type}: ${query}`, 'info');
        
        fetch(`/search_${searchType}?${searchType}=${encodeURIComponent(query)}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error('Ошибка сети');
                }
                return response.text();
            })
            .then(html => {
                const newWindow = window.open('', '_blank');
                newWindow.document.write(html);
                newWindow.document.close();
            })
            .catch(error => {
                showNotification('Ошибка при поиске: ' + error.message, 'error');
            });
    }

    function showNotification(message, type) {
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            background: ${type === 'error' ? 'linear-gradient(135deg, #ff6b6b, #ff4757)' : 'linear-gradient(135deg, #00ff88, #00cc6a)'};
            color: #000;
            padding: 12px 24px;
            border-radius: 12px;
            font-weight: 600;
            z-index: 1000;
            box-shadow: 0 8px 25px ${type === 'error' ? 'rgba(255, 107, 107, 0.3)' : 'rgba(0, 255, 136, 0.3)'};
            animation: slideDown 0.3s ease;
        `;
        
        notification.textContent = message;
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideUp 0.3s ease';
            setTimeout(() => {
                if (notification.parentNode) {
                    document.body.removeChild(notification);
                }
            }, 300);
        }, 3000);
    }
});

const style = document.createElement('style');
style.textContent = `
    @keyframes slideDown {
        from { transform: translateX(-50%) translateY(-100%); opacity: 0; }
        to { transform: translateX(-50%) translateY(0); opacity: 1; }
    }
    
    @keyframes slideUp {
        from { transform: translateX(-50%) translateY(0); opacity: 1; }
        to { transform: translateX(-50%) translateY(-100%); opacity: 0; }
    }
`;
document.head.appendChild(style);
