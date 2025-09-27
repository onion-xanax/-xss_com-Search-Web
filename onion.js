document.addEventListener('DOMContentLoaded', () => {
    if (window.particlesJS) {
        window.particlesJS('particles-js', {
            "particles": {
                "number": { "value": 100, "density": { "enable": true, "value_area": 800 } },
                "color": { "value": "#ffffff" },
                "shape": { "type": "circle" },
                "opacity": { "value": 0.7, "random": true },
                "size": { "value": 3, "random": true },
                "line_linked": { "enable": true, "distance": 150, "color": "#ffffff", "opacity": 0.4 },
                "move": { "enable": true, "speed": 2, "direction": "none", "random": true }
            },
            "interactivity": {
                "events": {
                    "onhover": { "enable": true, "mode": "repulse" },
                    "onclick": { "enable": true, "mode": "push" }
                }
            }
        });
    }

    const searchInput = document.querySelector('.search-input');
    const searchButton = document.querySelector('.search-button');
    const resultContainer = document.getElementById('result');
    const registerButton = document.getElementById('registerButton');
    const loginButton = document.getElementById('loginButton');
    const logoutButton = document.getElementById('logoutButton');
    const modal = document.getElementById('authModal');
    const closeModal = document.querySelector('.close');
    const modalTitle = document.getElementById('modalTitle');
    const submitAuth = document.getElementById('submitAuth');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');

    let currentAuthMode = 'login';

    function isValidIP(ip) {
        const ipRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        return ipRegex.test(ip);
    }

    function isValidPhone(phone) {
        const phoneRegex = /^\+?[78][-\(]?\d{3}\)?-?\d{3}-?\d{2}-?\d{2}$/;
        return phoneRegex.test(phone);
    }

    function isValidEmail(email) {
        const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        return emailRegex.test(email) && email.length <= 254;
    }

    function detectQueryType(query) {
        if (isValidIP(query)) return 'ip';
        if (isValidPhone(query)) return 'phone';
        if (isValidEmail(query)) return 'email';
        return null;
    }

    function searchByIP(ip) {
        fetch(`/search_ip?ip=${encodeURIComponent(ip)}`)
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    showError(data.error);
                } else if (data.status === 'fail') {
                    showError(data.message);
                } else {
                    showIPResult(data);
                }
            })
            .catch(error => showError('Ошибка сети: ' + error.message));
    }

    function searchByPhone(phone) {
        fetch(`/search_phone?phone=${encodeURIComponent(phone)}`)
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    showError(data.error);
                } else if (data.results && data.results.length > 0) {
                    showPhoneResult(data.results);
                } else {
                    showError("Ничего не найдено.");
                }
            })
            .catch(error => showError('Ошибка сети: ' + error.message));
    }

    function searchByEmail(email) {
        fetch(`/search_email?email=${encodeURIComponent(email)}`)
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    showError(data.error);
                } else if (data.results && data.results.length > 0) {
                    showEmailResult(data.results);
                } else {
                    showError("Ничего не найдено.");
                }
            })
            .catch(error => showError('Ошибка сети: ' + error.message));
    }

    function showIPResult(data) {
        resultContainer.innerHTML = `
            <h3>Результаты поиска по IP: ${data.query}</h3>
            <div class="result-item">
                <p><strong>Страна:</strong> ${data.country || 'Не указано'}</p>
                <p><strong>Регион:</strong> ${data.regionName || 'Не указано'}</p>
                <p><strong>Город:</strong> ${data.city || 'Не указано'}</p>
                <p><strong>Провайдер:</strong> ${data.isp || 'Не указано'}</p>
                <p><strong>Координаты:</strong> ${data.lat || 'Не указано'}, ${data.lon || 'Не указано'}</p>
                <p><strong>Часовой пояс:</strong> ${data.timezone || 'Не указано'}</p>
            </div>
        `;
        resultContainer.classList.add('show');
    }

    function showPhoneResult(results) {
        let resultHTML = `<h3>Результаты поиска по телефону:</h3>`;
        results.forEach((item) => {
            const source = item.data ? `🏫 ${item.data}` : "🏫 Не указан";
            const fields = Object.entries(item)
                .filter(([key]) => key !== 'data')
                .map(([key, value], i, arr) => {
                    const prefix = i === arr.length - 1 ? '└' : '├';
                    return `${prefix}{${key}}: ${value || 'Не указано'}`;
                })
                .join('\n');

            resultHTML += `
                <div class="result-item">
                    <p><strong>База: ${source}</strong></p>
                    <pre>${fields}</pre>
                </div>
            `;
        });
        resultContainer.innerHTML = resultHTML;
        resultContainer.classList.add('show');
    }

    function showEmailResult(results) {
        let resultHTML = `<h3>Результаты поиска по email:</h3>`;
        results.forEach((item) => {
            const source = item.data ? `🏫 ${item.data}` : "🏫 Не указан";
            const fields = Object.entries(item)
                .filter(([key]) => key !== 'data')
                .map(([key, value], i, arr) => {
                    const prefix = i === arr.length - 1 ? '└' : '├';
                    return `${prefix}{${key}}: ${value || 'Не указано'}`;
                })
                .join('\n');

            resultHTML += `
                <div class="result-item">
                    <p><strong>База: ${source}</strong></p>
                    <pre>${fields}</pre>
                </div>
            `;
        });
        resultContainer.innerHTML = resultHTML;
        resultContainer.classList.add('show');
    }

    function showError(message) {
        resultContainer.innerHTML = `<div class="error-message">${message}</div>`;
        resultContainer.classList.add('show');
    }

    function sanitizeInput(input) {
        return input.replace(/[<>"'&]/g, '');
    }

    searchButton.addEventListener('click', () => {
        fetch('/check_auth')
            .then(response => response.json())
            .then(data => {
                if (!data.logged_in) {
                    showError("Требуется авторизация!");
                    return;
                }
                const query = sanitizeInput(searchInput.value.trim());
                if (!query) {
                    showError("Пожалуйста, введите IP, телефон или email!");
                    return;
                }

                const queryType = detectQueryType(query);
                if (!queryType) {
                    showError("Некорректный формат! Введите IP (например: 192.168.1.1), телефон (например: +79991234567) или email (например: user@example.com)");
                    return;
                }

                if (queryType === "ip") {
                    searchByIP(query);
                } else if (queryType === "phone") {
                    searchByPhone(query);
                } else if (queryType === "email") {
                    searchByEmail(query);
                }
            })
            .catch(error => showError('Ошибка проверки авторизации: ' + error.message));
    });

    if (registerButton) {
        registerButton.addEventListener('click', () => {
            currentAuthMode = 'register';
            modalTitle.textContent = 'Регистрация';
            modal.style.display = 'block';
        });
    }

    if (loginButton) {
        loginButton.addEventListener('click', () => {
            currentAuthMode = 'login';
            modalTitle.textContent = 'Вход';
            modal.style.display = 'block';
        });
    }

    if (logoutButton) {
        logoutButton.addEventListener('click', () => {
            fetch('/logout')
                .then(() => window.location.reload())
                .catch(error => console.error('Ошибка выхода:', error));
        });
    }

    closeModal.addEventListener('click', () => {
        modal.style.display = 'none';
    });

    submitAuth.addEventListener('click', () => {
        const username = sanitizeInput(usernameInput.value.trim());
        const password = sanitizeInput(passwordInput.value.trim());

        if (!username || !password) {
            alert('Пожалуйста, заполните все поля!');
            return;
        }

        if (username.length < 3 || username.length > 50) {
            alert('Логин должен быть от 3 до 50 символов!');
            return;
        }

        if (password.length < 6) {
            alert('Пароль должен быть не менее 6 символов!');
            return;
        }

        const url = currentAuthMode === 'register' ? '/register' : '/login';
        fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(data.message);
                modal.style.display = 'none';
                window.location.reload();
            } else {
                alert(data.message);
            }
        })
        .catch(error => alert('Ошибка: ' + error.message));
    });

    window.addEventListener('click', (event) => {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });

    searchInput.addEventListener('focus', () => {
        searchInput.placeholder = ' ';
    });

    searchInput.addEventListener('blur', () => {
        if (!searchInput.value) {
            searchInput.placeholder = 'Введите IP, телефон или email...';
        }
    });

    searchInput.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') {
            searchButton.click();
        }
    });

    searchInput.focus();
});
