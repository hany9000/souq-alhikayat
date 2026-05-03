// ============================================
// Souq Okaz - Chat App with Authentication
// ============================================

class SouqAlHikayatChat {
    constructor() {
        this.socket = null;
        this.username = null;
        this.userId = null;
        this.isAuthenticated = false;
        this.autoLoginDone = false;
        this.currentRoom = 'public';
        this.init();
    }
    
    init() {
        this.checkAuthFromURL();
        this.connectSocket();
        this.setupEventListeners();
        
        // مسح الرسائل القديمة بعد 3 ثواني
        setTimeout(() => {
            this.clearOldMessages();
        }, 3000);
        
        if (!this.isAuthenticated) {
            setTimeout(() => {
                if (!this.autoLoginDone) {
                    this.showLoginModal();
                }
            }, 1000);
        }
    }
    
    checkAuthFromURL() {
        const urlParams = new URLSearchParams(window.location.search);
        const token = urlParams.get('token');
        const username = urlParams.get('username');
        
        if (token && username) {
            this.username = username;
            this.isAuthenticated = true;
            this.autoLoginDone = true;
            
            localStorage.setItem('playerToken', token);
            localStorage.setItem('playerUsername', username);
            
            console.log('Token found in URL - auto login');
        } else {
            const savedToken = localStorage.getItem('playerToken');
            const savedUsername = localStorage.getItem('playerUsername');
            
            if (savedToken && savedUsername) {
                this.username = savedUsername;
                this.isAuthenticated = true;
                this.autoLoginDone = true;
            }
        }
    }
    
    async verifyAuth() {
        if (!this.isAuthenticated) return false;
        
        try {
            const response = await fetch('/api/verify-session', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            const data = await response.json();
            
            if (data.isAuthenticated && data.username) {
                this.userId = data.userId;
                this.username = data.username;
                return true;
            }
            
            return false;
        } catch (err) {
            console.error('Auth verification error:', err);
            return false;
        }
    }
    
    connectSocket() {
        this.socket = io({
            auth: {
                token: this.isAuthenticated ? 'authenticated' : null
            }
        });
        
        this.socket.on('connect', async () => {
            console.log('Connected to server:', this.socket.id);
            this.showNotification('Connected to server', 'success');
            
            if (this.isAuthenticated && this.username) {
                const verified = await this.verifyAuth();
                
                if (verified) {
                    this.socket.emit('authenticatedJoin', {
                        userId: this.userId,
                        username: this.username
                    });
                    
                    this.showAuthenticatedUI();
                }
            }
        });
        
        this.socket.on('disconnect', () => {
            console.log('Disconnected');
            this.showNotification('Disconnected from server', 'error');
        });
        
        this.socket.on('requireLogin', () => {
            if (!this.autoLoginDone) {
                this.showLoginModal();
            }
        });
        
        this.socket.on('welcome', (data) => {
            console.log('Welcome:', data.message);
            this.showNotification(data.message, 'success');
        });
        
        this.socket.on('onlineCount', (count) => {
            const counterEl = document.getElementById('onlineCount');
            if (counterEl) {
                counterEl.textContent = `${count} متصل`;
                console.log('✅ تم تحديث العداد:', count);
            } else {
                console.warn('⚠️ عنصر العداد غير موجود');
            }
        });
        
        this.socket.on('message', (data) => {
            this.addMessage(data);
        });
        
        this.socket.on('userJoined', (data) => {
            let msg = '';
            if (data.isAuthenticated) {
                msg = `Player ${data.username} joined`;
            } else {
                msg = `${data.username} joined`;
            }
            this.showNotification(msg, 'info');
        });
        
        this.socket.on('userLeft', (data) => {
            this.showNotification(`${data.username} left`, 'info');
        });
    }
    
    setupEventListeners() {
        const sendBtn = document.getElementById('sendButton');
        const messageInput = document.getElementById('messageInput');
        
        if (sendBtn) {
            sendBtn.addEventListener('click', () => this.sendMessage());
        }
        
        if (messageInput) {
            messageInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') this.sendMessage();
            });
        }
        
        const loginBtn = document.getElementById('loginButton');
        if (loginBtn) {
            loginBtn.addEventListener('click', () => this.loginAsGuest());
        }
        
        const gameLoginBtn = document.getElementById('gameLoginButton');
        if (gameLoginBtn) {
            gameLoginBtn.addEventListener('click', () => {
                this.showNotification('Use the game to login automatically', 'info');
            });
        }
        
        const closeBtn = document.getElementById('closeLoginModal');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                if (!this.isAuthenticated) {
                    this.showNotification('You must login first', 'error');
                }
            });
        }
        
        const createRoomBtn = document.getElementById('createRoomBtn');
        if (createRoomBtn) {
            createRoomBtn.addEventListener('click', () => this.createRoom());
        }
        
        const startCallBtn = document.getElementById('startCallBtn');
        if (startCallBtn) {
            startCallBtn.addEventListener('click', () => this.startVoiceCall());
        }
    }
    
    showLoginModal() {
        const modal = document.getElementById('loginModal');
        if (modal) {
            modal.style.display = 'flex';
        }
    }
    
    loginAsGuest() {
        const usernameInput = document.getElementById('usernameInput');
        const username = usernameInput ? usernameInput.value.trim() : '';
        
        if (!username) {
            this.showNotification('Please enter username', 'error');
            return;
        }
        
        this.username = username;
        this.isAuthenticated = false;
        
        this.socket.emit('join', { username, room: 'public' });
        
        const modal = document.getElementById('loginModal');
        if (modal) {
            modal.style.display = 'none';
        }
        
        this.showNotification(`Welcome ${username}!`, 'success');
    }
    
    showAuthenticatedUI() {
        const modal = document.getElementById('loginModal');
        if (modal) {
            modal.style.display = 'none';
        }
        
        const header = document.querySelector('.luxury-header');
        if (header && !document.querySelector('.auth-badge')) {
            const badge = document.createElement('div');
            badge.className = 'auth-badge';
            badge.innerHTML = `<i class="fas fa-check-circle"></i><span>Player: ${this.username}</span><span class="verified-badge">Verified</span>`;
            header.appendChild(badge);
        }
        
        const container = document.getElementById('messagesContainer');
        if (container) {
            const welcomeDiv = document.createElement('div');
            welcomeDiv.className = 'auth-welcome';
            welcomeDiv.innerHTML = `<i class="fas fa-sparkles"></i><strong>Welcome ${this.username} to Souq Okaz!</strong><p>You are connected as a verified player</p>`;
            container.insertBefore(welcomeDiv, container.firstChild);
        }
        
        this.autoLoginDone = true;
    }
    
    sendMessage() {
        const input = document.getElementById('messageInput');
        const content = input ? input.value.trim() : '';
        
        if (!content) return;
        
        const message = {
            username: this.username,
            content: content,
            room: this.currentRoom,
            timestamp: new Date().toISOString()
        };
        
        this.socket.emit('message', message);
        
        if (input) {
            input.value = '';
        }
    }
    
    addMessage(data) {
        const container = document.getElementById('messagesContainer');
        if (!container) return;
        
        const messageDiv = document.createElement('div');
        let className = 'message';
        if (data.isAuthenticated) className += ' authenticated';
        if (data.username === this.username) className += ' own';
        messageDiv.className = className;
        
        const time = new Date(data.timestamp).toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit'
        });
        
        let verifiedBadge = '';
        if (data.isAuthenticated) {
            verifiedBadge = ' <i class="fas fa-check-circle" style="color: var(--gold); font-size: 0.8rem;"></i>';
        }
        
        messageDiv.innerHTML = `<div class="message-header"><span class="message-username">${this.escapeHtml(data.username)}${verifiedBadge}</span><span class="message-time">${time}</span></div><div class="message-content">${this.escapeHtml(data.content)}</div>`;
        
        container.appendChild(messageDiv);
        container.scrollTop = container.scrollHeight;
    }
    
    createRoom() {
        if (!this.username) {
            this.showNotification('Please login first', 'error');
            return;
        }
        
        const roomName = prompt('Enter room name:');
        if (roomName) {
            this.socket.emit('createRoom', {
                name: roomName,
                creator: this.username,
                capacity: 1000
            });
            this.showNotification(`Room created: ${roomName}`, 'success');
        }
    }
    
    startVoiceCall() {
        this.showNotification('Preparing voice call...', 'info');
    }
    
    showNotification(message, type) {
        const container = document.getElementById('notificationsContainer');
        if (!container) return;
        
        const notification = document.createElement('div');
        notification.className = `notification ${type || 'info'}`;
        notification.textContent = message;
        
        container.appendChild(notification);
        
        setTimeout(() => {
            notification.style.animation = 'slideIn 0.3s ease reverse';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    clearOldMessages() {
        const container = document.getElementById('messagesContainer');
        if (container && container.children.length > 0) {
            // الاحتفاظ فقط برسالة الترحيب
            const welcomeMsg = `
                <div class="welcome-message">
                    <i class="fas fa-comments"></i>
                    <h3>أهلاً بك في سوق عكاظ</h3>
                    <p>ابدأ المحادثة وشارك الحكايات</p>
                </div>
            `;
            container.innerHTML = welcomeMsg;
            console.log('🧹 تم مسح الرسائل القديمة');
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.chatApp = new SouqAlHikayatChat();
});
