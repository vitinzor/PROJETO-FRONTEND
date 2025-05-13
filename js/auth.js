// js/auth.js

// Importa funções utilitárias
import { showNotification, handleApiError } from './utils.js';

// Define a URL base da API
const API = 'http://localhost:3000';

// Estado de autenticação global
const authState = {
  currentUser: null,
  isAuthenticated: false,
  token: null
};

// --- Serviço de Autenticação ---
export const authService = {
  get authState() {
    return { ...authState };
  },

  getToken() {
    return authState.token;
  },

  isAuthenticated() {
    return authState.isAuthenticated;
  },

  // Nova função: Verifica se o usuário é admin
  isAdmin() {
    const userRole = authState.currentUser?.role;
    const result = userRole === 'ADMIN';
    // Removido log excessivo
    return result;
  },

  // Registro
  async register(userData) {
    try {
      const res = await fetch(`${API}/users/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(userData)
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        const error = new Error(errorData.message || 'Erro no registro');
        error.status = res.status;
        error.data = errorData;
        throw error;
      }

      showNotification('Cadastro realizado com sucesso! Redirecionando para login...');
      setTimeout(() => window.location.href = 'login.html', 2000);
      return true;

    } catch (err) {
      console.error('Erro no registro:', err);
      throw err;
    }
  },

  // Login
  async login(credentials) {
    try {
        const response = await fetch(`${API}/users/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(credentials)
        });

        if (!response.ok) {
            await handleApiError(response, 'Credenciais inválidas');
            throw new Error('Falha na autenticação');
        }

        const data = await response.json();
        const token = data.token;
        const user = data.user ?? data;

        if (!token) {
            await handleApiError(response, 'Falha no login: token não recebido');
            throw new Error('Token não recebido');
        }

        // Atualiza estado e storage
        localStorage.setItem('auth', JSON.stringify({ token, user }));
        authState.token = token;
        authState.currentUser = user;
        authState.isAuthenticated = true;

        // Disparar evento para notificar componentes sobre mudança no estado
        window.dispatchEvent(new Event('auth-state-changed'));

        // Feedback visual
        const displayName = user?.name || user?.email || 'usuário';
        showNotification(`Bem-vindo, ${displayName}! Redirecionando...`);
        this.updateAuthUI();

        // Redirecionamento seguro
        setTimeout(() => {
            const redirectTo = localStorage.getItem('redirectTo') || 'index.html';
            localStorage.removeItem('redirectTo');
            
            if (redirectTo.includes('admin.html') && !this.isAdmin()) {
                window.location.href = 'index.html';
                showNotification('Você não tem permissão para acessar a área de administração', 'warning');
            } else {
                window.location.href = redirectTo;
            }
        }, 2000);

        return true;

    } catch (error) {
        console.error('Erro no login:', error);
        throw error;
    }
  },

  // Logout
  logout() {
    localStorage.removeItem('auth');
    authState.isAuthenticated = false;
    authState.currentUser = null;
    authState.token = null;
    
    // Disparar evento para notificar componentes sobre mudança no estado
    window.dispatchEvent(new Event('auth-state-changed'));
    
    showNotification('Logout realizado com sucesso', 'success');
    this.updateAuthUI();
    
    // Se já estamos na página inicial, forçar recarga para atualizar UI completamente
    if (window.location.pathname.includes('index.html') || window.location.pathname === '/') {
      setTimeout(() => window.location.reload(), 1500);
    } else {
      setTimeout(() => window.location.href = 'index.html', 1500);
    }
  },

  // Inicialização
  async initialize() {
    const saved = JSON.parse(localStorage.getItem('auth'));

    if (!saved?.token) {
      this.clearAuthState();
      this.updateAuthUI();
      window.dispatchEvent(new Event('auth-initialized'));
      return;
    }

    try {
      const res = await fetch(`${API}/users/me`, {
        headers: { 'Authorization': `Bearer ${saved.token}` }
      });

      if (res.ok) {
        const apiUserData = await res.json();
        
        if (!apiUserData.role && saved.user?.role) {
          apiUserData.role = saved.user.role;
          console.log('Role obtida do localStorage:', saved.user.role);
        }
        
        authState.token = saved.token;
        authState.currentUser = apiUserData;
        authState.isAuthenticated = true;
      } else {
        console.warn('Token inválido. Status:', res.status);
        this.clearAuthState();
      }

    } catch (err) {
      console.error('Erro na validação do token:', err);
      this.clearAuthState();
    }

    this.updateAuthUI();
    window.dispatchEvent(new Event('auth-initialized'));
  },

  clearAuthState() {
    localStorage.removeItem('auth');
    authState.token = null;
    authState.currentUser = null;
    authState.isAuthenticated = false;
    
    window.dispatchEvent(new Event('auth-state-changed'));
  },

  // Atualização da UI
  updateAuthUI() {
    console.log('Atualizando UI de autenticação...', authState.isAuthenticated ? 'Autenticado' : 'Não autenticado');
    
    document.querySelectorAll('[data-auth]').forEach(el => {
      const authType = el.dataset.auth;
      const shouldShow = 
        (authType === 'authenticated' && authState.isAuthenticated) || 
        (authType === 'unauthenticated' && !authState.isAuthenticated) ||
        (authType === 'admin' && this.isAdmin());
      
      el.style.display = shouldShow ? '' : 'none';
    });

    document.querySelectorAll('[data-user]').forEach(el => {
      const field = el.dataset.user;
      el.textContent = authState.currentUser?.[field] || '';
    });

    document.body.classList.toggle('authenticated', authState.isAuthenticated);
    document.body.classList.toggle('unauthenticated', !authService.isAuthenticated());
    document.body.classList.toggle('admin', this.isAdmin());
  }
};

// --- Inicialização automática ---
document.addEventListener('DOMContentLoaded', () => {
  if (!document.getElementById('notification-container')) {
    const nc = document.createElement('div');
    nc.id = 'notification-container';
    document.body.prepend(nc);
  }

  authService.initialize();
});