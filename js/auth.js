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
    // Se já temos um token em memória, retorna-o
    if (authState.token) {
      return authState.token;
    }
    
    // Se não temos token na memória, tente renovar assincronamente
    console.log("Não há token na memória, tentando renovar...");
    this.refreshToken().catch(err => {
      console.error("Falha ao renovar token:", err);
    });
    
    // Retorna o token atual (pode ser null até que refreshToken complete)
    return authState.token;
  },

  isAuthenticated() {
    return authState.isAuthenticated;
  },

  // Nova função: Verifica se o usuário é admin
  isAdmin() {
    const userRole = authState.currentUser?.role;
    const result = userRole === 'ADMIN';
    return result;
  },

  // Função auxiliar para debug de token
  debugToken() {
    const token = this.getToken();
    const tokenStatus = token ? 
      `presente (${token.substring(0, 10)}...${token.substring(token.length - 5)})` : 
      'ausente';
    
    console.log('==== Debug de Token ====');
    console.log('Token:', tokenStatus);
    console.log('isAuthenticated:', this.isAuthenticated());
    console.log('isAdmin:', this.isAdmin());
    console.log('userData:', authState.currentUser);
    console.log('=======================');
    
    return {
      hasToken: !!token,
      isAuthenticated: this.isAuthenticated(),
      isAdmin: this.isAdmin()
    };
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
        body: JSON.stringify(credentials),
        credentials: 'include' // Importante para receber e enviar cookies
      });

      if (!response.ok) {
        await handleApiError(response, 'Credenciais inválidas');
        throw new Error('Falha na autenticação');
      }

      const data = await response.json();
      const token = data.token || data.accessToken;

      // Criar objeto de usuário EXCLUINDO o token
      let user;
      if (data.user) {
        // Se os dados do usuário estão em um objeto separado
        user = {...data.user};
      } else {
        // Se os dados do usuário estão no objeto principal
        user = {...data};
        // Remover campos relacionados a token
        delete user.token;
        delete user.accessToken;
        delete user.refreshToken;
      }

      if (!token) {
        await handleApiError(response, 'Falha no login: token não recebido');
        throw new Error('Token não recebido');
      }

      // Atualiza estado (token APENAS na memória)
      authState.token = token;
      authState.currentUser = user;
      authState.isAuthenticated = true;
      
      // Armazenar apenas dados do usuário no localStorage (sem token)
      localStorage.setItem('userData', JSON.stringify(user));

      // Feedback visual
      const displayName = user?.name || user?.email || 'usuário';
      showNotification(`Bem-vindo, ${displayName}! Redirecionando...`);
      
      // Atualiza UI e dispara evento depois de confirmar o estado
      this.updateAuthUI();
      
      // Disparar evento para notificar componentes sobre mudança no estado
      window.dispatchEvent(new Event('auth-state-changed'));

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

  // Renovar token - versão robusta
  async refreshToken() {
    try {
      console.log("Tentando renovar token...");
      
      // Se já está em processo de renovação, aguarde
      if (this._refreshing) {
        console.log("Já existe uma renovação em andamento, aguardando...");
        await this._refreshPromise;
        return !!authState.token;
      }
      
      // Criar uma promessa para permitir outros chamarem aguardarem
      this._refreshing = true;
      this._refreshPromise = new Promise(async (resolve) => {
        try {
          const response = await fetch(`${API}/users/refresh-token`, {
            method: 'POST',
            credentials: 'include'
          });

          if (!response.ok) {
            console.error("Falha na resposta do refresh token:", response.status);
            resolve(false);
            return false;
          }

          const data = await response.json();
          console.log("Token renovado com sucesso!");
          authState.token = data.token;
          authState.isAuthenticated = true;
          
          // Atualizar userData se necessário
          if (data.user && !authState.currentUser) {
            authState.currentUser = data.user;
            localStorage.setItem('userData', JSON.stringify(data.user));
          }
          
          // Disparar evento
          window.dispatchEvent(new Event('auth-state-changed'));
          
          resolve(true);
          return true;
        } catch (error) {
          console.error('Erro ao renovar token:', error);
          resolve(false);
          return false;
        } finally {
          this._refreshing = false;
        }
      });
      
      return await this._refreshPromise;
    } catch (error) {
      console.error('Erro no processo de renovação de token:', error);
      this._refreshing = false;
      return false;
    }
  },

  // Logout
  logout() {
    // Executar logout na API (opcional, se implementado)
    fetch(`${API}/users/logout`, {
      method: 'POST',
      credentials: 'include'
    }).catch(err => console.log('Aviso: Falha ao notificar servidor sobre logout', err));
    
    // Limpar dados locais
    localStorage.removeItem('userData');
    authState.isAuthenticated = false;
    authState.currentUser = null;
    authState.token = null;
    
    // Atualizar UI primeiro
    this.updateAuthUI();
    
    // Depois disparar evento
    window.dispatchEvent(new Event('auth-state-changed'));
    
    showNotification('Logout realizado com sucesso', 'success');
    
    // Se já estamos na página inicial, forçar recarga para atualizar UI completamente
    if (window.location.pathname.includes('index.html') || window.location.pathname === '/') {
      setTimeout(() => window.location.reload(), 1500);
    } else {
      setTimeout(() => window.location.href = 'index.html', 1500);
    }
  },

  // Inicialização
  async initialize() {
    console.log("Inicializando autenticação...");
    
    // Definir explicitamente como não autenticado por padrão
    authState.isAuthenticated = false;
    authState.currentUser = null;
    authState.token = null;
    
    // Primeira atualização para garantir que a UI comece no estado correto
    this.updateAuthUI();
    
    const userData = JSON.parse(localStorage.getItem('userData'));

    if (!userData) {
      console.log("Nenhum dado de usuário encontrado no localStorage.");
      // Disparar evento mesmo sem autenticação
      setTimeout(() => {
        window.dispatchEvent(new Event('auth-initialized'));
      }, 50);
      return;
    }

    console.log("Dados de usuário encontrados, tentando renovar o token...");
    
    try {
      // Tentar renovar o token usando o refresh token
      const success = await this.refreshToken();
      
      if (success) {
        console.log("Token renovado com sucesso, autenticando usuário...");
        // Se o refresh token funcionou, o token já foi atualizado
        authState.currentUser = userData;
        authState.isAuthenticated = true;
        console.log("Usuário autenticado!");
        
        // Debug token após autenticação
        this.debugToken();
      } else {
        console.log("Falha ao renovar token, limpando estado de autenticação...");
        // Se falhou, limpar o estado de autenticação
        localStorage.removeItem('userData');
        authState.isAuthenticated = false;
        authState.currentUser = null;
        authState.token = null;
      }
    } catch (err) {
      console.error('Erro na inicialização da autenticação:', err);
      localStorage.removeItem('userData');
      authState.isAuthenticated = false;
      authState.currentUser = null;
      authState.token = null;
    }

    // Atualizar UI após determinar estado
    this.updateAuthUI();
    
    // Garantir que o evento seja disparado após pequeno delay 
    // para dar tempo ao DOM de processar as mudanças
    setTimeout(() => {
      window.dispatchEvent(new Event('auth-state-changed'));
      window.dispatchEvent(new Event('auth-initialized'));
    }, 50);
    
    return true;
  },

  // Limpar estado de autenticação
  clearAuthState() {
    localStorage.removeItem('userData');
    authState.token = null;
    authState.currentUser = null;
    authState.isAuthenticated = false;
      
    window.dispatchEvent(new Event('auth-state-changed'));
  },

  // Atualização da UI
  updateAuthUI() {
    console.log('Atualizando UI de autenticação...', 
      authState.isAuthenticated ? 'Autenticado' : 'Não autenticado',
      'Admin:', this.isAdmin() ? 'Sim' : 'Não');
    
    // Debug para confirmar que conhecemos o estado
    console.log('Estado completo:', {
      isAuthenticated: authState.isAuthenticated,
      userRole: authState.currentUser?.role,
      isAdmin: this.isAdmin(),
      hasToken: !!authState.token
    });
    
    // Aplicar visibilidade com base no localStorage como fallback
    // (para garantir consistência com `components.js`)
    const userData = JSON.parse(localStorage.getItem('userData'));
    const isLoggedInLS = !!userData;
    const isAdminLS = userData && userData.role === 'ADMIN';
    
    // Verificar se há discrepância entre estado em memória e localStorage
    if (isLoggedInLS !== authState.isAuthenticated) {
      console.warn('Discrepância entre localStorage e authState:', 
        { localStorage: isLoggedInLS, authState: authState.isAuthenticated });
        
      // Priorizar localStorage
      if (isLoggedInLS && userData) {
        authState.isAuthenticated = true;
        authState.currentUser = userData;
      } else {
        authState.isAuthenticated = false;
        authState.currentUser = null;
        authState.token = null;
      }
    }
    
    // Seleciona todos os elementos com atributo data-auth
    document.querySelectorAll('[data-auth]').forEach(el => {
      const authType = el.dataset.auth;
      let shouldShow = false;
      
      // Determina se o elemento deve ser mostrado
      switch(authType) {
        case 'all':
          shouldShow = true;
          break;
        case 'authenticated':
          shouldShow = authState.isAuthenticated;
          break;
        case 'unauthenticated':
          shouldShow = !authState.isAuthenticated;
          break;
        case 'admin':
          shouldShow = this.isAdmin();
          break;
      }
      
      // Mostra ou esconde o elemento
      el.style.display = shouldShow ? '' : 'none';
      console.log(`Menu ${el.textContent.trim()} [data-auth="${authType}"]`, shouldShow ? 'mostrado' : 'escondido');
    });

    // Aplica classes ao body
    document.body.classList.toggle('authenticated', authState.isAuthenticated);
    document.body.classList.toggle('unauthenticated', !authState.isAuthenticated);
    document.body.classList.toggle('admin', this.isAdmin());
    
    // Atualiza campos com dados do usuário
    document.querySelectorAll('[data-user]').forEach(el => {
      const field = el.dataset.user;
      el.textContent = authState.currentUser?.[field] || '';
    });
  }
};



// --- Inicialização automática ---
document.addEventListener('DOMContentLoaded', () => {
  if (!document.getElementById('notification-container')) {
    const nc = document.createElement('div');
    nc.id = 'notification-container';
    document.body.prepend(nc);
  }
  
  // Inicializar auth e guardar promessa
  const initPromise = authService.initialize();
  
  // Verificar se há um navbar, se não, esperar e atualizar UI novamente
  setTimeout(() => {
    if (document.querySelector('nav')) {
      console.log('Navbar encontrada, atualizando a UI novamente');
      authService.updateAuthUI();
    }
  }, 100);
});

// Expor método para forçar atualização da UI (apenas para debug)
window.forceUpdateAuthUI = () => authService.updateAuthUI();