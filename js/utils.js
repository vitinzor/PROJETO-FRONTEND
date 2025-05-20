// js/utils.js
import { authService } from './auth.js';

// --- API Communication Utils ---
// Configurações globais para a API
const API_URL = 'http://localhost:3000';

// Função para requisições autenticadas
export async function fetchWithAuth(endpoint, options = {}) {
  const url = endpoint.startsWith('http') ? endpoint : `${API_URL}${endpoint}`;
  
  // Prepara as opções da requisição com o token de autenticação
  const token = authService.getToken();
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers
  };
  
  // Adiciona o token de Authorization se disponível
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  
  // Configura a requisição com credentials e headers
  const fetchOptions = {
    ...options,
    headers,
    credentials: 'include' // Importante para cookies
  };
  
  try {
    // Faz a requisição
    let response = await fetch(url, fetchOptions);
    
    // Se a resposta indica token expirado (401)
    if (response.status === 401) {
      console.log("Token expirado ou inválido, tentando renovar...");
      
      // Tenta renovar o token
      const tokenRefreshed = await authService.refreshToken();
      
      // Se o token foi renovado com sucesso, tenta a requisição novamente
      if (tokenRefreshed) {
        console.log("Token renovado com sucesso, repetindo requisição...");
        // Atualiza o token na requisição
        const newToken = authService.getToken();
        headers['Authorization'] = `Bearer ${newToken}`;
        
        // Refaz a requisição com o novo token
        response = await fetch(url, {
          ...fetchOptions,
          headers
        });
      } else {
        // Se não conseguiu renovar o token, o usuário precisa fazer login novamente
        console.error("Não foi possível renovar o token. Redirecionando para login...");
        authService.logout();
        window.location.href = '/login.html';
        throw new Error("Sessão expirada. Por favor, faça login novamente.");
      }
    }
    
    return response;
    
  } catch (error) {
    console.error("Erro na requisição:", error);
    throw error;
  }
}

// Funções wrapper para os diferentes métodos HTTP
export const api = {
  async get(endpoint, options = {}) {
    return fetchWithAuth(endpoint, {
      method: 'GET',
      ...options
    });
  },
  
  async post(endpoint, data, options = {}) {
    return fetchWithAuth(endpoint, {
      method: 'POST',
      body: JSON.stringify(data),
      ...options
    });
  },
  
  async put(endpoint, data, options = {}) {
    return fetchWithAuth(endpoint, {
      method: 'PUT',
      body: JSON.stringify(data),
      ...options
    });
  },
  
  async delete(endpoint, options = {}) {
    return fetchWithAuth(endpoint, {
      method: 'DELETE',
      ...options
    });
  }
};

// --- Sistema de Notificações ---
export const showNotification = (message, type = 'success', duration = 5000) => {
    // Apenas mostrar notificações de sucesso, erro ou aviso, ignorar as de carregamento
    if (type === 'loading') {
        // Não mostrar notificações de carregamento
        return null;
    }
    
    // Crie um ID único para esta notificação
    const notificationId = Date.now();
    
    const notificationContainer = document.getElementById('notification-container');
    if (!notificationContainer) {
        console.error("Element with id 'notification-container' not found. Please add it to your HTML.");
        // Fallback para alerta simples se o container não for encontrado
        if (type === 'error') {
            alert(`Erro: ${message}`);
        } else {
            alert(message);
        }
        return null;
    }

    const notification = document.createElement('div');
    notification.className = `message ${type}`; // Usando classes CSS definidas
    notification.setAttribute('data-notification-id', notificationId);
    
    // Determinar o ícone com base no tipo
    let icon = '';
    switch(type) {
        case 'success':
            icon = '<i class="fas fa-check-circle"></i>';
            break;
        case 'error':
            icon = '<i class="fas fa-exclamation-circle"></i>';
            break;
        case 'info':
            icon = '<i class="fas fa-info-circle"></i>';
            break;
        case 'warning':
            icon = '<i class="fas fa-exclamation-triangle"></i>';
            break;
    }
    
    // Estrutura da notificação com ícone
    notification.innerHTML = `
        <div class="notification-content">
            ${icon} <span>${message}</span>
        </div>
        <span class="close-notification">&times;</span>
    `;
    
    // Estilização inline para o botão de fechar
    const closeButton = notification.querySelector('.close-notification');
    closeButton.style.cursor = 'pointer';
    closeButton.style.marginLeft = '15px';
    closeButton.style.fontWeight = 'bold';
    closeButton.style.fontSize = '20px';
    closeButton.style.opacity = '0.7';
    
    // Estilo inline para conteúdo
    const content = notification.querySelector('.notification-content');
    content.style.display = 'flex';
    content.style.alignItems = 'center';
    content.style.gap = '10px';
    
    // Manipulador de eventos para fechar a notificação
    closeButton.addEventListener('click', () => {
        notification.style.opacity = '0';
        setTimeout(() => notification.remove(), 300);
    });
    
    notificationContainer.appendChild(notification);

    // Garantir que a notificação será removida após o tempo especificado
    if (duration > 0) {
        setTimeout(() => {
            // Verificar se a notificação ainda existe
            const notificationElement = document.querySelector(`[data-notification-id="${notificationId}"]`);
            if (notificationElement) {
                notificationElement.style.opacity = '0';
                
                // Remover após a transição de opacidade
                setTimeout(() => {
                    if (notificationElement.parentNode) {
                        notificationElement.remove();
                    }
                }, 300); // 300ms para a transição acontecer
            }
        }, duration);
    }
    
    // Retornar o ID para poder remover programaticamente
    return notificationId;
};

// Função para remover notificação por ID
export const removeNotification = (id) => {
    if (!id) return;
    
    const notification = document.querySelector(`[data-notification-id="${id}"]`);
    if (notification) {
        notification.style.opacity = '0';
        
        // Remover após transição
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 300);
    }
};

// Função para limpar todas as notificações
export const clearAllNotifications = () => {
    const container = document.getElementById('notification-container');
    if (container) {
        container.innerHTML = '';
    }
};

// Função para tratamento de erros de API
export const handleApiError = async (response, defaultMessage = 'Erro na operação') => {
    let errorMessage = defaultMessage;
    console.error('API Error Status:', response.status);

    try {
        const responseClone = response.clone();
        const errorData = await responseClone.json();
        console.error('API Error Data:', errorData);

        if (errorData && typeof errorData === 'object') {
            if (errorData.errors && Array.isArray(errorData.errors)) {
                errorMessage = errorData.errors.map(err => err.message || err.msg || JSON.stringify(err)).join(', ');
            } else if (errorData.message) {
                errorMessage = errorData.message;
            } else if (errorData.error) {
                errorMessage = errorData.error;
            } else {
                errorMessage = JSON.stringify(errorData);
            }
        } else if (typeof errorData === 'string') {
            errorMessage = errorData;
        } else {
            errorMessage = response.statusText || `Erro desconhecido: Status ${response.status}`;
        }

    } catch (jsonError) {
        errorMessage = response.statusText || `Erro na resposta do servidor: Status ${response.status}`;
        console.error('Failed to parse API error response:', jsonError);
    }

    console.error('API Error Details:', { status: response.status, message: errorMessage });
    showNotification(errorMessage, 'error');
};

// --- Função para Formatar Data ---
export const formatDate = (dateString) => {
    if (!dateString) return 'Data indisponível';
    
    try {
        // Converter para um objeto Date
        const date = new Date(dateString);
        
        // Verificar se é uma data válida
        if (isNaN(date.getTime())) {
            console.warn('Data inválida:', dateString);
            return 'Data indisponível';
        }
        
        // Aplicar o fuso horário brasileiro
        const opcoesDeFormato = { 
            year: 'numeric', 
            month: 'long', 
            day: 'numeric',
            timeZone: 'America/Sao_Paulo'
        };
        
        // Criar string formatada em português brasileiro
        return date.toLocaleDateString('pt-BR', opcoesDeFormato);
    } catch (e) {
        console.error("Erro ao formatar data:", e);
        return 'Data indisponível';
    }
};

// Função para gerar data do filme baseada no ID
export const generateMovieDateFromId = (movieId, referenceDate = '2025-05-10') => {
    if (!movieId) {
        return 'Data indisponível';
    }
    
    // Usar o ID do filme para criar uma data fictícia mais antiga
    try {
        // Criar data base a partir da referência
        const baseDate = new Date(referenceDate);
        
        // Subtrair dias baseados no ID (filmes com ID maior são mais recentes)
        // ID 1 = data mais antiga, IDs maiores = datas mais recentes
        const daysOffset = Math.max(movieId, 1);
        const resultDate = new Date(baseDate);
        resultDate.setDate(baseDate.getDate() - daysOffset);
        
        // Retornar formatado
        const options = { 
            year: 'numeric', 
            month: 'long', 
            day: 'numeric', 
            timeZone: 'America/Sao_Paulo' 
        };
        
        return resultDate.toLocaleDateString('pt-BR', options);
    } catch (e) {
        console.error("Erro ao gerar data para filme:", e);
        return 'Data indisponível';
    }
};

// --- Função para Gerar Classificação em Estrelas ---
export const starRating = (rating) => {
    const roundedRating = Math.max(0, Math.min(5, Math.round(rating || 0)));
    return '★'.repeat(roundedRating) + '☆'.repeat(5 - roundedRating);
};