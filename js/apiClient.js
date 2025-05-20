// js/apiClient.js (novo arquivo)
import { authService } from './auth.js';

const API = 'http://localhost:3000';

export const apiClient = {
  async fetch(url, options = {}) {
    // Preparar opções padrão
    const defaultOptions = {
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include' // Para enviar/receber cookies
    };
    
    // Adicionar token se autenticado
    if (authService.isAuthenticated()) {
      defaultOptions.headers['Authorization'] = `Bearer ${authService.getToken()}`;
    }
    
    // Mesclar opções
    const fetchOptions = {
      ...defaultOptions,
      ...options,
      headers: {
        ...defaultOptions.headers,
        ...options.headers,
      },
    };
    
    try {
      // Fazer requisição
      let response = await fetch(`${API}${url}`, fetchOptions);
      
      // Se token expirou (401), tentar renovar e tentar novamente
      if (response.status === 401) {
        const refreshSuccess = await authService.refreshToken();
        
        if (refreshSuccess) {
          // Atualizar token nas opções
          fetchOptions.headers['Authorization'] = `Bearer ${authService.getToken()}`;
          
          // Tentar requisição novamente
          response = await fetch(`${API}${url}`, fetchOptions);
        } else {
          // Se não conseguir renovar, propagar erro de 401
          throw new Error('Sessão expirada');
        }
      }
      
      return response;
    } catch (error) {
      console.error('Erro na requisição API:', error);
      throw error;
    }
  },
  
  // Métodos auxiliares
  async get(url, options = {}) {
    return this.fetch(url, { ...options, method: 'GET' });
  },
  
  async post(url, data, options = {}) {
    return this.fetch(url, {
      ...options,
      method: 'POST',
      body: JSON.stringify(data),
    });
  },
  
  async put(url, data, options = {}) {
    return this.fetch(url, {
      ...options,
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },
  
  async delete(url, options = {}) {
    return this.fetch(url, { ...options, method: 'DELETE' });
  }
};