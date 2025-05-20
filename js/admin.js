// js/admin.js

import { authService } from './auth.js';
import { showNotification } from './utils.js';

const API_URL = 'http://localhost:3000';

// Controle de inicialização
let initialized = false;

// Função principal para inicializar a página
function init() {
  if (initialized) return;
  
  // Buscar elementos DOM
  const adminPanel = document.getElementById('admin-panel');
  const accessDenied = document.getElementById('access-denied');
  const loginRequired = document.getElementById('login-required');
  
  if (!adminPanel || !accessDenied || !loginRequired) {
    console.error('Elementos principais não encontrados');
    return;
  }
  
  // Verificar autenticação
  if (!authService.isAuthenticated()) {
    adminPanel.style.display = 'none';
    accessDenied.style.display = 'none';
    loginRequired.style.display = 'block';
    localStorage.setItem('redirectTo', 'admin.html');
    return;
  }
  
  // Verificar se é admin
  if (!authService.isAdmin()) {
    adminPanel.style.display = 'none';
    accessDenied.style.display = 'block';
    loginRequired.style.display = 'none';
    return;
  }
  
  // É admin, mostrar painel
  adminPanel.style.display = 'block';
  accessDenied.style.display = 'none';
  loginRequired.style.display = 'none';
  
  // Inicializar tabs e carregar dados
  initTabs();
  initialized = true;
}

// Inicializar tabs
function initTabs() {
  const tabButtons = document.querySelectorAll('.tab-button');
  const tabContents = document.querySelectorAll('.tab-content');
  
  if (tabButtons.length === 0) {
    console.error('Botões de tab não encontrados');
    return;
  }
  
  // Configurar eventos de clique para tabs
  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      const tabName = button.getAttribute('data-tab');
      
      // Atualizar estados ativos
      tabButtons.forEach(btn => btn.classList.remove('active'));
      tabContents.forEach(content => content.classList.remove('active'));
      
      button.classList.add('active');
      const tabContent = document.getElementById(`${tabName}-tab`);
      
      if (tabContent) {
        tabContent.classList.add('active');
        
        // Carregar dados se necessário
        if (tabName === 'users' && !tabContent.dataset.loaded) {
          loadUsers();
          tabContent.dataset.loaded = 'true';
        } else if (tabName === 'reviews' && !tabContent.dataset.loaded) {
          loadReviews();
          tabContent.dataset.loaded = 'true';
        } else if (tabName === 'movies' && !tabContent.dataset.loaded) {
          loadMovies();
          tabContent.dataset.loaded = 'true';
        }
      }
    });
  });
  
  // Ativar primeira tab por padrão
  const firstTab = tabButtons[0];
  if (firstTab) {
    firstTab.click();
  }
}

// Evento DOMContentLoaded
document.addEventListener('DOMContentLoaded', () => {
  console.log('DOM carregado');
  
  // Aguardar inicialização da autenticação
  if (authService.isAuthenticated()) {
    init();
  } else {
    // Aguardar o evento de inicialização
    window.addEventListener('auth-initialized', () => {
      setTimeout(init, 100); // Pequeno atraso para garantir que o estado esteja atualizado
    });
  }
  
  // Verificar visibilidade a cada 2 segundos - limitado a 10 tentativas
  let attempts = 0;
  const checkInterval = setInterval(() => {
    if (attempts >= 10) {
      clearInterval(checkInterval);
      return;
    }
    
    attempts++;
    
    const adminPanel = document.getElementById('admin-panel');
    const accessDenied = document.getElementById('access-denied');
    
    if (authService.isAdmin()) {
      if (accessDenied && accessDenied.style.display !== 'none') {
        accessDenied.style.display = 'none';
      }
      
      if (adminPanel && adminPanel.style.display !== 'block') {
        adminPanel.style.display = 'block';
        if (!initialized) {
          init();
        }
      }
    }
  }, 2000);

  // Adicionar botão de debug na UI - remove este código em produção
  const debugBtn = document.createElement('button');
  debugBtn.textContent = 'Depurar Auth';
  debugBtn.style.position = 'fixed';
  debugBtn.style.bottom = '10px';
  debugBtn.style.right = '10px';
  debugBtn.style.zIndex = 9999;
  debugBtn.style.padding = '5px 10px';
  debugBtn.style.background = '#ff5500';
  debugBtn.style.color = 'white';
  debugBtn.style.border = 'none';
  debugBtn.style.borderRadius = '4px';
  debugBtn.style.cursor = 'pointer';
  
  debugBtn.addEventListener('click', function() {
    debugAuth().then(result => {
      console.log('Debug concluído:', result);
    });
  });
  
  document.body.appendChild(debugBtn);
});

// Função para debug de autenticação
async function debugAuth() {
  try {
    // Verificar estado atual
    const debugInfo = authService.debugToken();
    console.table(debugInfo);
    
    // Tentar renovar token explicitamente
    console.log('Forçando renovação de token...');
    const success = await authService.refreshToken();
    console.log('Renovação de token:', success ? 'sucesso' : 'falha');
    
    // Verificar estado após renovação
    const newDebugInfo = authService.debugToken();
    console.table(newDebugInfo);
    
    // Se conseguimos um token, tentar recarregar usuários
    if (newDebugInfo.hasToken) {
      console.log('Recarregando usuários após renovação de token...');
      loadUsers();
    }
    
    return {
      beforeRefresh: debugInfo,
      afterRefresh: newDebugInfo
    };
  } catch (error) {
    console.error('Erro durante debug:', error);
    return { error: error.message };
  }
}

// Nova função para retry
async function retryLoadUsers() {
  console.log('Tentando carregar usuários novamente...');
  
  try {
    // Forçar renovação de token antes de tentar novamente
    const success = await authService.refreshToken();
    console.log('Renovação de token antes de retry:', success ? 'sucesso' : 'falha');
    
    const token = authService.getToken();
    console.log('Token antes de retry:', token ? 'presente' : 'ausente');
    
    // Pequeno delay para evitar múltiplas chamadas
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Tentar carregar usuários novamente
    await loadUsers();
    return true;
  } catch (err) {
    console.error('Erro no retry:', err);
    return false;
  }
}

// Funções para carregar e gerenciar dados
async function loadUsers() {
  try {
    console.log('Carregando usuários...');
    let token = authService.getToken();
    
    // Se não temos um token, tentar renovar explicitamente
    if (!token) {
      console.log('Token não encontrado, tentando renovar...');
      const refreshSuccess = await authService.refreshToken();
      
      if (refreshSuccess) {
        console.log('Renovação de token bem-sucedida!');
        token = authService.getToken();
      } else {
        console.error('Não foi possível renovar o token');
        throw new Error('Não foi possível obter um token de autenticação válido');
      }
    }
    
    // Debug do token
    console.log('Token para requisição:', 
                token ? `${token.substring(0, 10)}...` : 'ausente');
    
    const response = await fetch(`${API_URL}/users/admin/users`, {
      method: 'GET', // Especificar método explicitamente
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      credentials: 'include' // Incluir cookies
    });
    
    if (!response.ok) {
      // Tentar renovar o token se receber 401 (Unauthorized)
      if (response.status === 401) {
        console.log('Token inválido ou expirado, renovando...');
        const renewed = await authService.refreshToken();
        
        if (renewed) {
          console.log('Token renovado, tentando requisição novamente');
          // Tentar novamente com o novo token
          return await retryLoadUsers();
        } else {
          throw new Error('Sessão expirada. Faça login novamente.');
        }
      }
      
      let errorMessage = `Erro do servidor: ${response.status} ${response.statusText}`;
      try {
        const errorData = await response.json();
        errorMessage = errorData.error || errorData.message || errorMessage;
      } catch (e) {
        try {
          const errorText = await response.text();
          errorMessage = errorText || errorMessage;
        } catch (e2) {}
      }
      throw new Error(errorMessage);
    }
    
    const users = await response.json();
    
    // Encontrar o usuário mais ativo
    let mostActiveUser = { name: "-", count: 0 };
    for (const user of users) {
      const totalContributions = (user._count?.reviews || 0) + (user._count?.addedMovies || 0);
      if (totalContributions > mostActiveUser.count) {
        mostActiveUser = {
          name: user.name || "Usuário",
          count: totalContributions
        };
      }
    }
    
    // Renderizar estatísticas
    const usersTab = document.getElementById('users-tab');
    if (usersTab) {
      usersTab.innerHTML = `
        <h2>Gerenciamento de Usuários</h2>
        
        <div class="stats-summary">
          <div class="stats-row">
            <div class="card">
              <h3>Total de Usuários</h3>
              <p id="total-users">${users.length}</p>
            </div>
            <div class="card">
              <h3>Administradores</h3>
              <p id="admin-count">${users.filter(user => user.role === 'ADMIN').length}</p>
            </div>
            <div class="card">
              <h3>Usuário Mais Ativo</h3>
              <p>${mostActiveUser.name}</p>
              <small>${mostActiveUser.count} contribuições</small>
            </div>
          </div>
        </div>
        
        <h3>Lista de Usuários</h3>
        <div class="table-container">
          <table id="users-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Nome</th>
                <th>Email</th>
                <th>Função</th>
                <th>Data de Registro</th>
                <th>Avaliações</th>
                <th>Filmes</th>
                <th>Ações</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td colspan="8" class="text-center">Carregando usuários...</td>
              </tr>
            </tbody>
          </table>
        </div>
      `;
    }
    
    // Renderizar tabela
    renderUsersTable(users);
    
  } catch (error) {
    console.error('Erro ao carregar usuários:', error);
    
    const usersTab = document.getElementById('users-tab');
    if (usersTab) {
      usersTab.innerHTML = `
        <h2>Gerenciamento de Usuários</h2>
        <div class="error-message">
          <p>Erro ao carregar dados: ${error.message}</p>
          <button class="btn btn-primary" onclick="retryLoadUsers()">
            Tentar novamente
          </button>
        </div>
      `;
    }
    
    showNotification(`Erro: ${error.message}`, 'error');
  }
}

// O restante das funções permanece o mesmo...

function renderUsersTable(users) {
  const tableBody = document.querySelector('#users-table tbody');
  
  if (!tableBody) {
    console.error('Corpo da tabela não encontrado');
    return;
  }
  
  if (users.length === 0) {
    tableBody.innerHTML = '<tr><td colspan="8">Nenhum usuário encontrado</td></tr>';
    return;
  }
  
  try {
    tableBody.innerHTML = users.map(user => {
      if (!user) return '';
      
      const createdAt = user.createdAt ? new Date(user.createdAt).toLocaleDateString('pt-BR') : 'N/A';
      const isCurrentUser = authService.authState.currentUser && 
                            user.id === authService.authState.currentUser.id;
      const reviewsCount = user._count?.reviews || 0;
      const moviesCount = user._count?.addedMovies || 0;
      
      const safeUserName = user.name ? user.name.replace(/'/g, "\\'") : 'Usuário';
      
      return `
        <tr>
          <td>${user.id || 'N/A'}</td>
          <td>${user.name || 'N/A'}</td>
          <td>${user.email || 'N/A'}</td>
          <td>${user.role || 'N/A'}</td>
          <td>${createdAt}</td>
          <td>${reviewsCount}</td>
          <td>${moviesCount}</td>
          <td>
            <div class="user-actions">
              ${user.role === 'ADMIN' ? 
                `<button class="btn btn-small btn-warning" ${isCurrentUser ? 'disabled' : ''} 
                  onclick="${isCurrentUser ? '' : `demoteUser(${user.id}, '${safeUserName}')`}">
                  <i class="fas fa-arrow-down"></i> Rebaixar
                </button>` : 
                `<button class="btn btn-small btn-primary" 
                  onclick="promoteUser(${user.id}, '${safeUserName}')">
                  <i class="fas fa-arrow-up"></i> Promover
                </button>`
              }
              <button class="btn btn-small btn-danger" ${isCurrentUser ? 'disabled' : ''} 
                onclick="${isCurrentUser ? '' : `confirmDeleteUser(${user.id}, '${safeUserName}')`}">
                <i class="fas fa-trash"></i> Excluir
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
    
    // Adicionar funções ao escopo global para os botões
    window.promoteUser = promoteUser;
    window.demoteUser = demoteUser;
    window.confirmDeleteUser = confirmDeleteUser;
    
  } catch (error) {
    console.error('Erro ao renderizar tabela:', error);
    tableBody.innerHTML = `<tr><td colspan="8">Erro ao renderizar tabela: ${error.message}</td></tr>`;
  }
}

async function loadReviews() {
  try {
    console.log('Carregando avaliações...');
    const token = authService.getToken();
    
    if (!token) {
      throw new Error('Token de autenticação não encontrado');
    }
    
    const response = await fetch(`${API_URL}/reviews/admin/stats`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      credentials: 'include'
    });
    
    if (!response.ok) {
      // Tentar renovar token em caso de falha de autorização
      if (response.status === 401) {
        const renewed = await authService.refreshToken();
        if (renewed) {
          // Tentar novamente com o novo token
          return loadReviews();
        }
      }
      
      throw new Error(`Erro ao carregar estatísticas: ${response.status} ${response.statusText}`);
    }
    
    const stats = await response.json();
    
    // Renderizar estatísticas
    renderReviewStats(stats);
    
    // Carregar lista de avaliações
    const reviewsResponse = await fetch(`${API_URL}/reviews/admin/list`, {
      headers: {
        'Authorization': `Bearer ${authService.getToken()}`,
        'Content-Type': 'application/json'
      },
      credentials: 'include'
    });
    
    if (!reviewsResponse.ok) {
      throw new Error(`Erro ao carregar lista: ${reviewsResponse.status} ${reviewsResponse.statusText}`);
    }
    
    const reviews = await reviewsResponse.json();
    
    // Renderizar tabela
    renderReviewsTable(reviews);
    
  } catch (error) {
    console.error('Erro ao carregar avaliações:', error);
    const reviewsTab = document.getElementById('reviews-tab');
    if (reviewsTab) {
      reviewsTab.innerHTML = `
        <h2>Gerenciamento de Avaliações</h2>
        <div class="error-message">
          <p>Erro: ${error.message}</p>
          <button class="btn btn-primary" onclick="window.location.reload()">Tentar novamente</button>
        </div>
      `;
    }
    showNotification(`Erro: ${error.message}`, 'error');
  }
}

function renderReviewStats(stats) {
  const reviewsTab = document.getElementById('reviews-tab');
  if (!reviewsTab) return;
  
  const ratingDistribution = stats.ratingDistribution || {1: 0, 2: 0, 3: 0, 4: 0, 5: 0};
  const totalReviews = stats.totalReviews || 0;
  
  reviewsTab.innerHTML = `
    <h2>Gerenciamento de Avaliações</h2>
    
    <div class="stats-summary">
      <div class="stats-row">
        <div class="card">
          <h3>Total de Avaliações</h3>
          <p>${totalReviews}</p>
        </div>
        <div class="card">
          <h3>Média Geral</h3>
          <p>${stats.averageRating ? stats.averageRating.toFixed(1) : 'N/A'} <i class="fas fa-star" style="color: var(--letterboxd-green);"></i></p>
        </div>
        <div class="card">
          <h3>Filme Mais Avaliado</h3>
          <p>${stats.mostReviewedMovie?.title || 'Nenhum'}</p>
          <small>${stats.mostReviewedMovie?.count || 0} avaliações</small>
        </div>
      </div>
      
      <div class="stats-row">
        <div class="card">
          <h3>Distribuição por Estrelas</h3>
          <div class="rating-distribution">
            ${renderRatingDistribution(ratingDistribution, totalReviews)}
          </div>
        </div>
      </div>
    </div>
    
    <h3>Lista de Avaliações</h3>
    <div class="table-container">
      <table id="reviews-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Filme</th>
            <th>Usuário</th>
            <th>Nota</th>
            <th>Comentário</th>
            <th>Data</th>
            <th>Ações</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td colspan="7">Carregando avaliações...</td>
          </tr>
        </tbody>
      </table>
    </div>
  `;
}

function renderRatingDistribution(distribution, totalReviews) {
  const ratings = [5, 4, 3, 2, 1];
  
  return `
    <div class="rating-bars">
      ${ratings.map(stars => {
        const count = distribution[stars] || 0;
        const percentage = totalReviews ? Math.round((count / totalReviews) * 100) : 0;
        
        return `
          <div class="rating-bar-row">
            <div class="rating-label">${stars} <i class="fas fa-star" style="color: var(--letterboxd-green);"></i></div>
            <div class="rating-bar-container">
              <div class="rating-bar" style="width: ${percentage}%"></div>
            </div>
            <div class="rating-count">${count} (${percentage}%)</div>
          </div>
        `;
      }).join('')}
    </div>
  `;
}

function renderReviewsTable(reviews) {
  const tableBody = document.querySelector('#reviews-table tbody');
  if (!tableBody) return;
  
  if (reviews.length === 0) {
    tableBody.innerHTML = '<tr><td colspan="7">Nenhuma avaliação encontrada</td></tr>';
    return;
  }
  
  tableBody.innerHTML = reviews.map(review => {
    const createdAt = review.createdAt ? new Date(review.createdAt).toLocaleDateString('pt-BR') : 'N/A';
    const commentPreview = review.comment ? 
      (review.comment.length > 50 ? review.comment.substring(0, 50) + '...' : review.comment) : 
      'Sem comentário';
    
    const safeMovieTitle = review.movie?.title ? review.movie.title.replace(/'/g, "\\'") : 'Filme';
    
    return `
      <tr>
        <td>${review.id}</td>
        <td>${review.movie?.title || 'N/A'}</td>
        <td>${review.user?.name || 'N/A'}</td>
        <td>${review.rating} <i class="fas fa-star" style="color: var(--letterboxd-green);"></i></td>
        <td>${commentPreview}</td>
        <td>${createdAt}</td>
        <td>
          <div class="user-actions">
            <button class="btn btn-small btn-primary" 
              onclick="viewReview(${review.id}, ${review.movie?.id})">
              <i class="fas fa-eye"></i> Ver
            </button>
            <button class="btn btn-small btn-danger" 
              onclick="confirmDeleteReview(${review.id}, '${safeMovieTitle}')">
              <i class="fas fa-trash"></i> Excluir
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join('');
  
  window.viewReview = viewReview;
  window.confirmDeleteReview = confirmDeleteReview;
}

async function loadMovies() {
  try {
    console.log('Carregando filmes...');
    const token = authService.getToken();
    
    if (!token) {
      throw new Error('Token de autenticação não encontrado');
    }
    
    // Carregar estatísticas
    const statsResponse = await fetch(`${API_URL}/movies/admin/stats`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      credentials: 'include'
    });
    
    if (!statsResponse.ok) {
      // Tentar renovar token em caso de falha de autorização
      if (statsResponse.status === 401) {
        const renewed = await authService.refreshToken();
        if (renewed) {
          // Tentar novamente com o novo token
          return loadMovies();
        }
      }
      
      throw new Error(`Erro ao carregar estatísticas: ${statsResponse.status}`);
    }
    
    const stats = await statsResponse.json();
    
    // Carregar lista de filmes
    const listResponse = await fetch(`${API_URL}/movies/admin/list`, {
      headers: {
        'Authorization': `Bearer ${authService.getToken()}`,
        'Content-Type': 'application/json'
      },
      credentials: 'include'
    });
    
    if (!listResponse.ok) {
      throw new Error(`Erro ao carregar lista: ${listResponse.status}`);
    }
    
    const moviesList = await listResponse.json();
    
    // Renderizar conteúdo
    const moviesTab = document.getElementById('movies-tab');
    if (moviesTab) {
      moviesTab.innerHTML = `
        <h2>Gerenciamento de Filmes</h2>
        
        <div class="stats-summary">
          <div class="stats-row">
            <div class="card">
              <h3>Total de Filmes</h3>
              <p>${stats.totalMovies || 0}</p>
            </div>
            <div class="card">
              <h3>Gênero mais popular</h3>
              <p>${stats.topGenre || 'N/A'}</p>
              <small>${stats.topGenreCount || 0} filmes</small>
            </div>
            <div class="card">
              <h3>Filme melhor avaliado</h3>
              <p>${stats.topRatedMovie?.title || 'N/A'}</p>
              <small>${stats.topRatedMovie?.rating ? stats.topRatedMovie.rating.toFixed(1) : 'N/A'} <i class="fas fa-star" style="color: var(--letterboxd-green);"></i></small>
            </div>
          </div>
        </div>
        
        <h3>Lista de Filmes</h3>
        <div class="table-container">
          <table id="movies-table" class="admin-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Título</th>
                <th>Ano</th>
                <th>Gênero</th>
                <th>Diretor</th>
                <th>Avaliação</th>
                <th>Ações</th>
              </tr>
            </thead>
            <tbody>
              ${moviesList.length > 0 
                ? moviesList.map(movie => `
                  <tr>
                    <td>${movie.id}</td>
                    <td>${movie.title}</td>
                    <td>${movie.releaseYear || 'N/A'}</td>
                    <td>${movie.genre || 'N/A'}</td>
                    <td>${movie.director || 'N/A'}</td>
                    <td>${movie.averageRating ? movie.averageRating.toFixed(1) : 'N/A'} 
                      ${movie.averageRating ? '<i class="fas fa-star" style="color: var(--letterboxd-green);"></i>' : ''}
                    </td>
                    <td class="actions-column">
                      <button class="btn btn-sm btn-edit" onclick="editMovie(${movie.id})">
                        <i class="fas fa-edit"></i>
                      </button>
                      <button class="btn btn-sm btn-delete" onclick="deleteMovie(${movie.id})">
                        <i class="fas fa-trash"></i>
                      </button>
                    </td>
                  </tr>
                `).join('') 
                : '<tr><td colspan="7">Nenhum filme encontrado</td></tr>'
              }
            </tbody>
          </table>
        </div>
      `;
      
      window.editMovie = editMovie;
      window.deleteMovie = deleteMovie;
    }
    
  } catch (error) {
    console.error('Erro ao carregar filmes:', error);
    const moviesTab = document.getElementById('movies-tab');
    if (moviesTab) {
      moviesTab.innerHTML = `
        <h2>Gerenciamento de Filmes</h2>
        <div class="error-message">
          <p>Erro: ${error.message}</p>
          <button class="btn btn-primary" onclick="window.location.reload()">Tentar novamente</button>
        </div>
      `;
    }
    showNotification(`Erro: ${error.message}`, 'error');
  }
}

// Funções para gerenciar filmes
function editMovie(id) {
  window.location.href = `edit.html?id=${id}`;
}

async function deleteMovie(id) {
  try {
    const token = authService.getToken();
    if (!token) {
      throw new Error('Token de autenticação não encontrado');
    }
    
    // Obter informações do filme
    const movieResponse = await fetch(`${API_URL}/movies/${id}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      credentials: 'include'
    });
    
    if (!movieResponse.ok) {
      throw new Error(`Erro ao obter detalhes: ${movieResponse.status}`);
    }
    
    const movie = await movieResponse.json();
    const movieTitle = movie.title || `ID ${id}`;
    
    if (confirm(`Tem certeza que deseja excluir o filme "${movieTitle}"? Esta ação não pode ser desfeita.`)) {
      const response = await fetch(`${API_URL}/movies/${id}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        credentials: 'include'
      });
      
      if (!response.ok) {
        let errorMessage = `Erro: ${response.status} ${response.statusText}`;
        try {
          const errorData = await response.json();
          errorMessage = errorData.message || errorData.error || errorMessage;
        } catch (e) {}
        throw new Error(errorMessage);
      }
      
      let result;
      try {
        result = await response.json();
      } catch (e) {
        result = { message: `Filme "${movieTitle}" excluído com sucesso` };
      }
      
      showNotification(result.message || `Filme excluído com sucesso`, 'success');
      
      // Recarregar lista de filmes
      setTimeout(() => loadMovies(), 500);
    }
  } catch (error) {
    console.error('Erro ao excluir filme:', error);
    showNotification(error.message, 'error');
  }
}

function viewReview(reviewId, movieId) {
  if (movieId) {
    window.location.href = `movie-detail.html?id=${movieId}&review=${reviewId}`;
  } else {
    showNotification('ID do filme não disponível', 'error');
  }
}

function confirmDeleteReview(reviewId, movieTitle) {
  if (confirm(`Tem certeza que deseja excluir a avaliação do filme "${movieTitle}"?`)) {
    deleteReview(reviewId);
  }
}

async function deleteReview(reviewId) {
  try {
    const token = authService.getToken();
    if (!token) {
      throw new Error('Token de autenticação não encontrado');
    }
    
    const response = await fetch(`${API_URL}/reviews/admin/${reviewId}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error(`Erro ao excluir avaliação (${response.status})`);
    }
    
    const result = await response.json();
    showNotification(result.message || 'Avaliação excluída com sucesso', 'success');
    
    // Recarregar dados
    loadReviews();
  } catch (error) {
    console.error('Erro ao excluir avaliação:', error);
    showNotification(error.message, 'error');
  }
}

async function promoteUser(userId, userName) {
  if (confirm(`Tem certeza que deseja promover ${userName} para ADMINISTRADOR?`)) {
    try {
      const token = authService.getToken();
      if (!token) {
        throw new Error('Token de autenticação não encontrado');
      }
      
      const response = await fetch(`${API_URL}/users/admin/users/${userId}/promote`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        credentials: 'include'
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        try {
          const errorJson = JSON.parse(errorText);
          throw new Error(errorJson.error || errorJson.message || 'Erro ao promover usuário');
        } catch (e) {
          throw new Error(`Erro: ${errorText || response.statusText}`);
        }
      }
      
      const result = await response.json();
      showNotification(result.message || 'Usuário promovido com sucesso', 'success');
      
      // Recarregar dados
      loadUsers();
    } catch (error) {
      console.error('Erro ao promover usuário:', error);
      showNotification(error.message, 'error');
    }
  }
}

async function demoteUser(userId, userName) {
  if (confirm(`Tem certeza que deseja rebaixar ${userName} para usuário comum?`)) {
    try {
      const token = authService.getToken();
      if (!token) {
        throw new Error('Token de autenticação não encontrado');
      }
      
      const response = await fetch(`${API_URL}/users/admin/users/${userId}/demote`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        credentials: 'include'
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        try {
          const errorJson = JSON.parse(errorText);
          throw new Error(errorJson.error || errorJson.message || 'Erro ao rebaixar usuário');
        } catch (e) {
          throw new Error(`Erro: ${errorText || response.statusText}`);
        }
      }
      
      const result = await response.json();
      showNotification(result.message || 'Usuário rebaixado com sucesso', 'success');
      
      // Recarregar dados
      loadUsers();
    } catch (error) {
      console.error('Erro ao rebaixar usuário:', error);
      showNotification(error.message, 'error');
    }
  }
}

function confirmDeleteUser(userId, userName) {
  if (confirm(`ATENÇÃO: Esta ação é irreversível. Tem certeza que deseja excluir o usuário ${userName}?`)) {
    deleteUser(userId, userName);
  }
}

async function deleteUser(userId, userName) {
  try {
    const token = authService.getToken();
    if (!token) {
      throw new Error('Token de autenticação não encontrado');
    }
    
    const response = await fetch(`${API_URL}/users/admin/users/${userId}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      credentials: 'include'
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      try {
        const errorJson = JSON.parse(errorText);
        throw new Error(errorJson.error || errorJson.message || 'Erro ao excluir usuário');
      } catch (e) {
        throw new Error(`Erro: ${errorText || response.statusText}`);
      }
    }
    
    const result = await response.json();
    showNotification(result.message || 'Usuário excluído com sucesso', 'success');
    
    // Recarregar dados
    loadUsers();
  } catch (error) {
    console.error('Erro ao excluir usuário:', error);
    showNotification(error.message, 'error');
  }
}

// Exportar funções para os botões
window.editMovie = editMovie;
window.deleteMovie = deleteMovie;
window.viewReview = viewReview;
window.confirmDeleteReview = confirmDeleteReview;
window.deleteReview = deleteReview;
window.promoteUser = promoteUser;
window.demoteUser = demoteUser;
window.confirmDeleteUser = confirmDeleteUser;
window.deleteUser = deleteUser;
window.retryLoadUsers = retryLoadUsers;
window.debugAuth = debugAuth;