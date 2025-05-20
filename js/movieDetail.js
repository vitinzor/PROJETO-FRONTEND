// js/movieDetail.js - Versão completa e atualizada

import { authService } from './auth.js';
import { showNotification, starRating, formatDate, handleApiError } from './utils.js';
import { movieService } from './main.js';

const movieId = new URLSearchParams(window.location.search).get('id');
const config = {
    baseUrl: 'http://localhost:3000',
    endpoints: {
        movie: '/movies',
        reviews: '/reviews',
        users: '/users' // Adicionado endpoint para usuários
    }
};

// Elementos DOM
const dom = {
    moviePoster: document.getElementById('movie-poster'),
    movieTitle: document.getElementById('movie-title'),
    movieYear: document.getElementById('movie-year'),
    movieDirector: document.getElementById('movie-director'),
    movieGenre: document.getElementById('movie-genre'),
    movieDuration: document.getElementById('movie-duration'),
    movieDescription: document.getElementById('movie-description'),
    movieMeta: document.querySelector('.movie-meta'),
    ratingValue: document.getElementById('rating-value'),
    averageRating: document.getElementById('average-rating'),
    ratingCount: document.getElementById('rating-count'),
    reviewsList: document.getElementById('reviews-list'),
    reviewForm: document.getElementById('review-form'),
    reviewsCount: document.getElementById('reviews-count'),
    sortButton: document.getElementById('sort-reviews'),
    movieActions: document.getElementById('movie-actions'),
    editMovieBtn: document.getElementById('edit-movie-btn'),
    deleteMovieBtn: document.getElementById('delete-movie-btn'),
    activityHistoryButton: document.querySelector('.activity-history-button')
};

// Estado da aplicação
let state = {
    reviews: [],
    sortOrder: 'recent-desc', // Ordenação padrão: mais recentes primeiro
    movie: null
};

// Configuração de estrelas interativas CORRIGIDA
const initStarRating = () => {
    const stars = document.querySelectorAll('.star-rating-input label');
    const inputs = document.querySelectorAll('.star-rating-input input');
    
    // Limpar todas as seleções iniciais
    inputs.forEach(input => {
        input.checked = false;
    });
    
    stars.forEach(star => {
        star.classList.remove('active');
    });
    
    // Adicionar evento de clique para cada estrela
    stars.forEach((star, index) => {
        star.addEventListener('click', () => {
            // Pegar o valor correto (5 - index porque os elementos estão em ordem reversa)
            const ratingValue = 5 - index;
            
            // Encontrar o input correspondente e marcá-lo
            const input = document.querySelector(`input[value="${ratingValue}"]`);
            if (input) {
                // Desmarcar todos os inputs primeiro
                inputs.forEach(inp => inp.checked = false);
                
                // Marcar apenas o input correspondente
                input.checked = true;
            }
            
            // Atualizar classes visuais - CORREÇÃO AQUI
            stars.forEach((s, i) => {
                // Remover 'active' de todas as estrelas
                s.classList.remove('active');
            });
            
            // Adicionar 'active' apenas às estrelas que deveriam estar ativas
            // Como os elementos estão em ordem reversa (de 5 a 1), precisamos aplicar a lógica correta
            for (let i = 0; i < ratingValue; i++) {
                stars[stars.length - 1 - i].classList.add('active');
            }
        });
    });
};

// Configura o botão de histórico de atividade para redirecionar para o perfil
const setupActivityHistoryButton = () => {
    // Verificar se o botão existe
    if (!dom.activityHistoryButton) return;

    // Adicionar evento de clique para redirecionar para o perfil
    dom.activityHistoryButton.addEventListener('click', () => {
        if (!authService.isAuthenticated()) {
            showNotification('Você precisa estar logado para ver suas avaliações.', 'info');
            localStorage.setItem('redirectTo', window.location.pathname);
            window.location.href = 'login.html';
            return;
        }

        // Redirecionar para a página de perfil, com a aba de avaliações ativa
        window.location.href = 'profile.html?tab=reviews';
    });
};

// Calcular média de avaliações
const calculateAverageRating = (reviews) => {
    if (!reviews || reviews.length === 0) return 0;
    const sum = reviews.reduce((total, review) => total + review.rating, 0);
    return sum / reviews.length;
};

// Verifica permissões do usuário para o filme
const checkUserPermissions = () => {
    // Verificar explicitamente se o usuário está autenticado e se o objeto authState existe
    if (!authService.isAuthenticated() || !authService.authState) {
        console.log('Usuário não autenticado ou estado de autenticação não disponível');
        return false;
    }
    
    const currentUser = authService.authState.currentUser;
    if (!currentUser || !currentUser.id) {
        console.log('Dados do usuário não disponíveis');
        return false;
    }
    
    const movieDetails = state.movie;
    if (!movieDetails) {
        console.log('Detalhes do filme não disponíveis');
        return false;
    }
    
    const currentUserId = String(currentUser.id);
    console.log(`Verificando permissões para usuário ID: ${currentUserId}`);
    
    // Determinar o ID do criador do filme
    let movieCreatorId = null;
    if (movieDetails.addedByUserId) {
        movieCreatorId = String(movieDetails.addedByUserId);
    } else if (movieDetails.addedBy && movieDetails.addedBy.id) {
        movieCreatorId = String(movieDetails.addedBy.id);
    } else if (movieDetails.createdBy) {
        movieCreatorId = String(movieDetails.createdBy);
    } else if (movieDetails.userId) {
        movieCreatorId = String(movieDetails.userId);
    }
    
    const isAdmin = currentUser.role === 'ADMIN';
    
    // Log para depuração
    console.log(`Criador do filme ID: ${movieCreatorId}, Usuário é admin: ${isAdmin}`);
    
    const hasPermission = (movieCreatorId && currentUserId === movieCreatorId) || isAdmin;
    console.log(`Usuário tem permissão: ${hasPermission}`);
    
    return hasPermission;
};

// Configurar botões de ação
const setupActionButtons = () => {
    if (!dom.movieActions) return;
    
    const isOwner = checkUserPermissions();
    
    if (isOwner) {
        dom.movieActions.style.display = 'flex';
        
        // Configurar botão de edição
        if (dom.editMovieBtn) {
            const editUrl = `./edit.html?id=${movieId}`;
            dom.editMovieBtn.href = editUrl;
            dom.editMovieBtn.onclick = (e) => {
                e.preventDefault();
                window.location.href = editUrl;
            };
        }
        
        // Configurar botão de exclusão
        if (dom.deleteMovieBtn) {
            // Remover event listeners antigos para evitar duplicação
            const newDeleteBtn = dom.deleteMovieBtn.cloneNode(true);
            dom.deleteMovieBtn.parentNode.replaceChild(newDeleteBtn, dom.deleteMovieBtn);
            dom.deleteMovieBtn = newDeleteBtn;
            
            dom.deleteMovieBtn.addEventListener('click', async () => {
                if (confirm('Tem certeza que deseja excluir este filme? Esta ação não pode ser desfeita.')) {
                    try {
                        const deleted = await movieService.deleteMovie(movieId);
                        
                        if (deleted) {
                            showNotification('Filme excluído com sucesso!', 'success');
                            setTimeout(() => {
                                window.location.href = 'index.html';
                            }, 1500);
                        } else {
                            showNotification('Não foi possível excluir o filme. Tente novamente.', 'error');
                        }
                    } catch (error) {
                        showNotification('Erro ao excluir o filme. Tente novamente.', 'error');
                    }
                }
            });
        }
    } else {
        dom.movieActions.style.display = 'none';
    }
};

// Carrega dados do filme
const loadMovieDetails = async () => {
    try {
        const response = await fetch(`${config.baseUrl}${config.endpoints.movie}/${movieId}`);
        if (!response.ok) return handleApiError(response);
        
        const movie = await response.json();
        state.movie = movie;
        
        // Preencher informações básicas
        dom.moviePoster.src = movie.imageUrl || 'https://via.placeholder.com/230x345?text=Sem+Imagem';
        dom.moviePoster.onerror = function() { 
            this.src = 'https://via.placeholder.com/230x345?text=Sem+Imagem'; 
        };

        document.title = `${movie.title} | CineLog`;
        
        // MODIFICADO: Configuração melhorada do título com quebra de linha forçada
        dom.movieTitle.textContent = movie.title;
        dom.movieTitle.style.width = '100%';
        dom.movieTitle.style.whiteSpace = 'normal';
        dom.movieTitle.style.wordWrap = 'break-word';
        dom.movieTitle.style.overflowWrap = 'break-word';
        dom.movieTitle.style.wordBreak = 'break-word';
        dom.movieTitle.style.hyphens = 'auto';
        dom.movieTitle.style.maxWidth = '100%';

        // Modificar o layout da seção header para garantir quebra correta
        const movieHeader = document.querySelector('.movie-header');
        if (movieHeader) {
            // Mudando para grid layout ao invés de flex para melhor controle
            movieHeader.style.display = 'grid';
            movieHeader.style.gridTemplateColumns = 'auto 1fr';
            movieHeader.style.width = '100%';
        }
        
        // Garantir que o container de informações tenha tamanho adequado
        const movieInfo = document.querySelector('.movie-info');
        if (movieInfo) {
            movieInfo.style.minWidth = '0'; // Crucial para flex/grid containers
            movieInfo.style.width = '100%';
            movieInfo.style.maxWidth = '100%';
        }

        // CORRIGIDO: Exibir metadados do filme com melhor controle de visibilidade
        let visibleMetadataCount = 0;
        
        if (movie.releaseYear && dom.movieYear) {
            dom.movieYear.textContent = movie.releaseYear;
            dom.movieYear.style.display = 'inline-block';
            visibleMetadataCount++;
        } else if (dom.movieYear) {
            dom.movieYear.style.display = 'none';
        }
        
        if (movie.director && dom.movieDirector) {
            dom.movieDirector.textContent = `Dirigido por ${movie.director}`;
            dom.movieDirector.style.display = 'inline-block';
            visibleMetadataCount++;
        } else if (dom.movieDirector) {
            dom.movieDirector.style.display = 'none';
        }

        if (movie.duration && dom.movieDuration) {
            dom.movieDuration.textContent = `${movie.duration} min`;
            dom.movieDuration.style.display = 'inline-block';
            visibleMetadataCount++;
        } else if (dom.movieDuration) {
            dom.movieDuration.style.display = 'none';
        }
        
        // Mostrar ou esconder o contêiner de metadados baseado em seu conteúdo
        if (dom.movieMeta) {
            dom.movieMeta.style.display = visibleMetadataCount > 0 ? 'flex' : 'none';
            // ADICIONADO: Garantir que os metadados quebrem linha quando necessário
            dom.movieMeta.style.flexWrap = 'wrap';
            dom.movieMeta.style.width = '100%';
        }
        
        // CORRIGIDO: Ajuste para o último item de metadados que deve não ter separador
        const metaItems = document.querySelectorAll('.movie-meta-item');
        metaItems.forEach(item => {
            // Por padrão, remova todas as classes de último item e redefina o estilo
            item.classList.remove('last-item');
        });

        // Encontrar o último item visível e remover seu separador
        let lastVisibleItem = null;
        metaItems.forEach(item => {
            if (item.style.display !== 'none') {
                lastVisibleItem = item;
            }
        });
        
        if (lastVisibleItem) {
            lastVisibleItem.classList.add('last-item');
            // Aplicar estilo diretamente ao elemento para garantir que o separador não apareça
            lastVisibleItem.style.cssText += '; position: relative;';
            lastVisibleItem.style.setProperty('--pseudo-display', 'none', 'important');
        }
        
        // Atualizar o estilo inline de cada item para garantir que os separadores funcionem
        metaItems.forEach((item, index) => {
            if (item === lastVisibleItem) {
                // Último item visível não deve ter separador
                item.style.setProperty('--pseudo-display', 'none', 'important');
                item.dataset.isLast = 'true';
            } else if (item.style.display !== 'none') {
                // Outros itens visíveis devem ter separador
                item.style.setProperty('--pseudo-display', 'block');
                item.dataset.isLast = 'false';
            }
        });
        
        // Gerenciar visibilidade do gênero
        if (dom.movieGenre && movie.genre) {
            dom.movieGenre.textContent = movie.genre;
            dom.movieGenre.style.display = 'block';
            // ADICIONADO: Garantir que o gênero quebre linha quando necessário
            dom.movieGenre.style.wordWrap = 'break-word'; 
            dom.movieGenre.style.width = '100%';
        } else if (dom.movieGenre) {
            dom.movieGenre.style.display = 'none';
        }
        
        dom.movieDescription.textContent = movie.description || 'Sem descrição disponível.';
        // ADICIONADO: Garantir que a descrição quebre linha quando necessário
        dom.movieDescription.style.wordWrap = 'break-word';
        dom.movieDescription.style.width = '100%';
        
        // Calcular média de avaliações
        let averageRating = 0;
        if (movie.reviews && movie.reviews.length > 0) {
            averageRating = calculateAverageRating(movie.reviews);
            state.reviews = movie.reviews;
        }
        
        // Atualizar exibição da média
        if (dom.ratingValue) {
            dom.ratingValue.textContent = averageRating > 0 ? averageRating.toFixed(1) : '0.0';
        }
        
        if (dom.averageRating) {
            dom.averageRating.innerHTML = starRating(averageRating, true);
        }
        
        if (dom.ratingCount && movie.reviews) {
            dom.ratingCount.textContent = movie.reviews.length;
        }

        // Verificar se o usuário atual já avaliou o filme
        checkUserReview();

        // Configurar botões de ação e UI
        setupActionButtons();
        
        // Renderizar reviews ou carregá-las separadamente
        if (movie.reviews && Array.isArray(movie.reviews)) {
            applySorting();
            renderReviews();
        } else {
            await loadReviews();
        }
        
        updateAuthUI();
        
    } catch (error) {
        showNotification('Erro ao carregar detalhes do filme', 'error');
        console.error(error);
    }

    // Adicionado ao final de loadMovieDetails:
    setTimeout(() => {
        // Verificar permissões novamente após um breve atraso para garantir que authState esteja carregado
        setupActionButtons();
        renderReviews(); // Para garantir que os botões de exclusão apareçam corretamente
    }, 500);
};

// Verifica se o usuário atual já avaliou este filme
const checkUserReview = () => {
    if (!authService.isAuthenticated() || !state.reviews.length) return;
    
    const currentUser = authService.authState.currentUser;
    if (!currentUser || !currentUser.id) return;
    
    // Filtrar todas as avaliações do usuário atual
    const userReviews = state.reviews.filter(review => {
        const reviewUserId = review.userId || (review.user && review.user.id);
        return reviewUserId && String(reviewUserId) === String(currentUser.id);
    });
    
    if (userReviews.length === 0) return;
    
    // Ordenar por data mais recente primeiro
    userReviews.sort((a, b) => {
        const dateA = a.updatedAt ? new Date(a.updatedAt) : new Date(a.createdAt);
        const dateB = b.updatedAt ? new Date(b.updatedAt) : new Date(b.createdAt);
        return dateB - dateA;
    });
    
    // Pegar a avaliação mais recente
    const latestReview = userReviews[0];
    
    console.log("Avaliação mais recente encontrada:", latestReview);
    
    // Se encontrou uma avaliação do usuário atual, preencher o formulário
    const ratingInput = document.querySelector(`input[name="rating"][value="${latestReview.rating}"]`);
    if (ratingInput) {
        ratingInput.checked = true;
        
        // Atualizar a visualização das estrelas
        const stars = document.querySelectorAll('.star-rating-input label');
        stars.forEach(star => star.classList.remove('active'));
        
        // Adicionar classe active às estrelas correspondentes
        // Como as estrelas estão em ordem reversa, precisamos calculá-las corretamente
        for (let i = 0; i < latestReview.rating; i++) {
            const starIndex = stars.length - 1 - i;
            if (starIndex >= 0) {
                stars[starIndex].classList.add('active');
            }
        }
    }
    
    // Preencher o comentário
    const commentTextarea = document.getElementById('comment');
    if (commentTextarea && latestReview.comment) {
        commentTextarea.value = latestReview.comment;
    }
    
    // Mudar o texto do botão para "Atualizar Avaliação"
    const submitButton = document.getElementById('review-form');
    if (submitButton) {
        submitButton.textContent = 'Atualizar Avaliação';
    }
};

// Carrega e exibe reviews
const loadReviews = async () => {
    try {
        const response = await fetch(
            `${config.baseUrl}${config.endpoints.movie}/${movieId}${config.endpoints.reviews}`
        );
        if (!response.ok) return handleApiError(response);
        
        state.reviews = await response.json();
        
        // DEBUG: Verificar o formato dos dados recebidos
        console.log("Reviews carregadas:", state.reviews);
        
        // Recalcular média de avaliações
        const averageRating = calculateAverageRating(state.reviews);
        if (dom.ratingValue) {
            dom.ratingValue.textContent = averageRating > 0 ? averageRating.toFixed(1) : '0.0';
        }
        
        if (dom.averageRating) {
            dom.averageRating.innerHTML = starRating(averageRating, true);
        }
        
        if (dom.ratingCount) {
            dom.ratingCount.textContent = state.reviews.length;
        }
        
        // Verificar se o usuário atual já avaliou o filme
        checkUserReview();
        
        applySorting();
        renderReviews();
    } catch (error) {
        showNotification('Erro ao carregar avaliações', 'error');
        console.error(error);
    }
};

// Array de cores para avatares
const avatarColors = [
    '#1abc9c', '#2ecc71', '#3498db', '#9b59b6', '#34495e',
    '#16a085', '#27ae60', '#2980b9', '#8e44ad', '#2c3e50',
    '#f1c40f', '#e67e22', '#e74c3c', '#ecf0f1', '#95a5a6',
    '#f39c12', '#d35400', '#c0392b', '#bdc3c7', '#7f8c8d'
];

// Função para carregar os avatares reais
function loadAvatars() {
    document.querySelectorAll('.user-avatar[data-filename]').forEach(avatarElement => {
        const filename = avatarElement.dataset.filename;
        const userInitial = avatarElement.dataset.initial || 'U';
        
        // Se não tiver nome de arquivo, usar avatar com inicial
        if (!filename) {
            createInitialAvatar(avatarElement, userInitial);
            return;
        }
        
        // CORRIGIDO: Usar o caminho correto para a pasta de avatares no Cloudinary
        const img = new Image();
        
        // A pasta correta é "cinelog/avatars" de acordo com seu controller
        img.src = `https://res.cloudinary.com/dz4v2tibm/image/upload/cinelog/avatars/${filename}`;
        
        img.alt = "Avatar do usuário";
        img.className = "avatar-image";
        
        // Adicionar log para debug
        console.log(`Tentando carregar avatar: ${img.src}`);
        
        // Se a imagem carregar com sucesso
        img.onload = function() {
            console.log(`Avatar carregado com sucesso: ${img.src}`);
            avatarElement.innerHTML = '';
            avatarElement.appendChild(img);
        };
        
        // Se a imagem falhar, mostrar a inicial
        img.onerror = function() {
            console.error(`Falha ao carregar imagem do Cloudinary: ${img.src}`);
            createInitialAvatar(avatarElement, userInitial);
        };
    });
}

// Função auxiliar para criar avatar com inicial
function createInitialAvatar(element, initial) {
    // Gerar uma cor consistente baseada na inicial
    const colorIndex = initial.charCodeAt(0) % avatarColors.length;
    const bgColor = avatarColors[colorIndex];
    
    // Criar o avatar com inicial
    element.innerHTML = `<span style="
        display: flex;
        align-items: center;
        justify-content: center;
        width: 100%;
        height: 100%;
        background-color: ${bgColor};
        color: white;
        font-weight: bold;
        border-radius: 50%;
        text-transform: uppercase;
    ">${initial}</span>`;
}

// Verificar se o usuário atual é um administrador
const isCurrentUserAdmin = () => {
    if (!authService.isAuthenticated() || !authService.authState || !authService.authState.currentUser) {
        return false;
    }
    return authService.authState.currentUser.role === 'ADMIN';
};

// Renderiza reviews
const renderReviews = () => {
    dom.reviewsList.innerHTML = state.reviews.length > 0 
        ? state.reviews.map(reviewTemplate).join('')
        : '<p class="empty-state">Seja o primeiro a avaliar este filme!</p>';
    
    dom.reviewsCount.textContent = `(${state.reviews.length})`;
    
    // Chamar loadAvatars após renderizar o HTML
    loadAvatars();
    
    // ADICIONADO: Garantir que todos os textos de comentários quebrem linha quando necessário
    document.querySelectorAll('.review-comment').forEach(comment => {
        comment.style.wordWrap = 'break-word';
        comment.style.overflowWrap = 'break-word';
        comment.style.wordBreak = 'break-word';
    });
    
    // ADICIONADO: Garantir que os nomes de usuário também quebrem linha quando necessário
    document.querySelectorAll('.username').forEach(username => {
        username.style.wordWrap = 'break-word';
        username.style.overflowWrap = 'break-word';
        username.style.wordBreak = 'break-word';
    });
};

const reviewTemplate = (review) => {
    const user = review.user || {};
    
    // Buscar nome do usuário
    const userName = user.name || review.userName || 
                    (review.addedBy && review.addedBy.name) || 'Usuário Anônimo';
    const userInitial = userName.charAt(0).toUpperCase() || 'U';
    
    // Extrair apenas o nome do arquivo, se houver avatarUrl
    let filename = '';
    if (user.avatarUrl) {
        // Verificar se é uma URL do Cloudinary
        if (user.avatarUrl.includes('cloudinary.com')) {
            // Para URLs do Cloudinary, precisamos apenas do nome do arquivo
            filename = user.avatarUrl.split('/').pop();
        } else {
            // Para qualquer outro formato de URL
            filename = user.avatarUrl.split('/').pop();
        }
        console.log("Nome do arquivo de avatar:", filename);
    }
    
    // Verificar se é o proprietário da avaliação ou se é admin
    const currentUser = authService.authState && authService.authState.currentUser;
    const isOwner = currentUser && (
        (user.id && String(user.id) === String(currentUser.id)) || 
        (review.userId && String(review.userId) === String(currentUser.id))
    );
    const isAdmin = currentUser && currentUser.role === 'ADMIN';
    
    // Tratar texto do comentário
    const commentText = review.comment && review.comment.trim() 
        ? review.comment 
        : '<em>Avaliação sem comentário</em>';
    
    // Gerar ID único para este avatar
    const avatarId = `avatar-${review.id}-${Date.now()}`;
    
    // Template com placeholder para o avatar que será carregado depois
    return `
        <div class="review-card" data-review-id="${review.id}">
            <div class="review-header">
                <div class="user-avatar" id="${avatarId}" data-filename="${filename}" data-initial="${userInitial}">
                    <span>${userInitial}</span>
                </div>
                <div class="user-info">
                    <span class="username">${userName}</span>
                    <div class="review-meta">
                        ${starRating(review.rating, false)}
                        <span class="review-date">${formatDate(review.createdAt)}</span>
                    </div>
                </div>
                ${isOwner ? `
                <div class="review-actions">
                    <button class="btn-icon btn-delete" data-action="delete" data-review-id="${review.id}" aria-label="Excluir avaliação">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>` : ''}
                ${isAdmin && !isOwner ? `
                <div class="review-actions">
                    <button class="btn-icon btn-delete admin-delete-review-btn" data-action="admin-delete" data-review-id="${review.id}" aria-label="Excluir avaliação (Admin)">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>` : ''}
            </div>
            <p class="review-comment">${commentText}</p>
        </div>
    `;
};

// Aplica a ordenação selecionada às reviews - versão atualizada
const applySorting = () => {
    // Para depuração: verificar se temos reviews para ordenar
    console.log(`Ordenando ${state.reviews.length} avaliações por: ${state.sortOrder}`);
    
    if (state.reviews.length === 0) return;
    
    // Extrair o critério e a direção da ordenação
    const [criterion, direction] = state.sortOrder.split('-');
    const isAscending = direction === 'asc';
    
    state.reviews.sort((a, b) => {
        if (criterion === 'recent') {
            // Ordenar por data
            const dateComparison = new Date(b.createdAt) - new Date(a.createdAt);
            return isAscending ? -dateComparison : dateComparison;
        } else {
            // Ordenar por classificação
            // Em caso de empate nas estrelas, usar a data como critério secundário
            if (b.rating === a.rating) {
                const dateComparison = new Date(b.createdAt) - new Date(a.createdAt);
                return isAscending ? -dateComparison : dateComparison;
            }
            const ratingComparison = b.rating - a.rating;
            return isAscending ? -ratingComparison : ratingComparison;
        }
    });
    
    // Para depuração: verificar a primeira review após ordenação
    if (state.reviews.length > 0) {
        const first = state.reviews[0];
        console.log(`Primeira avaliação após ordenação: Rating=${first.rating}, Data=${first.createdAt}`);
    }
};

// Atualiza a UI baseada no estado de autenticação
const updateAuthUI = () => {
    const isAuthenticated = authService.isAuthenticated();
    
    document.querySelectorAll('[data-auth="authenticated"]').forEach(el => {
        el.style.display = isAuthenticated ? 'block' : 'none';
    });
    
    document.querySelectorAll('[data-auth="unauthenticated"]').forEach(el => {
        el.style.display = isAuthenticated ? 'none' : 'block';
    });
};

const handleReviewSubmit = async (event) => {
    event.preventDefault();
    
    if (!authService.isAuthenticated()) {
        showNotification('Você precisa estar logado para avaliar.', 'error');
        localStorage.setItem('redirectTo', window.location.pathname);
        window.location.href = 'login.html';
        return;
    }
    
    const rating = document.querySelector('input[name="rating"]:checked')?.value;
    // Vamos tentar com null em vez de string vazia
    const commentText = document.getElementById('comment').value;
    const comment = commentText.trim().length > 0 ? commentText.trim() : " ";

    if (!rating) {
        return showNotification('Selecione uma classificação de 1 a 5 estrelas', 'error');
    }
    
    try {
        const token = authService.getToken();
        
        // Constrói o payload de forma diferente
        const payload = { 
            rating: Number(rating)
        };
        
        // Só inclui comment se não for nulo
        if (comment !== null) {
            payload.comment = comment;
        }
        
        const response = await fetch(`${config.baseUrl}${config.endpoints.movie}/${movieId}${config.endpoints.reviews}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(payload)
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Erro ao enviar avaliação');
        }
        
        showNotification('Avaliação publicada com sucesso!', 'success');
        
        // Limpar formulário
        document.getElementById('comment').value = '';
        document.querySelectorAll('.star-rating-input label').forEach(star => {
            star.classList.remove('active');
        });
        document.querySelectorAll('input[name="rating"]').forEach(input => {
            input.checked = false;
        });
        
        // Recarregar avaliações
        await loadReviews();
    } catch (error) {
        showNotification(error.message || 'Erro ao enviar avaliação', 'error');
        console.error(error);
    }
};

// Exclui uma avaliação (como usuário normal)
const deleteReview = async (reviewId) => {
    try {
        const token = authService.getToken();
        if (!token) {
            showNotification('Você precisa estar logado para excluir avaliações.', 'error');
            return false;
        }
        
        // Converter para número
        const numericReviewId = parseInt(reviewId, 10);
        
        if (isNaN(numericReviewId)) {
            console.error('ID da avaliação inválido:', reviewId);
            showNotification('ID da avaliação inválido', 'error');
            return false;
        }
        
        // Enviar ID como parte do body
        const response = await fetch(`${config.baseUrl}${config.endpoints.movie}/${movieId}${config.endpoints.reviews}/${numericReviewId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ id: numericReviewId })
        });
        
        if (!response.ok) {
            let errorMessage;
            try {
                const errorData = await response.json();
                errorMessage = errorData.message || `Erro ao excluir (Status ${response.status})`;
            } catch (e) {
                errorMessage = `Erro ao excluir avaliação: ${response.statusText || response.status}`;
            }
            throw new Error(errorMessage);
        }
        
        showNotification('Avaliação excluída com sucesso!', 'success');
        return true;
    } catch (error) {
        console.error('Erro ao excluir avaliação:', error);
        showNotification(error.message || 'Erro ao excluir avaliação', 'error');
        return false;
    }
};

// Versão alternativa da função caso a primeira não funcione
const deleteReviewAsAdmin = async (reviewId) => {
    try {
        const token = authService.getToken();
        if (!token) {
            showNotification('Você precisa estar logado para excluir avaliações.', 'error');
            return false;
        }
        
        // Verificar se o usuário atual é administrador
        if (!isCurrentUserAdmin()) {
            showNotification('Apenas administradores podem excluir avaliações de outros usuários.', 'error');
            return false;
        }
        
        // Converter para número
        const numericReviewId = parseInt(reviewId, 10);
        
        if (isNaN(numericReviewId)) {
            console.error('ID da avaliação inválido:', reviewId);
            showNotification('ID da avaliação inválido', 'error');
            return false;
        }
        
        // URL alternativa: usando o endpoint de usuários admin
        const url = `${config.baseUrl}/users/admin/reviews/${numericReviewId}`;
        console.log('URL da exclusão de administrador (alternativa):', url);
        
        const response = await fetch(url, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        if (!response.ok) {
            let errorMessage;
            try {
                const errorData = await response.json();
                errorMessage = errorData.message || `Erro ao excluir (Status ${response.status})`;
            } catch (e) {
                errorMessage = `Erro ao excluir avaliação: ${response.statusText || response.status}`;
            }
            throw new Error(errorMessage);
        }
        
        showNotification('Avaliação excluída com sucesso (Admin)!', 'success');
        return true;
    } catch (error) {
        console.error('Erro ao excluir avaliação como admin:', error);
        showNotification(error.message || 'Erro ao excluir avaliação', 'error');
        return false;
    }
};

// Atualiza o ícone do botão de ordenação - versão atualizada
const updateSortButtonIcon = () => {
    if (!dom.sortButton) return;
    
    // Limpar o conteúdo atual
    while (dom.sortButton.firstChild) {
        dom.sortButton.removeChild(dom.sortButton.firstChild);
    }
    
    // Criar o novo ícone apropriado
    const icon = document.createElement('i');
    
    // Extrair o critério e a direção
    const [criterion, direction] = state.sortOrder.split('-');
    const isAscending = direction === 'asc';
    
    if (criterion === 'recent') {
        // Ícone para ordenação por data
        icon.className = isAscending ? 'fas fa-clock fa-flip-horizontal' : 'fas fa-clock';
        dom.sortButton.setAttribute('title', isAscending 
            ? 'Ordenado por mais antigas. Clique para ordenar por classificação crescente.' 
            : 'Ordenado por mais recentes. Clique para ordenar por mais antigas.'
        );
    } else {
        // Ícone para ordenação por classificação
        icon.className = isAscending ? 'fas fa-sort-numeric-down' : 'fas fa-sort-numeric-up';
        dom.sortButton.setAttribute('title', isAscending 
            ? 'Ordenado por classificação crescente. Clique para ordenar por classificação decrescente.' 
            : 'Ordenado por classificação decrescente. Clique para ordenar por data.'
        );
    }
    
    dom.sortButton.appendChild(icon);
};

// Configura todos os event listeners
const setupEventListeners = () => {
    // Botão de ordenação - lógica atualizada
    if (dom.sortButton) {
        // Definir o visual inicial do botão de ordenação
        updateSortButtonIcon();
        
        // Adicionar evento de clique para alternar ordenação (com 4 estados possíveis)
        dom.sortButton.addEventListener('click', () => {
            // Alterar o estado de ordenação em ciclo
            switch (state.sortOrder) {
                case 'recent-desc':
                    state.sortOrder = 'recent-asc';
                    break;
                case 'recent-asc':
                    state.sortOrder = 'rating-desc';
                    break;
                case 'rating-desc':
                    state.sortOrder = 'rating-asc';
                    break;
                case 'rating-asc':
                    state.sortOrder = 'recent-desc';
                    break;
                default:
                    state.sortOrder = 'recent-desc';
            }
            
            // Extrair critério e direção para mensagem
            const [criterion, direction] = state.sortOrder.split('-');
            const isAscending = direction === 'asc';
            
            // Mostrar notificação para o usuário
            let message = '';
            if (criterion === 'recent') {
                message = isAscending ? 'Avaliações ordenadas da mais antiga para a mais recente' : 'Avaliações ordenadas da mais recente para a mais antiga';
            } else {
                message = isAscending ? 'Avaliações ordenadas da menor para a maior classificação' : 'Avaliações ordenadas da maior para a menor classificação';
            }
            showNotification(message, 'info');
            
            // Atualizar o ícone do botão
            updateSortButtonIcon();
            
            // Aplicar a ordenação e renderizar as reviews
            applySorting();
            renderReviews();
        });
    }

    // Botões de exclusão de review
    if (dom.reviewsList) {
        dom.reviewsList.addEventListener('click', async (event) => {
            const deleteButton = event.target.closest('[data-action="delete"]');
            const adminDeleteButton = event.target.closest('[data-action="admin-delete"]');
            
            if (deleteButton) {
                // Exclusão normal pelo usuário dono da avaliação
                let reviewId = deleteButton.getAttribute('data-review-id');
                
                // Se não encontrou no botão, tenta no card pai
                if (!reviewId) {
                    const reviewCard = deleteButton.closest('[data-review-id]');
                    if (!reviewCard) {
                        showNotification('Erro: ID da avaliação não encontrado', 'error');
                        return;
                    }
                    reviewId = reviewCard.dataset.reviewId;
                }
                
                if (confirm('Tem certeza que deseja excluir esta avaliação?')) {
                    const success = await deleteReview(reviewId);
                    if (success) {
                        await loadReviews();
                    }
                }
            } else if (adminDeleteButton) {
                // Exclusão pelo administrador
                let reviewId = adminDeleteButton.getAttribute('data-review-id');
                
                // Se não encontrou no botão, tenta no card pai
                if (!reviewId) {
                    const reviewCard = adminDeleteButton.closest('[data-review-id]');
                    if (!reviewCard) {
                        showNotification('Erro: ID da avaliação não encontrado', 'error');
                        return;
                    }
                    reviewId = reviewCard.dataset.reviewId;
                }
                
                if (confirm('Tem certeza que deseja excluir esta avaliação como administrador? Esta ação é irreversível.')) {
                    const success = await deleteReviewAsAdmin(reviewId);
                    if (success) {
                        await loadReviews();
                    }
                }
            }
        });
    }

    // Formulário de avaliação
    if (dom.reviewForm) {
        dom.reviewForm.addEventListener('click', handleReviewSubmit);
    }

    // Configurar o botão de histórico de atividade
    setupActivityHistoryButton();

    // Adicionar CSS dinâmico para garantir o comportamento correto dos metadados e quebra de palavras
    const style = document.createElement('style');
    style.textContent = `
        .movie-meta-item[data-is-last="true"]::after {
            display: none !important;
        }
        
        .user-avatar img.avatar-image {
            width: 100%;
            height: 100%;
            object-fit: cover;
            display: block;
        }
        
        /* Fix para quebra de linha no título */
        .movie-title {
            width: 100% !important;
            white-space: normal !important;
            word-wrap: break-word !important;
            overflow-wrap: break-word !important;
            word-break: break-word !important;
            hyphens: auto;
            max-width: 100%;
            display: block;
        }
        
        /* Container de informações do filme */
        .movie-info {
            min-width: 0 !important;
            width: 100%;
            max-width: 100%;
        }
        
        /* Layout do header do filme */
        .movie-header {
            display: grid !important;
            grid-template-columns: auto 1fr !important;
            width: 100%;
        }
        
        /* Metadados, gêneros e descrição */
        .movie-meta {
            flex-wrap: wrap;
            width: 100%;
        }
        
        .movie-genre, .movie-description {
            word-wrap: break-word;
            overflow-wrap: break-word;
            word-break: break-word;
            width: 100%;
        }
        
        /* Reviews */
        .review-header {
            flex-wrap: wrap;
        }
        
        .user-info {
            min-width: 0 !important;
        }
        
        .review-comment, .username {
            word-wrap: break-word;
            overflow-wrap: break-word;
            word-break: break-word;
        }
        
        /* Melhorias para o botão de ordenação */
        .btn-icon {
            background: none;
            border: none;
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 18px;
            width: 36px;
            height: 36px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s ease;
        }

        .btn-icon:hover {
            color: var(--text-light);
            background-color: rgba(255, 255, 255, 0.1);
        }

        .btn-icon:active {
            transform: scale(0.95);
        }

        /* Animação suave quando o ícone muda */
        .btn-icon i {
            transition: all 0.3s ease;
        }
        
        /* Correção para alinhamento vertical na avaliação média */
        .average-rating-card .big-rating {
          font-size: 42px;
          font-weight: 700;
          margin-bottom: 10px;
          line-height: 1;
          display: flex;
          justify-content: center;
          align-items: center;
        }

        .average-rating-card .big-stars {
          font-size: 24px;
          margin-bottom: 10px;
          display: flex;
          justify-content: center;
          align-items: center;
          line-height: 1;
        }

        .star-rating {
          display: flex;
          align-items: center;
          justify-content: center;
          line-height: 1;
        }

        .star-rating .fas,
        .star-rating .far {
          vertical-align: middle;
        }

        .average-rating-card {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
        }
        
        /* Correção para alinhamento do botão de exclusão de review */
        .review-card {
            position: relative;
        }
        
        .review-actions {
            position: absolute;
            top: 1.5rem; /* Ajustado para melhor alinhamento vertical */
            right: 1.5rem;
            opacity: 0;
            transition: opacity 0.3s ease;
            display: flex;
            align-items: center;
            z-index: 10;
        }
        
        .review-card:hover .review-actions {
            opacity: 1;
        }
        
        .review-header {
            padding-right: 40px; /* Espaço para o botão de exclusão */
        }
        
        /* Garantir que o botão tenha tamanho consistente */
        .review-actions .btn-icon {
            width: 36px;
            height: 36px;
            display: flex;
            align-items: center;
            justify-content: center;
            background-color: rgba(0, 0, 0, 0.2);
            border-radius: 50%;
            transition: all 0.2s ease;
        }
        
        .review-actions .btn-icon:hover {
            background-color: rgba(244, 67, 54, 0.2);
        }
        
        .review-actions .btn-icon.btn-delete:hover {
            color: var(--error-color);
        }
        
        /* Estilo para botão de admin-delete */
        .admin-delete-review-btn {
            background-color: rgba(0, 0, 0, 0.2) !important;
            border: 1px solid rgba(244, 67, 54, 0.3) !important;
        }
        
        .admin-delete-review-btn:hover {
            background-color: rgba(244, 67, 54, 0.2) !important;
            color: var(--error-color) !important;
        }
        
        /* Melhor posicionamento do botão em telas menores */
        @media screen and (max-width: 480px) {
            .review-actions {
                position: static;
                margin-top: 10px;
                margin-left: auto;
                opacity: 1;
            }
            
            .review-header {
                padding-right: 0;
            }
        }
        
        /* Responsividade */
        @media screen and (max-width: 960px) {
            .movie-header {
                grid-template-columns: 1fr !important;
                justify-items: center;
            }
        }
        
        @media screen and (max-width: 480px) {
            .review-actions {
                position: static;
                margin-top: 10px;
                margin-left: auto;
            }
        }
    `;
    document.head.appendChild(style);
    
    // Garantir que o layout do header esteja correto
    const movieHeader = document.querySelector('.movie-header');
    if (movieHeader) {
        movieHeader.style.display = 'grid';
        movieHeader.style.gridTemplateColumns = 'auto 1fr';
        movieHeader.style.width = '100%';
    }
    
    // Garantir que o container de informações do filme tenha largura adequada
    const movieInfo = document.querySelector('.movie-info');
    if (movieInfo) {
        movieInfo.style.minWidth = '0'; // Crucial para flex/grid containers
        movieInfo.style.width = '100%';
        movieInfo.style.maxWidth = '100%';
    }
};

// Inicialização da página
document.addEventListener('DOMContentLoaded', async () => {
    // Verificar ID de filme
    if (!movieId) {
        showNotification('Filme não encontrado', 'error');
        return setTimeout(() => window.location.href = 'index.html', 2000);
    }
    
    // Configuração inicial
    const editBtn = document.getElementById('edit-movie-btn');
    if (editBtn) {
        const editUrl = `./edit.html?id=${movieId}`;
        editBtn.href = editUrl;
        editBtn.setAttribute('data-movie-id', movieId);
        
        editBtn.addEventListener('click', function(e) {
            e.preventDefault();
            window.location.href = editUrl;
        });
    }

    // Inicializar componentes e carregar dados
    initStarRating();
    setupEventListeners();
    await loadMovieDetails();
    
    // Verificação adicional após um tempo
    setTimeout(() => {
        console.log("Verificando permissões e UI novamente...");
        setupActionButtons();
        renderReviews();
    }, 1000);
});

// Backup para garantir que o botão de edição funcione sempre
document.addEventListener('click', function(e) {
    const target = e.target.closest('#edit-movie-btn');
    if (target) {
        e.preventDefault();
        const id = target.getAttribute('data-movie-id') || movieId;
        if (id) {
            window.location.href = `./edit.html?id=${id}`;
        }
    }
});