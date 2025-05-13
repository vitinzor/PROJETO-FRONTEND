// js/ui.js
import { starRating, formatDate, showNotification } from './utils.js';
import { authService } from './auth.js';
import { movieService, reviewService, pagination } from './main.js';

/**
 * URL da imagem placeholder para quando não houver imagem disponível
 * @type {string}
 */
const PLACEHOLDER_IMAGE_URL = 'https://via.placeholder.com/400x600?text=Sem+Imagem';

/**
 * Cria o HTML para um card de filme
 * @param {Object} movie - Dados do filme
 * @returns {string} - Markup HTML do card
 */
export const movieCardComponent = (movie) => {
    if (!movie) return '';

    const currentUserId = authService.authState?.currentUser?.id;
    const isOwner = currentUserId && movie.createdBy === currentUserId;

    return `
        <article class="movie-card" data-movie-id="${movie.id}">
            <div class="poster-container">
                <a href="movie-detail.html?id=${movie.id}" class="movie-card-link">
                    <img class="movie-poster"
                         src="${movie.imageUrl || PLACEHOLDER_IMAGE_URL}"
                         onerror="this.src='${PLACEHOLDER_IMAGE_URL}'"
                         alt="${movie.title || 'Filme sem Título'} Poster">
                </a>
            </div>
            
            ${authService.isAuthenticated() && isOwner ? `
                <div class="movie-actions owner-actions">
                    <a href="edit.html?id=${movie.id}" class="btn-edit" data-action="edit">
                        <i class="fas fa-edit"></i>
                    </a>
                    <button class="btn-delete" data-action="delete-movie" 
                            data-movie-id="${movie.id}">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            ` : ''}
        </article>
    `;
};

/**
 * Cria o HTML para um componente de review
 * @param {Object} review - Dados da review
 * @returns {string} - Markup HTML da review
 */
export const reviewComponent = (review) => {
    if (!review) return '';
    
    // Tentar encontrar informações do usuário em diferentes propriedades
    const user = review.user || {};
    const userName = user.name || (review.addedBy && review.addedBy.name) || 'Anônimo';
    
    const currentUserId = authService.authState?.currentUser?.id;
    const isOwner = currentUserId && user.id === currentUserId;

    return `
        <div class="review" data-review-id="${review.id}">
            <div class="user-avatar">
                ${userName[0]?.toUpperCase() || 'A'}
            </div>
            <div class="review-content">
                <div class="review-header">
                    <span class="review-author">${userName}</span>
                    <span class="review-date">${formatDate(review.createdAt)}</span>
                </div>
                <div class="review-rating">${starRating(review.rating)}</div>
                <p class="review-text">${review.comment || ''}</p>
                ${isOwner ? `
                    <div class="review-actions">
                        <button class="btn-delete btn-small" 
                                data-action="delete-review" 
                                data-review-id="${review.id}" 
                                data-movie-id="${review.movieId}">
                            Excluir
                        </button>
                    </div>
                ` : ''}
            </div>
        </div>
    `;
};

/**
 * Renderiza uma grade de filmes em um container específico
 * @param {Array} movies - Array de objetos de filme
 * @param {HTMLElement} container - Elemento onde os filmes serão renderizados
 */
export const renderMovieGrid = (movies, container) => {
    if (!container) {
        console.error("Container para grid de filmes não encontrado.");
        return;
    }
    
    // Certifique-se que o container tem a ID correta para aplicar nosso CSS
    container.id = 'movie-grid';
    
    container.innerHTML = movies?.length > 0 
        ? movies.map(movieCardComponent).join('')
        : '<p class="message info">Nenhum filme encontrado.</p>';
};

/**
 * Renderiza os detalhes de um filme em um container
 * @param {Object} movie - Dados do filme
 * @param {HTMLElement} container - Elemento onde os detalhes serão renderizados
 */
export const renderMovieDetails = (movie, container) => {
    if (!container || !movie) {
        console.error("Dados inválidos para renderização de detalhes.");
        return;
    }

    container.innerHTML = `
        <div class="movie-detail">
            <div class="movie-detail-header">
                <img class="movie-detail-poster"
                     src="${movie.imageUrl || PLACEHOLDER_IMAGE_URL}"
                     onerror="this.src='${PLACEHOLDER_IMAGE_URL}'"
                     alt="${movie.title || 'Filme sem Título'} Poster">
                <h1>${movie.title || 'Título Desconhecido'} (${movie.releaseYear || 'N/A'})</h1>
                <p class="movie-detail-meta">
                    ${starRating(movie.averageRating || 0)}
                    ${movie.averageRating?.toFixed(1) || ''}
                    | Lançado em ${movie.releaseYear || 'N/A'}
                </p>
                <div class="movie-detail-actions">
                    <button class="btn-review" 
                            data-action="show-review-modal" 
                            data-movie-id="${movie.id}" 
                            data-movie-title="${movie.title}">
                        Avaliar
                    </button>
                    ${authService.isAuthenticated() && authService.authState.currentUser?.id === movie.createdBy ? `
                        <a href="edit.html?id=${movie.id}" class="btn-edit">Editar</a>
                        <button class="btn-delete" 
                                data-action="delete-movie-detail" 
                                data-movie-id="${movie.id}">
                            Excluir
                        </button>
                    ` : ''}
                </div>
            </div>
            <div class="movie-detail-description">
                <h3>Sinopse</h3>
                <p>${movie.description || 'Sem descrição disponível.'}</p>
            </div>
            <div id="reviews-section" class="reviews-section">
                <h3>Avaliações</h3>
                <div id="review-list" class="review-list"></div>
            </div>
            <div id="review-form-container"></div>
        </div>
    `;
};

/**
 * Renderiza uma lista de reviews em um container
 * @param {Array} reviews - Array de objetos de review
 * @param {string} containerId - ID do elemento onde as reviews serão renderizadas
 */
export const renderReviewsList = (reviews, containerId = 'review-list') => {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.innerHTML = reviews?.length > 0
        ? reviews.map(reviewComponent).join('')
        : '<p class="message info">Ainda não há avaliações para este filme.</p>';

    container.addEventListener('click', async (event) => {
        const target = event.target;
        if (target.classList.contains('btn-delete') && target.dataset.action === 'delete-review') {
            const { reviewId, movieId } = target.dataset;
            if (confirm('Tem certeza que deseja excluir esta avaliação?')) {
                try {
                    const success = await reviewService.deleteReview(movieId, reviewId);
                    if (success) {
                        target.closest('.review')?.remove();
                        if (container.children.length === 0) {
                            container.innerHTML = '<p class="message info">Ainda não há avaliações para este filme.</p>';
                        }
                    }
                } catch (error) {
                    console.error('Erro ao excluir avaliação:', error);
                }
            }
        }
    });
};

/**
 * Renderiza um formulário de avaliação em um container
 * @param {HTMLElement} container - Elemento onde o formulário será renderizado
 */
export const renderReviewForm = (container) => {
    if (!container) return;

    if (!authService.isAuthenticated()) {
        container.innerHTML = '<p class="message info">Faça login para deixar sua avaliação.</p>';
        return;
    }

    container.innerHTML = `
        <div class="comment-form" id="review-form">
            <h4>Deixar uma Avaliação</h4>
            <form>
                <div class="form-group">
                    <label for="rating">Sua Nota:</label>
                    <select id="rating" name="rating" required>
                        <option value="">-- Selecione --</option>
                        ${[1, 2, 3, 4, 5].map(i => `<option value="${i}">${i} Estrela${i > 1 ? 's' : ''}</option>`).join('')}
                    </select>
                </div>
                <div class="form-group">
                    <label for="comment">Comentário:</label>
                    <textarea id="comment" name="comment" rows="4" 
                              placeholder="O que você achou do filme?" required></textarea>
                </div>
                <button type="submit">Enviar Avaliação</button>
            </form>
        </div>
    `;
};

/**
 * Preenche um formulário de edição de filme com os dados existentes
 * @param {HTMLFormElement} form - Formulário a ser preenchido
 * @param {Object} movie - Dados do filme
 */
export const fillEditMovieForm = (form, movie) => {
    if (!form || !movie) return;

    form.querySelector('#title').value = movie.title || '';
    form.querySelector('#description').value = movie.description || '';
    form.querySelector('#releaseYear').value = movie.releaseYear || '';

    const currentImageContainer = form.querySelector('#current-image-container');
    if (currentImageContainer) {
        currentImageContainer.innerHTML = `
            <p>Imagem Atual:</p>
            ${movie.imageUrl 
                ? `<img src="${movie.imageUrl}" alt="Imagem atual" style="max-width: 200px;">` 
                : '<p>Nenhuma imagem</p>'}
            <div class="form-group">
                <input type="checkbox" id="clearImage" name="clearImage">
                <label for="clearImage">Remover imagem atual</label>
            </div>
        `;
    }
};

/**
 * Renderiza um formulário de registro com validações
 * @param {HTMLElement} container - Container onde o formulário será renderizado
 */
export const renderRegistrationForm = (container) => {
    if (!container) return;
    
    container.innerHTML = `
        <form id="register-form" class="register-form">
            <div class="form-group">
                <label for="name">Nome completo</label>
                <input type="text" id="name" name="name" placeholder="Digite seu nome completo" required>
                <i class="validation-icon fas fa-check-circle"></i>
                <span class="error-message">Por favor, insira seu nome completo</span>
            </div>
            
            <div class="form-group">
                <label for="email">E-mail</label>
                <input type="email" id="email" name="email" placeholder="Digite seu e-mail" required>
                <i class="validation-icon fas fa-check-circle"></i>
                <span class="error-message">Por favor, insira um e-mail válido</span>
            </div>
            
            <div class="form-group">
                <label for="password">Senha</label>
                <div class="password-container">
                    <input type="password" id="password" name="password" placeholder="Digite sua senha" required>
                    <i class="input-icon fas fa-eye-slash toggle-password"></i>
                </div>
                
                <div class="password-strength">
                    <div class="password-strength-bar"></div>
                </div>
                <div class="password-strength-text">Força da senha: <span id="strength-text">Fraca</span></div>
                
                <span class="error-message">Sua senha não atende a todos os requisitos listados abaixo.</span>
                
                <div class="password-requirements">
                    <p>Sua senha deve conter:</p>
                    <ul>
                        <li id="length"><i class="fas fa-circle"></i> Pelo menos 8 caracteres</li>
                        <li id="uppercase"><i class="fas fa-circle"></i> Uma letra maiúscula</li>
                        <li id="lowercase"><i class="fas fa-circle"></i> Uma letra minúscula</li>
                        <li id="number"><i class="fas fa-circle"></i> Um número</li>
                    </ul>
                </div>
            </div>
            
            <button type="submit" class="btn-register">Criar Conta</button>
        </form>
    `;
};

// --- Gerenciamento do Modal de Avaliação ---

/**
 * Elemento do modal de avaliação
 * @type {HTMLElement|null}
 */
let ratingModalElement = null;

/**
 * Exibe o modal de avaliação para um filme
 * @param {string} movieId - ID do filme
 * @param {string} movieTitle - Título do filme
 */
export const showRatingModal = (movieId, movieTitle) => {
    if (!authService.isAuthenticated()) {
        showNotification('Você precisa estar logado para avaliar.', 'error');
        localStorage.setItem('redirectTo', window.location.pathname);
        window.location.href = 'login.html';
        return;
    }

    ratingModalElement?.remove();

    ratingModalElement = document.createElement('div');
    ratingModalElement.className = 'modal';
    ratingModalElement.innerHTML = `
        <div class="modal-content">
            <span class="close-button">&times;</span>
            <h3>Avaliar ${movieTitle || 'Filme'}</h3>
            <form id="modal-review-form" data-movie-id="${movieId}">
                <div class="form-group star-rating-input">
                    <label>Sua Nota:</label>
                    <div id="modal-rating-stars" class="rating interactive">
                        ${[1, 2, 3, 4, 5].map(i => `<span class="star" data-value="${i}">☆</span>`).join('')}
                    </div>
                    <input type="hidden" id="modal-rating" name="rating" required>
                </div>
                <div class="form-group">
                    <label for="modal-comment">Comentário:</label>
                    <textarea id="modal-comment" name="comment" rows="4" 
                              placeholder="Deixe seu comentário..." required></textarea>
                </div>
                <button type="submit" class="form-button">Enviar Avaliação</button>
            </form>
        </div>
    `;

    document.body.appendChild(ratingModalElement);

    // Configuração das estrelas interativas
    const stars = ratingModalElement.querySelectorAll('.star');
    let currentRating = 0;
    const ratingInput = ratingModalElement.querySelector('#modal-rating');

    const updateStars = (value) => {
        stars.forEach(star => {
            star.textContent = star.dataset.value <= value ? '★' : '☆';
        });
    };

    ratingModalElement.querySelector('#modal-rating-stars').addEventListener('mouseover', (e) => {
        const value = e.target.dataset.value;
        if (value) updateStars(value);
    });

    ratingModalElement.querySelector('#modal-rating-stars').addEventListener('mouseout', () => {
        updateStars(currentRating);
    });

    ratingModalElement.querySelector('#modal-rating-stars').addEventListener('click', (e) => {
        const value = e.target.dataset.value;
        if (value) {
            currentRating = Number(value);
            ratingInput.value = currentRating;
            updateStars(currentRating);
        }
    });

    // Fechar modal
    ratingModalElement.querySelector('.close-button').addEventListener('click', hideRatingModal);
    ratingModalElement.addEventListener('click', (e) => {
        if (e.target === ratingModalElement) hideRatingModal();
    });

    // Submit do formulário
    ratingModalElement.querySelector('form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const reviewData = {
            rating: formData.get('rating'),
            comment: formData.get('comment')
        };

        if (!reviewData.rating) {
            showNotification('Selecione uma nota!', 'error');
            return;
        }

        const submitButton = e.target.querySelector('button[type="submit"]');
        submitButton.disabled = true;
        submitButton.textContent = 'Enviando...';

        try {
            const newReview = await reviewService.submitReview(movieId, reviewData);
            if (newReview) {
                hideRatingModal();
                if (window.location.pathname.includes('movie.html')) {
                    const updatedReviews = await reviewService.loadReviews(movieId);
                    renderReviewsList(updatedReviews);
                }
            }
        } catch (error) {
            console.error('Erro ao enviar avaliação:', error);
        } finally {
            submitButton.disabled = false;
            submitButton.textContent = 'Enviar Avaliação';
        }
    });

    setTimeout(() => ratingModalElement.classList.add('is-visible'), 10);
};

/**
 * Oculta o modal de avaliação
 */
export const hideRatingModal = () => {
    if (!ratingModalElement) return;

    ratingModalElement.classList.remove('is-visible');
    ratingModalElement.addEventListener('transitionend', () => {
        ratingModalElement?.remove();
        ratingModalElement = null;
    }, { once: true });
};

// --- Event Listeners Globais ---
document.addEventListener('DOMContentLoaded', () => {
    document.body.addEventListener('click', async (e) => {
        const movieCard = e.target.closest('.movie-card');
        const actionButton = e.target.closest('[data-action]');

        try {
            if (movieCard && actionButton) {
                e.preventDefault();
                e.stopPropagation();

                const movieId = movieCard.dataset.movieId;
                const action = actionButton.dataset.action;

                switch (action) {
                    case 'show-review-modal':
                        const movieTitle = actionButton.dataset.movieTitle;
                        showRatingModal(movieId, movieTitle);
                        break;

                    case 'edit':
                        window.location.href = `edit.html?id=${movieId}`;
                        break;

                    case 'delete-movie':
                    case 'delete-movie-detail':
                        if (confirm('Tem certeza que deseja excluir este filme?')) {
                            const success = await movieService.deleteMovie(movieId);
                            if (success) {
                                if (action === 'delete-movie') {
                                    movieCard.remove();
                                } else {
                                    window.location.href = 'index.html';
                                }
                            }
                        }
                        break;
                }
            }
        } catch (error) {
            console.error('Erro na ação:', error);
            showNotification('Falha na operação', 'error');
        }
    });
});