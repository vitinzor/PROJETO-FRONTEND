// Importar helpers e serviços necessários
import { authService } from './auth.js';
import { showNotification, handleApiError, formatDate, starRating } from './utils.js';
import { 
  renderMovieGrid, 
  renderMovieDetails, 
  renderReviewsList, 
  renderReviewForm, 
  fillEditMovieForm, 
  showRatingModal, 
  hideRatingModal 
} from './ui.js';

// Define a URL base da API
const API = 'http://localhost:3000';

// --- Movie Service ---
const movieService = {
    // Busca filmes da API com paginação e parâmetros de busca opcionais
    async fetchMovies(params = {}) {
        try {
            const url = new URL(`${API}/movies`);
            // Adiciona parâmetros de busca (page, limit, etc.)
            Object.entries(params).forEach(([key, value]) => {
                if (value !== undefined && value !== null) {
                    url.searchParams.append(key, value);
                }
            });

            const response = await fetch(url);

            if (!response.ok) {
                await handleApiError(response, 'Erro ao carregar filmes');
                return { movies: [], totalPages: 1 };
            }

            const data = await response.json();
            const movies = data.movies || data || [];
            const totalPages = data.totalPages || 1;

            return { movies, totalPages };
        } catch (error) {
            console.error('Erro ao buscar filmes:', error);
            showNotification(error.message || 'Erro de comunicação ao buscar filmes', 'error');
            return { movies: [], totalPages: 1 };
        }
    },

    // Cria um novo filme
    async createMovie(movieData) {
        try {
            console.log('[DEBUG] Dados brutos recebidos:', movieData);
            
            const token = authService.getToken();
            if (!token) {
                showNotification('Você precisa estar logado para adicionar um filme.', 'error');
                localStorage.setItem('redirectTo', window.location.pathname);
                window.location.href = 'login.html';
                return null;
            }

            let imageUrl = null;
            // Processamento de imagem
            if (movieData.imageFile) {
                console.log('[DEBUG] Iniciando upload de imagem...');
                imageUrl = await this.handleImageUpload(movieData.imageFile);
                if (!imageUrl) {
                    console.error('[ERRO] Upload de imagem falhou');
                    return null;
                }
                console.log('[DEBUG] Imagem carregada com sucesso:', imageUrl);
            }

            // Construção do payload
            const moviePayload = {
                title: movieData.title.trim(),
                description: movieData.description.trim(),
                releaseYear: parseInt(movieData.releaseYear),
                genre: movieData.genre || "", // Campo de gênero
                director: movieData.director || "", // Adicionado campo de diretor
                imageUrl: imageUrl
            };

            console.log('[DEBUG] Payload final:', moviePayload);

            // Requisição para API
            const response = await fetch(`${API}/movies`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(moviePayload)
            });

            console.log('[DEBUG] Status da resposta:', response.status);
            const responseData = await response.json();
            console.log('[DEBUG] Resposta completa:', responseData);

            if (!response.ok) {
                throw new Error(responseData.message || 'Erro desconhecido na API');
            }

            showNotification('Filme criado com sucesso! Redirecionando...', 'success', 2000);
            setTimeout(() => window.location.href = 'index.html', 2000);
            return responseData;

        } catch (error) {
            console.error('[ERRO COMPLETO] Falha ao criar filme:', error);
            showNotification(error.message || 'Erro crítico ao processar filme', 'error');
            return null;
        }
    },

    // Busca detalhes de um filme específico
    async getMovieById(id) {
        try {
            if (!id) {
                throw new Error('ID do filme não fornecido');
            }
            
            console.log(`Buscando detalhes do filme ID: ${id}`);
            const response = await fetch(`${API}/movies/${id}`);
            
            if (!response.ok) {
                throw new Error('Filme não encontrado');
            }
            
            const movie = await response.json();
            return movie;
        } catch (error) {
            console.error('Erro ao buscar detalhes do filme:', error);
            showNotification(error.message, 'error');
            return null;
        }
    },

    // Edita um filme existente - CORRIGIDO
    // Apenas o método updateMovie atualizado
    async updateMovie(movieData) {
        try {
            console.log('[DEBUG] Dados recebidos para atualização:', movieData);
            
            if (!movieData.id) {
                throw new Error('ID do filme não fornecido para atualização');
            }
            
            const token = authService.getToken();
            if (!token) {
                showNotification('Você precisa estar logado para editar um filme.', 'error');
                localStorage.setItem('redirectTo', window.location.pathname);
                window.location.href = 'login.html';
                return null;
            }

            let imageUrl = null;
            
            // Processar imagem apenas se uma nova foi enviada
            if (movieData.imageFile && movieData.imageFile.size > 0) {
                console.log('[DEBUG] Processando nova imagem para upload...');
                imageUrl = await this.handleImageUpload(movieData.imageFile);
                if (!imageUrl) {
                    console.error('[ERRO] Upload de imagem falhou');
                    throw new Error('Falha no upload da imagem');
                }
                console.log('[DEBUG] Nova imagem processada:', imageUrl);
            }

            // Construir payload para envio
            const payload = {
                title: movieData.title,
                description: movieData.description,
                releaseYear: parseInt(movieData.releaseYear),
                director: movieData.director || null,
                genre: movieData.genre || null
            };
            
            // Adicionar URLs de imagem conforme necessário
            if (imageUrl) {
                // Se tem nova imagem, usá-la
                payload.imageUrl = imageUrl;
            } else if (movieData.clearImage) {
                // Se pediu para limpar, enviar null
                payload.imageUrl = null;
            }
            // Se keepExistingImage, não enviar imageUrl para manter a atual
            
            console.log('[DEBUG] Payload de atualização:', payload);

            const response = await fetch(`${API}/movies/${movieData.id}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || 'Erro ao atualizar filme');
            }

            const updatedMovie = await response.json();
            showNotification('Filme atualizado com sucesso!', 'success');
            return updatedMovie;
        } catch (error) {
            console.error('[ERRO] Falha ao atualizar filme:', error);
            showNotification(error.message || 'Erro ao atualizar filme', 'error');
            throw error;
        }
    },

    // Método para excluir um filme
    async deleteMovie(movieId) {
    try {
        console.log('Iniciando exclusão do filme:', movieId);
        
        if (!movieId) {
        console.error('ID do filme não informado');
        showNotification('ID do filme não informado', 'error');
        return false;
        }
        
        // Verificar se o usuário está autenticado
        if (!authService.isAuthenticated()) {
        console.error('Usuário não autenticado');
        showNotification('Você precisa estar logado para excluir filmes', 'error');
        return false;
        }
        
        const token = authService.getToken();
        console.log('Token obtido para exclusão');
        
        // URL para fazer a exclusão do filme - CORRIGIDO: agora usamos API em vez de API_BASE_URL
        const url = `${API}/movies/${movieId}`;
        console.log('URL de exclusão:', url);
        
        // Fazer a requisição para a API para excluir o filme
        const response = await fetch(url, {
        method: 'DELETE',
        headers: {
            'Authorization': `Bearer ${token}`
        }
        });
        
        console.log('Resposta da API:', response.status, response.statusText);
        
        if (!response.ok) {
        let errorMessage = 'Erro ao excluir o filme';
        
        try {
            const errorData = await response.json();
            errorMessage = errorData.message || errorMessage;
            console.error('Detalhes do erro:', errorData);
        } catch (e) {
            console.error('Não foi possível obter detalhes do erro:', e);
        }
        
        throw new Error(errorMessage);
        }
        
        console.log('Filme excluído com sucesso!');
        return true;
    } catch (error) {
        console.error('Erro ao excluir filme:', error);
        showNotification(error.message || 'Erro ao excluir o filme. Tente novamente.', 'error');
        return false;
    }
    },

    // Upload de imagem
    async handleImageUpload(file) {
        if (!file) return null;

        if (!file.type.startsWith('image/')) {
            showNotification('Por favor, selecione um arquivo de imagem válido.', 'error');
            return null;
        }

        try {
            const token = authService.getToken();
            if (!token) {
                showNotification('Você precisa estar logado para enviar imagens.', 'error');
                localStorage.setItem('redirectTo', window.location.pathname);
                window.location.href = 'login.html';
                return null;
            }

            const formData = new FormData();
            formData.append('image', file);

            const response = await fetch(`${API}/movies/upload`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                body: formData
            });

            if (!response.ok) {
                await handleApiError(response, 'Erro no upload da imagem');
                return null;
            }

            const { url } = await response.json();
            showNotification('Imagem enviada com sucesso!', 'success', 1000);
            return url;
        } catch (error) {
            console.error('Error uploading image:', error);
            showNotification(error.message || 'Erro inesperado ao enviar imagem', 'error');
            return null;
        }
    },

    // Busca detalhes de um filme
    async getMovieDetails(id) {
        try {
            const response = await fetch(`${API}/movies/${id}`);
            if (!response.ok) {
                await handleApiError(response, 'Filme não encontrado');
                return null;
            }
            return await response.json();
        } catch (error) {
            console.error('Error fetching movie details:', error);
            showNotification(error.message || 'Erro ao carregar detalhes do filme', 'error');
            return null;
        }
    }
};

// --- Review Service ---
const reviewService = {
    // Envia uma nova avaliação para um filme
    async submitReview(movieId, reviewData) {
        try {
            const token = authService.getToken();
            if (!token) {
                showNotification('Você precisa estar logado para avaliar.', 'error');
                localStorage.setItem('redirectTo', window.location.pathname);
                window.location.href = 'login.html';
                return null;
            }

            const response = await fetch(`${API}/movies/${movieId}/reviews`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    rating: Number(reviewData.rating),
                    comment: reviewData.comment
                })
            });

            if (!response.ok) {
                await handleApiError(response, 'Erro ao enviar avaliação');
                return null;
            }

            const newReview = await response.json();
            showNotification('Avaliação enviada com sucesso!', 'success');
            return newReview;
        } catch (error) {
            console.error('Error submitting review:', error);
            showNotification(error.message || 'Erro inesperado ao enviar avaliação', 'error');
            return null;
        }
    },

    // Carrega avaliações para um filme específico
    async loadReviews(movieId) {
        try {
            const response = await fetch(`${API}/movies/${movieId}/reviews`);
            if (!response.ok) {
                await handleApiError(response, 'Erro ao carregar avaliações');
                return [];
            }
            return await response.json();
        } catch (error) {
            console.error('Error loading reviews:', error);
            showNotification(error.message || 'Erro inesperado ao carregar avaliações', 'error');
            return [];
        }
    },

    // Exclui uma avaliação
    async deleteReview(movieId, reviewId) {
        try {
            const token = authService.getToken();
            if (!token) {
                showNotification('Você precisa estar logado para excluir avaliações.', 'error');
                localStorage.setItem('redirectTo', window.location.pathname);
                window.location.href = 'login.html';
                return false;
            }

            const response = await fetch(`${API}/movies/${movieId}/reviews/${reviewId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (!response.ok) {
                await handleApiError(response, 'Erro ao excluir avaliação');
                return false;
            }

            showNotification('Avaliação excluída com sucesso!', 'success');
            return true;
        } catch (error) {
            console.error('Error deleting review:', error);
            showNotification(error.message || 'Erro inesperado ao excluir avaliação', 'error');
            return false;
        }
    }
};

// --- Paginação ---
const pagination = {
    currentPage: 1,
    totalPages: 1,
    paginationContainer: null,
    movieGridContainer: null,

    init(paginationContainerId = 'pagination', movieGridContainerId = 'movie-grid') {
        this.paginationContainer = document.getElementById(paginationContainerId);
        if (this.paginationContainer) {
            this.setupEventListeners();
        }

        this.movieGridContainer = document.getElementById(movieGridContainerId);
        if (!this.movieGridContainer) {
            console.error(`Container do grid de filmes #${movieGridContainerId} não encontrado.`);
        }
    },

    setupEventListeners() {
        if (this.paginationContainer) {
            this.paginationContainer.addEventListener('click', (event) => {
                const target = event.target;
                if (target.tagName === 'BUTTON') {
                    if (target.classList.contains('prev-page')) {
                        this.loadPage(this.currentPage - 1);
                    } else if (target.classList.contains('next-page')) {
                        this.loadPage(this.currentPage + 1);
                    }
                }
            });
        }
    },

    async loadPage(page) {
        if (!this.movieGridContainer || page < 1 || page > this.totalPages) return;

        console.log(`Carregando página ${page}...`);
        this.movieGridContainer.innerHTML = '<p class="message info">Carregando filmes...</p>';

        const { movies, totalPages } = await movieService.fetchMovies({ page });
        this.currentPage = page;
        this.totalPages = totalPages;

        this.updatePaginationUI();
        renderMovieGrid(movies, this.movieGridContainer);
    },

    updatePaginationUI() {
        if (this.totalPages <= 1) {
          this.paginationContainer.style.display = 'none'; // Oculta se não houver paginação
          return;
        }
        // ... código existente
      }
    }


// --- Inicialização da Página Inicial ---
const initHomePage = async () => {
    console.log('[INIT] Iniciando página inicial...');
    try {
        pagination.init('pagination', 'movie-grid');
        if (pagination.movieGridContainer) {
            await pagination.loadPage(1);
        }
    } catch (error) {
        console.error('[ERRO] Falha na inicialização:', error);
        showNotification('Falha ao carregar catálogo de filmes', 'error');
    }
};

// --- Execução na Inicialização ---
document.addEventListener('DOMContentLoaded', async () => {
    console.log('[INIT] Inicialização do sistema');
    const pathname = window.location.pathname;
    
    try {
        if (pathname === '/' || pathname.endsWith('index.html')) {
            await initHomePage();
        }
        else if (pathname.endsWith('add.html')) {
            console.log('[INIT] Modo de adição de filme');
        }
    } catch (error) {
        console.error('[ERRO CRÍTICO] Falha na inicialização:', error);
        showNotification('Erro crítico no carregamento da página', 'error');
    }
});

export { movieService, pagination, reviewService };