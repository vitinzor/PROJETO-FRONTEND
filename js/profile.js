// js/profile.js
import { authService } from './auth.js';
import { showNotification, handleApiError, formatDate, starRating } from './utils.js';
import { initializeNavbar } from './components.js';

const API = 'http://localhost:3000';

// Inicializa o serviço de perfil
const profileService = {
    // Busca dados do usuário atual
    async fetchUserData() {
        try {
            const token = authService.getToken();
            if (!token) {
                window.location.href = 'login.html';
                return null;
            }

            const response = await fetch(`${API}/users/me`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (!response.ok) {
                console.error('Erro ao buscar dados de usuário:', response.status);
                if (response.status === 401) {
                    // Forçar logout apenas se for erro de autenticação
                    authService.clearAuthState();
                    window.location.href = 'login.html';
                    return null;
                }
                
                showNotification('Erro ao carregar dados do usuário', 'error');
                return null;
            }

            const userData = await response.json();
            console.log("Dados brutos do usuário:", userData);
            return userData;
        } catch (error) {
            console.error('Erro ao buscar dados do usuário:', error);
            showNotification('Falha ao carregar seus dados', 'error');
            return null;
        }
    },

    // Atualiza perfil do usuário
    async updateProfile(userData) {
        try {
            const token = authService.getToken();
            if (!token) {
                window.location.href = 'login.html';
                return null;
            }

            // Obtenha o ID do usuário atual
            const currentUser = authService.authState.currentUser;
            if (!currentUser || !currentUser.id) {
                showNotification('Dados de usuário não disponíveis', 'error');
                return null;
            }

            const response = await fetch(`${API}/users/${currentUser.id}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify(userData)
            });

            if (!response.ok) {
                if (response.status === 401) {
                    // Forçar logout apenas se for erro de autenticação
                    authService.clearAuthState();
                    window.location.href = 'login.html';
                    return null;
                }
                
                const errorData = await response.json();
                showNotification(errorData.error || 'Erro ao atualizar perfil', 'error');
                return null;
            }

            showNotification('Perfil atualizado com sucesso!', 'success');
            return await response.json();
        } catch (error) {
            console.error('Erro ao atualizar perfil:', error);
            showNotification('Falha ao atualizar perfil', 'error');
            return null;
        }
    },

    // Busca as avaliações feitas pelo usuário
    async fetchUserReviews() {
        try {
            const token = authService.getToken();
            if (!token) {
                return []; // Não redirecionar, apenas retornar vazio
            }

            const response = await fetch(`${API}/users/me/reviews`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (!response.ok) {
                console.warn('Erro ao buscar avaliações:', response.status);
                // Se o endpoint existir mas retornar erro, apenas logamos
                // Não redirecionamos por causa de falha na busca de avaliações
                return [];
            }

            const reviews = await response.json();
            console.log("Avaliações brutas recebidas:", reviews);
            return reviews;
        } catch (error) {
            console.error('Erro ao buscar avaliações do usuário:', error);
            return []; // Em caso de erro, retorna array vazio
        }
    },
    
    // Busca os filmes adicionados pelo usuário
    async fetchUserMovies() {
        try {
            const token = authService.getToken();
            if (!token) {
                return []; // Não redirecionar, apenas retornar vazio
            }

            const response = await fetch(`${API}/users/me/movies`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (!response.ok) {
                console.warn('Erro ao buscar filmes do usuário:', response.status);
                
                // Se endpoint não existe ainda, usamos dados mockados temporariamente
                if (response.status === 404) {
                    return mockUserMovies(); 
                }
                return [];
            }

            const movies = await response.json();
            console.log("Filmes brutos recebidos:", movies);
            return movies;
        } catch (error) {
            console.error('Erro ao buscar filmes do usuário:', error);
            return []; // Em caso de erro, retorna array vazio
        }
    },
    
    // Upload de avatar
    async uploadAvatar(formData) {
        try {
            const token = authService.getToken();
            if (!token) {
                window.location.href = 'login.html';
                return null;
            }

            // Obtenha o ID do usuário atual
            const currentUser = authService.authState.currentUser;
            if (!currentUser || !currentUser.id) {
                showNotification('Dados de usuário não disponíveis', 'error');
                return null;
            }

            // Tenta o método 1: Upload direto de arquivo
            let response = await fetch(`${API}/users/${currentUser.id}/avatar`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                body: formData
            });

            // Se endpoint retornar erro 404, tenta o método 2: Gerar avatar baseado no nome
            if (response.status === 404) {
                console.log('Endpoint de upload não disponível, tentando gerar avatar por nome...');
                
                // Tenta método alternativo - chamar endpoint sem arquivo
                response = await fetch(`${API}/users/${currentUser.id}/avatar/generate`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                });
                
                // Se o segundo método também falhar
                if (!response.ok) {
                    // Último recurso: simular uma resposta
                    showNotification('Gerando avatar localmente...', 'info');
                    console.log('Gerando avatar localmente (backend não implementado)');
                    
                    // Gerar avatar usando serviço externo
                    const user = authService.getCurrentUser();
                    const mockAvatarUrl = 'https://ui-avatars.com/api/?name=' + 
                        encodeURIComponent(user.name) + '&background=2c3440&color=fff&size=200';
                    
                    return {
                        user: {
                            ...user,
                            avatarUrl: mockAvatarUrl
                        }
                    };
                }
            }
            
            // Se algum dos métodos acima funcionou e retornou uma resposta ok
            if (response.ok) {
                showNotification('Foto de perfil atualizada com sucesso!', 'success');
                return await response.json();
            }
            
            // Se nenhum método funcionou
            console.warn('Erro ao fazer upload de avatar:', response.status);
            showNotification('Não foi possível atualizar sua foto de perfil', 'error');
            return null;
        } catch (error) {
            console.error('Erro ao fazer upload de avatar:', error);
            showNotification('Falha ao atualizar foto de perfil', 'error');
            return null;
        }
    },
    
    // Método alternativo - gerar avatar baseado no nome
    async generateAvatar() {
        try {
            const token = authService.getToken();
            if (!token) {
                window.location.href = 'login.html';
                return null;
            }

            // Obtenha o ID do usuário atual
            const currentUser = authService.authState.currentUser;
            if (!currentUser || !currentUser.id) {
                showNotification('Dados de usuário não disponíveis', 'error');
                return null;
            }

            const response = await fetch(`${API}/users/${currentUser.id}/avatar/generate`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                // Fallback para simulação local
                if (response.status === 404) {
                    showNotification('Gerando avatar localmente...', 'info');
                    console.log('Gerando avatar localmente (backend não implementado)');
                    
                    // Gerar avatar usando serviço externo
                    const user = authService.getCurrentUser();
                    const mockAvatarUrl = 'https://ui-avatars.com/api/?name=' + 
                        encodeURIComponent(user.name) + '&background=2c3440&color=fff&size=200';
                    
                    return {
                        user: {
                            ...user,
                            avatarUrl: mockAvatarUrl
                        }
                    };
                }
                
                console.warn('Erro ao gerar avatar:', response.status);
                showNotification('Não foi possível gerar seu avatar', 'error');
                return null;
            }

            showNotification('Avatar gerado com sucesso!', 'success');
            return await response.json();
        } catch (error) {
            console.error('Erro ao gerar avatar:', error);
            showNotification('Falha ao gerar avatar', 'error');
            return null;
        }
    }
};

// Função para gerar iniciais a partir do nome
function getInitials(name) {
    if (!name) return '?';
    
    // Dividir o nome em palavras e pegar a primeira letra de cada
    const words = name.split(' ').filter(word => word.length > 0);
    
    if (words.length === 1) {
        // Se só tem uma palavra, usar as duas primeiras letras
        return words[0].substring(0, 2).toUpperCase();
    } else {
        // Senão, pegar a primeira letra da primeira e da última palavra
        return (words[0][0] + words[words.length - 1][0]).toUpperCase();
    }
}

// Função para preencher informações do usuário
// js/profile.js - Apenas a parte da função populateProfileInfo
function populateProfileInfo(userData) {
    if (!userData) return; // Proteção contra undefined
    
    console.log("Populando informações do usuário:", userData);
    
    // Atualizar nome do usuário
    const userNameElement = document.getElementById('user-name');
    if (userNameElement) {
        userNameElement.textContent = userData.name || 'Usuário';
    }
    
    // Atualizar email
    const userEmailElement = document.getElementById('user-email');
    if (userEmailElement) {
        userEmailElement.textContent = userData.email || '';
    }
    
    // Atualizar data de criação
    const userSinceElement = document.getElementById('user-since');
    if (userSinceElement && userData.createdAt) {
        console.log("Data de criação original:", userData.createdAt);
        
        // Criar um objeto Date diretamente
        const formattedDate = formatDate(userData.createdAt);
        console.log("Data formatada:", formattedDate);
        
        userSinceElement.textContent = formattedDate;
    } else if (userSinceElement) {
        // Fallback se não tiver data de criação
        userSinceElement.textContent = 'Data indisponível';
    }
    
    // Preencher avatar com foto ou iniciais
    updateUserAvatar(userData);
    
    // Preencher formulário caso seja mostrado posteriormente
    document.getElementById('name').value = userData.name || '';
    document.getElementById('email').value = userData.email || '';
}

// Função para atualizar o avatar do usuário
function updateUserAvatar(userData) {
    const avatarElement = document.getElementById('user-avatar');
    if (!avatarElement) return;
    
    // Limpar conteúdo atual
    avatarElement.innerHTML = '';
    
    if (userData.avatarUrl) {
        // Se tiver URL de avatar, mostrar a imagem
        const img = document.createElement('img');
        
        // IMPORTANTE: Verificar se a URL já é completa ou precisa adicionar o prefixo da API
        if (userData.avatarUrl.startsWith('http')) {
            img.src = userData.avatarUrl;
        } else {
            // Adicionar prefixo da API para caminhos relativos
            img.src = API + userData.avatarUrl;
        }
        
        console.log('Carregando avatar de:', img.src);
        
        // Adicionar manipuladores de eventos para debugging
        img.onload = () => console.log('Avatar carregado com sucesso!');
        img.onerror = (e) => {
            console.error('Erro ao carregar avatar:', e);
            // Fallback para iniciais se a imagem falhar
            avatarElement.textContent = getInitials(userData.name);
        };
        
        img.alt = userData.name || 'Avatar';
        img.className = 'avatar-image';
        avatarElement.appendChild(img);
    } else {
        // Senão, mostrar iniciais
        avatarElement.textContent = getInitials(userData.name);
    }
}

// Função para renderizar as avaliações do usuário
function renderUserReviews(reviews) {
    const container = document.getElementById('user-reviews');
    const emptyState = document.getElementById('empty-reviews');
    
    if (!container || !emptyState) return; // Proteção contra elementos não encontrados
    
    if (!reviews || reviews.length === 0) {
        container.innerHTML = '';
        emptyState.style.display = 'block';
        return;
    }

    // Ocultar o estado vazio
    emptyState.style.display = 'none';
    
    // Debug: mostrar datas originais para verificar
    reviews.forEach(review => {
        console.log(`Review para "${review.movie?.title}": Data criação original = ${review.createdAt}`);
    });
    
    // Ordenar avaliações da mais recente para a mais antiga
    reviews.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    
    // Construir HTML para cada avaliação
    container.innerHTML = reviews.map(review => {
        // Verificação para garantir que temos o objeto movie
        const movie = review.movie || { id: 0, title: 'Filme indisponível', imageUrl: '' };
        
        return `
            <div class="review-card">
                <div class="review-movie">
                    <img src="${movie.imageUrl || 'images/placeholder.jpg'}" alt="${movie.title}" class="review-movie-poster">
                    <div class="review-movie-info">
                        <h4 class="review-movie-title">${movie.title}</h4>
                        <span class="review-date">Avaliado em ${formatDate(review.createdAt)}</span>
                    </div>
                </div>
                
                <div class="review-content">
                    <div class="review-rating">${starRating(review.rating)} ${Number(review.rating).toFixed(1)}</div>
                    <div class="review-text">${review.comment || 'Sem comentários'}</div>
                </div>
                
                ${movie.id ? `
                <a href="movie-detail.html?id=${movie.id}" class="btn-primary movie-link" style="margin-top:10px">
                    <i class="fas fa-eye"></i> Ver Filme
                </a>
                ` : ''}
            </div>
        `;
    }).join('');
}

// Função para renderizar os filmes do usuário - APENAS POSTERS
function renderUserMovies(movies) {
    const container = document.getElementById('user-movies');
    const emptyState = document.getElementById('empty-movies');
    
    if (!container || !emptyState) return; // Proteção contra elementos não encontrados
    
    if (!movies || movies.length === 0) {
        container.innerHTML = '';
        emptyState.style.display = 'block';
        return;
    }

    // Ocultar o estado vazio
    emptyState.style.display = 'none';
    
    // Ordenar filmes pelo ID (mais alto = mais recente)
    movies.sort((a, b) => b.id - a.id);
    
    // Construir HTML - Apenas posters dos filmes
    container.innerHTML = movies.map(movie => {
        return `
            <div class="movie-card">
                ${movie.imageUrl 
                    ? `<img src="${movie.imageUrl}" alt="${movie.title}" class="movie-poster">`
                    : `<div class="movie-poster placeholder"><i class="fas fa-film" style="font-size:48px;color:#89a"></i></div>`
                }
                <a href="movie-detail.html?id=${movie.id}" class="movie-link" aria-label="Ver detalhes de ${movie.title}"></a>
            </div>
        `;
    }).join('');
    
    // Adicionar estilo para melhorar a grade de posters
    const styleTag = document.createElement('style');
    styleTag.textContent = `
        #user-movies {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        
        #user-movies .movie-card {
            position: relative;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
            cursor: pointer;
            aspect-ratio: 2/3;
        }
        
        #user-movies .movie-card:hover {
            transform: translateY(-5px);
        }
        
        #user-movies .movie-poster {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        
        #user-movies .placeholder {
            display: flex;
            align-items: center;
            justify-content: center;
            background-color: #f0f0f0;
            height: 100%;
        }
        
        #user-movies .movie-link {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
        }
    `;
    document.head.appendChild(styleTag);
    
    // Adicionar links aos cards de filme
    document.querySelectorAll('.movie-card').forEach(card => {
        card.addEventListener('click', function() {
            const link = this.querySelector('.movie-link');
            if (link) window.location.href = link.href;
        });
    });
}

// Função para calcular estatísticas do usuário
function updateUserStats(reviews, movies) {
    const totalReviewsElement = document.getElementById('total-reviews');
    const totalMoviesElement = document.getElementById('total-movies');
    const averageRatingElement = document.getElementById('average-rating');
    
    // Atualizar contagem de avaliações
    if (totalReviewsElement) {
        totalReviewsElement.textContent = reviews?.length || '0';
    }
    
    // Atualizar contagem de filmes
    if (totalMoviesElement) {
        totalMoviesElement.textContent = movies?.length || '0';
    }
    
    // Calcular e atualizar média de avaliações
    if (averageRatingElement) {
        if (!reviews || reviews.length === 0) {
            averageRatingElement.textContent = '0.0';
        } else {
            const totalRating = reviews.reduce((sum, review) => sum + Number(review.rating), 0);
            const averageRating = (totalRating / reviews.length).toFixed(1);
            averageRatingElement.textContent = averageRating;
        }
    }
}

// Configurar navegação por abas
function setupTabs() {
    const tabs = document.querySelectorAll('.profile-tab');
    const contents = document.querySelectorAll('.tab-content');
    
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            // Remover classe ativa de todas as abas
            tabs.forEach(t => t.classList.remove('active'));
            contents.forEach(c => c.classList.remove('active'));
            
            // Adicionar classe ativa à aba clicada
            tab.classList.add('active');
            
            // Mostrar o conteúdo correspondente
            const tabName = tab.getAttribute('data-tab');
            document.getElementById(`${tabName}-content`).classList.add('active');
        });
    });
}

// Configurar botão de editar perfil
function setupProfileButtons() {
    const editProfileBtn = document.getElementById('edit-profile-btn');
    const saveProfileBtn = document.getElementById('save-profile-btn');
    const editProfileSection = document.getElementById('edit-profile-section');
    
    if (editProfileBtn && saveProfileBtn && editProfileSection) {
        // Botão de editar perfil
        editProfileBtn.addEventListener('click', () => {
            editProfileSection.style.display = 'block';
            editProfileBtn.style.display = 'none';
            saveProfileBtn.style.display = 'inline-block';
        });
        
        // Botão de salvar alterações
        saveProfileBtn.addEventListener('click', async () => {
            const name = document.getElementById('name').value.trim();
            const password = document.getElementById('password').value.trim();
            const confirmPassword = document.getElementById('confirmPassword').value.trim();
            
            // Validação básica
            if (!name) {
                showNotification('O nome não pode estar vazio', 'error');
                return;
            }
            
            // Verificar se as senhas coincidem, se fornecidas
            if (password && password !== confirmPassword) {
                showNotification('As senhas não coincidem', 'error');
                return;
            }
            
            // Preparar dados para atualização
            const updateData = { name };
            
            // Adicionar senha apenas se fornecida
            if (password) {
                updateData.password = password;
            }
            
            // Mostrar notificação de processamento
            showNotification('Atualizando seu perfil...', 'info', 2000);
            
            // Enviar atualização
            try {
                const result = await profileService.updateProfile(updateData);
                
                if (result) {
                    // Esconder formulário e mostrar botão de editar
                    editProfileSection.style.display = 'none';
                    saveProfileBtn.style.display = 'none';
                    editProfileBtn.style.display = 'inline-block';
                    
                    // Limpar campos de senha
                    document.getElementById('password').value = '';
                    document.getElementById('confirmPassword').value = '';
                    
                    // Atualizar informações de autenticação local
                    await authService.initialize(); // Recarrega dados do usuário
                    
                    // Atualizar informações de perfil exibidas
                    populateProfileInfo(result.user || authService.getCurrentUser());
                }
            } catch (error) {
                console.error('Erro ao atualizar perfil:', error);
                showNotification('Falha ao processar atualização', 'error');
            }
        });
    }
}

// Configurar upload de foto de perfil
function setupAvatarUpload() {
    const changeAvatarBtn = document.getElementById('change-avatar-btn');
    const avatarUploadInput = document.getElementById('avatar-upload');
    const generateAvatarBtn = document.getElementById('generate-avatar-btn');
    
    // Configurar botão para upload de imagem personalizada
    if (changeAvatarBtn && avatarUploadInput) {
        // Configurar botão para abrir seletor de arquivos
        changeAvatarBtn.addEventListener('click', () => {
            avatarUploadInput.click();
        });
        
        // Configurar handler para quando um arquivo for selecionado
        avatarUploadInput.addEventListener('change', async (event) => {
            if (event.target.files && event.target.files[0]) {
                // Mostrar notificação
                showNotification('Enviando imagem...', 'info', 3000);
                
                // Criar FormData com o arquivo
                const formData = new FormData();
                formData.append('avatar', event.target.files[0]);
                
                // Enviar para o servidor
                try {
                    const result = await profileService.uploadAvatar(formData);
                    
                    if (result) {
                        // Atualizar avatar
                        updateUserAvatar(result.user);
                        
                        // Limpar input após upload
                        avatarUploadInput.value = '';
                    }
                } catch (error) {
                    console.error('Erro ao fazer upload de avatar:', error);
                    showNotification('Erro ao enviar imagem', 'error');
                }
            }
        });
    }
    
    // Configurar botão para geração de avatar automático (alternativa)
    if (generateAvatarBtn) {
        generateAvatarBtn.addEventListener('click', async () => {
            // Mostrar notificação
            showNotification('Gerando avatar...', 'info', 3000);
            
            try {
                const result = await profileService.generateAvatar();
                
                if (result) {
                    // Atualizar avatar
                    updateUserAvatar(result.user);
                }
            } catch (error) {
                console.error('Erro ao gerar avatar:', error);
                showNotification('Erro ao gerar avatar', 'error');
            }
        });
    }
}

// Configurar botão de adicionar filme
function setupAddMovieButton() {
    const addMovieBtn = document.querySelector('.add-movie-btn');
    
    if (addMovieBtn) {
        addMovieBtn.addEventListener('click', () => {
            window.location.href = 'add.html';
        });
    }
}

// Função para inicializar a página de perfil
async function initProfilePage() {
    console.log("Inicializando página de perfil...");
    
    // Limpar TODAS as notificações ao iniciar a página
    clearAllNotifications();
    
    try {
        // Verificar autenticação sem redirecionar
        if (!authService.isAuthenticated()) {
            console.log("Usuário não autenticado, redirecionando...");
            showNotification('Faça login para acessar seu perfil', 'error');
            // Atrasar redirecionamento para dar tempo da notificação aparecer
            setTimeout(() => {
                window.location.href = 'login.html';
            }, 2000);
            return;
        }
        
        // Configurar navegação por abas
        setupTabs();
        
        // Configurar botões de perfil
        setupProfileButtons();
        
        // Configurar upload de avatar
        setupAvatarUpload();
        
        // Configurar botão de adicionar filme
        setupAddMovieButton();
        
        // Mostrar uma mensagem de carregamento com ID para poder remover depois
        const loadingId = showNotification('Carregando seu perfil...', 'info', 5000);
        
        // Carregar dados do usuário
        console.log("Buscando dados do usuário...");
        const userData = await profileService.fetchUserData();
        
        // Remover notificação de carregamento ASSIM QUE dados chegarem
        removeNotification(loadingId);
        
        // Se não conseguiu buscar dados do usuário, não prosseguir
        if (!userData) {
            console.error("Falha ao buscar dados do usuário");
            return;
        }
        
        console.log("Dados do usuário recebidos:", userData);
        populateProfileInfo(userData);
        
        // Carregar dados em paralelo para melhor performance
        const [userReviews, userMovies] = await Promise.all([
            profileService.fetchUserReviews(),
            profileService.fetchUserMovies()
        ]);
        
        console.log("Avaliações recebidas:", userReviews?.length || 0);
        console.log("Filmes recebidos:", userMovies?.length || 0);
        
        // Renderizar dados
        renderUserReviews(userReviews);
        renderUserMovies(userMovies);
        
        // Atualizar estatísticas
        updateUserStats(userReviews, userMovies);
        
    } catch (error) {
        console.error('Erro ao inicializar página de perfil:', error);
        showNotification('Erro ao carregar suas informações', 'error');
    }
}

// Função para remover uma notificação específica
function removeNotification(id) {
    if (!id) return;
    
    const notification = document.querySelector(`[data-notification-id="${id}"]`);
    if (notification) {
        notification.remove();
    }
}

// Função para limpar todas as notificações
function clearAllNotifications() {
    const container = document.getElementById('notification-container');
    if (container) {
        container.innerHTML = '';
    }
}

// Função para dados mockados (enquanto o backend não está pronto)
function mockUserMovies() {
    return [
        {
            id: 1,
            title: "Interestelar",
            releaseYear: 2014,
            imageUrl: "https://m.media-amazon.com/images/M/MV5BZjdkOTU3MDktN2IxOS00OGEyLWFmMjktY2FiMmZkNWIyODZiXkEyXkFqcGdeQXVyMTMxODk2OTU@._V1_.jpg",
            averageRating: 4.8,
            _count: { reviews: 15 },
            createdAt: "2023-05-10T14:32:00Z",
            userId: 1
        },
        {
            id: 2,
            title: "Clube da Luta",
            releaseYear: 1999,
            imageUrl: "https://m.media-amazon.com/images/M/MV5BMmEzNTkxYjQtZTc0MC00YTVjLTg5ZTEtZWMwOWVlYzY0NWIwXkEyXkFqcGdeQXVyNzkwMjQ5NzM@._V1_.jpg",
            averageRating: 4.5,
            _count: { reviews: 8 },
            createdAt: "2023-04-28T09:15:00Z",
            userId: 1
        },
        {
            id: 3,
            title: "Matrix",
            releaseYear: 1999,
            imageUrl: "https://m.media-amazon.com/images/M/MV5BNzQzOTk3OTAtNDQ0Zi00ZTVkLWI0MTEtMDllZjNkYzNjNTc4L2ltYWdlXkEyXkFqcGdeQXVyNjU0OTQ0OTY@._V1_.jpg",
            averageRating: 4.7,
            _count: { reviews: 12 },
            createdAt: "2023-04-20T18:45:00Z",
            userId: 1
        }
    ];
}

// Inicialização quando o DOM estiver carregado
document.addEventListener('DOMContentLoaded', () => {
    console.log("DOM carregado, iniciando componentes...");
    
    // Inicializar navbar
    initializeNavbar();
    
    // Inicializar página de perfil (com pequeno atraso)
    setTimeout(() => {
        initProfilePage();
    }, 100);
});