// js/components.js

// Componente de navegação reutilizável
export function renderNavbar(currentPage) {
  const navbar = document.createElement('header');
  navbar.className = 'navbar';
  
  navbar.innerHTML = `
    <a href="index.html" class="logo-link">
      <div class="logo-container">
        <div class="logo-icon">
          <div class="logo-circles">
            <div class="logo-circle orange"></div>
            <div class="logo-circle green"></div>
            <div class="logo-circle blue"></div>
          </div>
        </div>
        <h1 class="logo-text">CineLog</h1>
      </div>
    </a>
    <nav>
      <a href="index.html" class="${currentPage === 'home' ? 'active' : ''}">Início</a>
      <a href="add.html" data-auth="authenticated" class="${currentPage === 'add' ? 'active' : ''}">Adicionar Filme</a>
      <a href="profile.html" data-auth="authenticated" class="${currentPage === 'profile' ? 'active' : ''}">Perfil</a>
      <!-- Novo link para o painel de administração - apenas para admins -->
      <a href="admin.html" data-auth="admin" class="${currentPage === 'admin' ? 'active' : ''}">Administração</a>
      <a href="#" id="logout-link" data-auth="authenticated">Sair</a>
      <a href="login.html" data-auth="unauthenticated" class="${currentPage === 'login' ? 'active' : ''}">Login</a>
      <a href="register.html" data-auth="unauthenticated" class="${currentPage === 'register' ? 'active' : ''}">Cadastrar</a>
    </nav>
  `;
  
  return navbar;
}

// Função para inicializar o componente da navbar em todas as páginas
export function initializeNavbar() {
  // Determinar a página atual com base no URL
  const path = window.location.pathname;
  let currentPage = 'home';
  
  if (path.includes('movie-detail.html')) {
    currentPage = 'detail';
    document.body.classList.add('movie-detail-page');
  }
  else if (path.includes('add.html')) currentPage = 'add';
  else if (path.includes('edit.html')) currentPage = 'edit';
  else if (path.includes('profile.html')) currentPage = 'profile';
  else if (path.includes('admin.html')) currentPage = 'admin'; // Nova página admin
  else if (path.includes('login.html')) {
    currentPage = 'login';
    document.body.classList.add('login-page');
  }
  else if (path.includes('register.html')) {
    currentPage = 'register';
    document.body.classList.add('register-page');
  }
  
  // Renderizar a navbar no início do body
  const navbar = renderNavbar(currentPage);
  document.body.prepend(navbar);
  
  // Configurar o event listener de logout
  const logoutLink = document.getElementById('logout-link');
  if (logoutLink) {
    logoutLink.addEventListener('click', (e) => {
      e.preventDefault();
      // Importamos dinamicamente o authService para evitar dependências circulares
      import('./auth.js').then(module => {
        module.authService.logout();
      });
    });
  }
}