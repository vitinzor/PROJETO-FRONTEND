// js/login.js

// Import necessary modules
import { authService } from './auth.js';
import { showNotification } from './utils.js';

/**
 * Inicializa o comportamento da página de login
 */
function initLoginPage() {
    // Verificar se já está autenticado
    if (authService.isAuthenticated()) {
        console.log('User is already authenticated, redirecting to home.');
        const redirectTo = localStorage.getItem('redirectTo') || '/';
        localStorage.removeItem('redirectTo');
        window.location.href = redirectTo;
        return;
    }

    // Inicializar os componentes da página
    setupLoginForm();
    setupPasswordToggle();
}

/**
 * Configura o formulário de login e seus eventos
 */
function setupLoginForm() {
    const loginForm = document.getElementById('login-form');
    
    if (loginForm) {
        loginForm.addEventListener('submit', handleLoginSubmit);
    } else {
        console.error('Login form with ID "login-form" not found!');
    }
}

/**
 * Manipula o envio do formulário de login
 * @param {Event} event - O evento de submit do formulário
 */
async function handleLoginSubmit(event) {
    event.preventDefault();
    
    // Get credentials from form inputs
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    
    // Basic client-side validation
    if (!validateLoginForm(email, password)) {
        return;
    }
    
    const credentials = { email, password };
    
    // Show loading state
    const loginButton = event.target.querySelector('button[type="submit"]');
    const originalText = loginButton.textContent;
    loginButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Entrando...';
    loginButton.disabled = true;
    
    try {
        // Call the login service
        await authService.login(credentials);
        
        // Success is handled in authService.login
    } catch (error) {
        // Reset button state
        loginButton.textContent = originalText;
        loginButton.disabled = false;
    }
}

/**
 * Valida os campos do formulário de login
 * @param {string} email - Email do usuário
 * @param {string} password - Senha do usuário
 * @returns {boolean} - Indica se o formulário é válido
 */
function validateLoginForm(email, password) {
    let isValid = true;
    
    // Validate email
    const emailInput = document.getElementById('email');
    const emailFormGroup = emailInput.closest('.form-group');
    const emailErrorMessage = emailFormGroup.querySelector('.error-message');
    
    if (!email) {
        emailFormGroup.classList.add('invalid');
        emailFormGroup.classList.remove('valid');
        if (emailErrorMessage) emailErrorMessage.textContent = 'Por favor, insira seu e-mail.';
        isValid = false;
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        emailFormGroup.classList.add('invalid');
        emailFormGroup.classList.remove('valid');
        if (emailErrorMessage) emailErrorMessage.textContent = 'Por favor, insira um e-mail válido.';
        isValid = false;
    } else {
        emailFormGroup.classList.add('valid');
        emailFormGroup.classList.remove('invalid');
    }
    
    // Validate password
    const passwordInput = document.getElementById('password');
    const passwordFormGroup = passwordInput.closest('.form-group');
    const passwordErrorMessage = passwordFormGroup.querySelector('.error-message');
    
    if (!password) {
        passwordFormGroup.classList.add('invalid');
        passwordFormGroup.classList.remove('valid');
        if (passwordErrorMessage) passwordErrorMessage.textContent = 'Por favor, insira sua senha.';
        isValid = false;
    } else {
        passwordFormGroup.classList.add('valid');
        passwordFormGroup.classList.remove('invalid');
    }
    
    return isValid;
}

/**
 * Configura o toggle de visibilidade da senha
 */
function setupPasswordToggle() {
    const togglePassword = document.querySelector('.toggle-password');
    
    if (togglePassword) {
        togglePassword.addEventListener('click', function() {
            const passwordInput = document.getElementById('password');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                this.classList.remove('fa-eye-slash');
                this.classList.add('fa-eye');
            } else {
                passwordInput.type = 'password';
                this.classList.remove('fa-eye');
                this.classList.add('fa-eye-slash');
            }
        });
    }
}

// Adicionar validação em tempo real para os campos
document.addEventListener('DOMContentLoaded', function() {
    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');
    
    if (emailInput) {
        emailInput.addEventListener('blur', function() {
            const email = this.value.trim();
            const formGroup = this.closest('.form-group');
            const errorMessage = formGroup.querySelector('.error-message');
            
            if (!email) {
                formGroup.classList.add('invalid');
                formGroup.classList.remove('valid');
                if (errorMessage) errorMessage.textContent = 'Por favor, insira seu e-mail.';
            } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
                formGroup.classList.add('invalid');
                formGroup.classList.remove('valid');
                if (errorMessage) errorMessage.textContent = 'Por favor, insira um e-mail válido.';
            } else {
                formGroup.classList.add('valid');
                formGroup.classList.remove('invalid');
            }
        });
    }
    
    if (passwordInput) {
        passwordInput.addEventListener('blur', function() {
            const password = this.value;
            const formGroup = this.closest('.form-group');
            const errorMessage = formGroup.querySelector('.error-message');
            
            if (!password) {
                formGroup.classList.add('invalid');
                formGroup.classList.remove('valid');
                if (errorMessage) errorMessage.textContent = 'Por favor, insira sua senha.';
            } else {
                formGroup.classList.add('valid');
                formGroup.classList.remove('invalid');
            }
        });
    }
});

// Inicializa a página quando o DOM estiver pronto
document.addEventListener('DOMContentLoaded', initLoginPage);