// js/register.js

// Import necessary modules
import { authService } from './auth.js';
import { showNotification } from './utils.js';

/**
 * Inicializa o comportamento e validações do formulário de registro
 */
function initRegisterPage() {
    // Verificar se já está autenticado
    if (authService.isAuthenticated()) {
        console.log('User is already authenticated, redirecting to home.');
        const redirectTo = localStorage.getItem('redirectTo') || '/';
        localStorage.removeItem('redirectTo');
        window.location.href = redirectTo;
        return;
    }

    // Inicializar os componentes da página
    setupRegisterForm();
    setupPasswordValidation();
    setupFormValidation();
}

/**
 * Configura o formulário de registro e seus eventos
 */
function setupRegisterForm() {
    const registerForm = document.getElementById('register-form');
    const togglePassword = document.querySelector('.toggle-password');
    
    // Toggle password visibility
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

    // Form submission
    if (registerForm) {
        registerForm.addEventListener('submit', handleFormSubmit);
    } else {
        console.error('Registration form with ID "register-form" not found!');
    }
}

/**
 * Manipula o envio do formulário de registro
 * @param {Event} event - O evento de submit do formulário
 */
async function handleFormSubmit(event) {
    event.preventDefault();
    
    // Get user data from form inputs
    const name = document.getElementById('name').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    
    // Verificar todos os requisitos de senha individualmente
    const hasMinLength = password.length >= 8;
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    
    // Se algum dos requisitos não for atendido, impedir o envio
    if (!hasMinLength || !hasUppercase || !hasLowercase || !hasNumber) {
        showNotification('Sua senha não atende a todos os requisitos. Por favor, verifique os requisitos listados.', 'error');
        return;
    }
    
    // Check if all fields are valid
    if (!validateForm()) {
        showNotification('Por favor, corrija os erros no formulário antes de continuar.', 'error');
        return;
    }
    
    const userData = { name, email, password };
    
    // Show loading state on button
    const registerButton = event.target.querySelector('.btn-register');
    const originalText = registerButton.textContent;
    registerButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Criando conta...';
    registerButton.disabled = true;
    
    try {
        // Call the register service
        const result = await authService.register(userData);
        console.log("Registro bem-sucedido:", result);
        // Success state is handled in authService.register
        
    } catch (error) {
        console.error('Erro ao registrar:', error);
        
        // Determine the error message based on the error status
        let errorMessage = 'Ocorreu um erro ao criar sua conta. Por favor, tente novamente.';
        
        // NOVO: Verificar o status do erro
        if (error.status === 409) {
            errorMessage = 'Este e-mail já está registrado. Por favor, use outro e-mail ou faça login.';
        } else if (error.message) {
            errorMessage = error.message;
        }
        
        // Mostrar notificação de erro
        showNotification(errorMessage, 'error');
        
        // IMPORTANTE: Resetar o botão para o estado original
        registerButton.innerHTML = originalText;
        registerButton.disabled = false;
    }
}

/**
 * Configura a validação de senha em tempo real
 */
function setupPasswordValidation() {
    const passwordInput = document.getElementById('password');
    const lengthCheck = document.getElementById('length');
    const uppercaseCheck = document.getElementById('uppercase');
    const lowercaseCheck = document.getElementById('lowercase');
    const numberCheck = document.getElementById('number');
    const strengthBar = document.querySelector('.password-strength-bar');
    const strengthText = document.getElementById('strength-text');
    
    if (!passwordInput) return;
    
    passwordInput.addEventListener('input', function() {
        const password = this.value;
        
        // Verifica cada requisito
        const hasMinLength = password.length >= 8;
        const hasUppercase = /[A-Z]/.test(password);
        const hasLowercase = /[a-z]/.test(password);
        const hasNumber = /[0-9]/.test(password);
        
        // Atualiza a interface para cada requisito
        updatePasswordRequirement(lengthCheck, hasMinLength);
        updatePasswordRequirement(uppercaseCheck, hasUppercase);
        updatePasswordRequirement(lowercaseCheck, hasLowercase);
        updatePasswordRequirement(numberCheck, hasNumber);
        
        // Calcula a força da senha
        let strength = 'weak';
        let score = 0;
        
        if (hasMinLength) score++;
        if (hasUppercase) score++;
        if (hasLowercase) score++;
        if (hasNumber) score++;
        
        if (score >= 4) {
            strength = 'strong';
        } else if (score >= 2) {
            strength = 'medium';
        }
        
        // Atualiza a barra de força
        strengthBar.className = 'password-strength-bar';
        strengthBar.classList.add(`strength-${strength}`);
        
        // Update strength text
        switch (strength) {
            case 'weak':
                strengthText.textContent = 'Fraca';
                strengthText.style.color = '#f44336';
                break;
            case 'medium':
                strengthText.textContent = 'Média';
                strengthText.style.color = '#ff9800';
                break;
            case 'strong':
                strengthText.textContent = 'Forte';
                strengthText.style.color = '#00C030';
                break;
        }
    });
}

/**
 * Atualiza visualmente os requisitos de senha
 * @param {HTMLElement} element - O elemento LI a ser atualizado
 * @param {boolean} isValid - Indica se o requisito foi atendido
 */
function updatePasswordRequirement(element, isValid) {
    if (!element) return; // Protege contra elemento não encontrado
    
    if (isValid) {
        element.classList.add('valid');
        element.querySelector('i').className = 'fas fa-check-circle';
    } else {
        element.classList.remove('valid');
        element.querySelector('i').className = 'fas fa-circle';
    }
}

/**
 * Configura validação em tempo real para os campos do formulário
 */
function setupFormValidation() {
    const nameInput = document.getElementById('name');
    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');
    
    if (nameInput) {
        nameInput.addEventListener('blur', function() {
            validateName(this);
        });
    }
    
    if (emailInput) {
        emailInput.addEventListener('blur', function() {
            validateEmail(this);
        });
    }
    
    if (passwordInput) {
        passwordInput.addEventListener('blur', function() {
            validatePassword(this);
        });
    }
}

/**
 * Valida o campo de nome
 * @param {HTMLInputElement} input - O campo de input a ser validado
 * @returns {boolean} - Indica se o campo é válido
 */
function validateName(input) {
    const formGroup = input.closest('.form-group');
    const errorMessage = formGroup.querySelector('.error-message');
    
    if (input.value.trim().length < 3) {
        formGroup.classList.add('invalid');
        formGroup.classList.remove('valid');
        if (errorMessage) errorMessage.textContent = 'O nome deve ter pelo menos 3 caracteres.';
        return false;
    } else {
        formGroup.classList.add('valid');
        formGroup.classList.remove('invalid');
        return true;
    }
}

/**
 * Valida o campo de email
 * @param {HTMLInputElement} input - O campo de input a ser validado
 * @returns {boolean} - Indica se o campo é válido
 */
function validateEmail(input) {
    const formGroup = input.closest('.form-group');
    const errorMessage = formGroup.querySelector('.error-message');
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    
    if (!emailRegex.test(input.value)) {
        formGroup.classList.add('invalid');
        formGroup.classList.remove('valid');
        if (errorMessage) errorMessage.textContent = 'Por favor, insira um e-mail válido.';
        return false;
    } else {
        formGroup.classList.add('valid');
        formGroup.classList.remove('invalid');
        return true;
    }
}

/**
 * Valida o campo de senha
 * @param {HTMLInputElement} input - O campo de input a ser validado
 * @returns {boolean} - Indica se o campo é válido
 */
function validatePassword(input) {
    const formGroup = input.closest('.form-group');
    const password = input.value;
    
    const hasMinLength = password.length >= 8;
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    
    if (!hasMinLength || !hasUppercase || !hasLowercase || !hasNumber) {
        formGroup.classList.add('invalid');
        formGroup.classList.remove('valid');
        return false;
    } else {
        formGroup.classList.add('valid');
        formGroup.classList.remove('invalid');
        return true;
    }
}

/**
 * Valida todo o formulário
 * @returns {boolean} - Indica se todos os campos são válidos
 */
function validateForm() {
    const nameInput = document.getElementById('name');
    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');
    
    const isNameValid = nameInput ? validateName(nameInput) : false;
    const isEmailValid = emailInput ? validateEmail(emailInput) : false;
    const isPasswordValid = passwordInput ? validatePassword(passwordInput) : false;
    
    return isNameValid && isEmailValid && isPasswordValid;
}

// Inicializa a página quando o DOM estiver pronto
document.addEventListener('DOMContentLoaded', initRegisterPage);