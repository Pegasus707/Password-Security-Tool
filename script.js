// --- Element Selection ---
const passwordInput = document.getElementById('password-input');
const toggleVisibilityBtn = document.getElementById('toggle-visibility');
const strengthBarInner = document.getElementById('strength-bar-inner');
const strengthText = document.getElementById('strength-text');
const patternWarning = document.getElementById('pattern-warning');
const checks = {
    length: document.getElementById('length-check'),
    uppercase: document.getElementById('uppercase-check'),
    lowercase: document.getElementById('lowercase-check'),
    number: document.getElementById('number-check'),
    symbol: document.getElementById('symbol-check'),
    pwned: document.getElementById('pwned-check')
};
const generatedPasswordInput = document.getElementById('generated-password');
const lengthSlider = document.getElementById('length-slider');
const lengthValue = document.getElementById('length-value');
const uppercaseOption = document.getElementById('uppercase-option');
const numbersOption = document.getElementById('numbers-option');
const symbolsOption = document.getElementById('symbols-option');
const generateButton = document.getElementById('generate-button');
const copyButton = document.getElementById('copy-button');
const copyFeedback = document.getElementById('copy-feedback');

// --- Weak Pattern Definitions ---
const COMMON_PASSWORDS = ['password', '123456', '12345678', '123456789', 'qwerty', 'iloveyou', '111111', 'password123', '123123', 'football', 'secret'];
const KEYBOARD_PATTERNS = ['qwerty', 'asdfgh', 'zxcvbn', 'qazwsx', '1q2w3e4r'];

let debounceTimer;

// --- Password Analysis Logic ---
function checkPatterns(password) {
    const lowerCasePassword = password.toLowerCase();
    for (const common of COMMON_PASSWORDS) {
        if (lowerCasePassword.includes(common)) {
            return { isWeak: true, message: '⚠️ Avoid using very common words or phrases.' };
        }
    }
    for (const pattern of KEYBOARD_PATTERNS) {
        if (lowerCasePassword.includes(pattern)) {
            return { isWeak: true, message: '⚠️ Avoid simple keyboard patterns.' };
        }
    }
    if (/(.)\1{2,}/.test(lowerCasePassword)) {
        return { isWeak: true, message: '⚠️ Avoid repeating characters (e.g., "aaa").' };
    }
    for (let i = 0; i < lowerCasePassword.length - 2; i++) {
        const char1 = lowerCasePassword.charCodeAt(i);
        const char2 = lowerCasePassword.charCodeAt(i + 1);
        const char3 = lowerCasePassword.charCodeAt(i + 2);
        if ((char1 + 1 === char2 && char2 + 1 === char3) || (char1 - 1 === char2 && char2 - 1 === char3)) {
            return { isWeak: true, message: '⚠️ Avoid sequential characters (e.g., "abc" or "123").' };
        }
    }
    return { isWeak: false, message: '' };
}

async function analyzePassword(password) {
    if (password.length === 0) {
        resetUI();
        return;
    }

    let score = 0;
    if (/.{12,}/.test(password)) { score++; updateCheckUI(checks.length, true); } else { updateCheckUI(checks.length, false); }
    if (/[A-Z]/.test(password)) { score++; updateCheckUI(checks.uppercase, true); } else { updateCheckUI(checks.uppercase, false); }
    if (/[a-z]/.test(password)) { score++; updateCheckUI(checks.lowercase, true); } else { updateCheckUI(checks.lowercase, false); }
    if (/[0-9]/.test(password)) { score++; updateCheckUI(checks.number, true); } else { updateCheckUI(checks.number, false); }
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) { score++; updateCheckUI(checks.symbol, true); } else { updateCheckUI(checks.symbol, false); }
    
    const patternResult = checkPatterns(password);
    
    updateCheckUI(checks.pwned, 'loading');
    const pwnedResult = await checkPwnedPassword(password);
    
    if (pwnedResult.isPwned) {
        updateCheckUI(checks.pwned, 'pwned');
    } else {
        updateCheckUI(checks.pwned, 'safe');
    }

    updateStrengthBar(score, pwnedResult, patternResult);
}

async function checkPwnedPassword(password) {
    try {
        const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password));
        const hash = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        const prefix = hash.substring(0, 5);
        const suffix = hash.substring(5);
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        if (!response.ok) return { isPwned: false, count: 0 };
        const data = await response.text();
        
        const lines = data.split('\n');
        for (const line of lines) {
            const [hashSuffix, count] = line.split(':');
            if (hashSuffix === suffix) {
                return { isPwned: true, count: parseInt(count) };
            }
        }
        return { isPwned: false, count: 0 };
    } catch (error) {
        console.error("Could not check pwned password:", error);
        return { isPwned: false, count: 0 };
    }
}

// --- UI Update Functions ---
function updateCheckUI(element, status) {
    const icon = element.querySelector('i');
    const wasMet = element.classList.contains('text-green-400');

    element.classList.remove('text-gray-500', 'text-green-400', 'text-red-500', 'text-yellow-400');
    icon.className = 'fa-solid w-5 mr-2';

    if (status === true || status === 'safe') {
        element.classList.add('text-green-400');
        icon.classList.add('fa-check-circle');
        if (!wasMet) { icon.classList.add('icon-pop'); setTimeout(() => icon.classList.remove('icon-pop'), 500); }
    } else if (status === false) {
        element.classList.add('text-gray-500'); icon.classList.add('fa-times-circle');
    } else if (status === 'pwned') {
        element.classList.add('text-red-500'); icon.classList.add('fa-exclamation-triangle');
    } else if (status === 'loading') {
        element.classList.add('text-yellow-400'); icon.classList.add('fa-spinner');
    } else {
         element.classList.add('text-gray-500'); icon.classList.add('fa-question-circle');
    }
}

function updateStrengthBar(score, pwnedResult, patternResult) {
    strengthBarInner.classList.remove('shimmer');
    strengthText.textContent = '';
    patternWarning.textContent = '';

    if (pwnedResult.isPwned) {
        strengthBarInner.style.width = '10%';
        strengthBarInner.style.backgroundColor = '#ef4444'; // red-500
        const countFormatted = new Intl.NumberFormat().format(pwnedResult.count);
        strengthText.innerHTML = `<span class="font-bold text-red-500">PWNED!</span>`;
        patternWarning.textContent = `Seen in breaches ${countFormatted} times.`;
        return;
    }

    if (patternResult.isWeak) {
        strengthBarInner.style.width = '10%';
        strengthBarInner.style.backgroundColor = '#ef4444'; // red-500
        strengthText.textContent = 'Very Weak';
        patternWarning.textContent = patternResult.message;
        return;
    }

    const finalScore = score;
    const width = (finalScore / 5) * 100;
    strengthBarInner.style.width = `${width}%`;

    switch (finalScore) {
        case 0: case 1: case 2:
            strengthBarInner.style.backgroundColor = '#f87171'; // red-400
            strengthText.textContent = 'Weak';
            break;
        case 3: case 4:
            strengthBarInner.style.backgroundColor = '#facc15'; // yellow-400
            strengthText.textContent = 'Moderate';
            break;
        case 5:
            strengthBarInner.style.backgroundColor = '#4ade80'; // green-400
            strengthText.textContent = 'Strong';
            strengthBarInner.classList.add('shimmer');
            break;
    }
}

function resetUI() {
    strengthBarInner.style.width = '0%';
    strengthBarInner.classList.remove('shimmer');
    strengthText.textContent = 'Enter a password to see its strength.';
    patternWarning.textContent = '';
    Object.values(checks).forEach(el => updateCheckUI(el, false));
    updateCheckUI(checks.pwned, 'initial');
}

function generateGuaranteedPassword() {
    const length = parseInt(lengthSlider.value);
    const charsets = { lowercase: "abcdefghijklmnopqrstuvwxyz", uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", numbers: "0123456789", symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?" };
    let allChars = charsets.lowercase, requiredChars = [];
    
    if (uppercaseOption.checked) { allChars += charsets.uppercase; requiredChars.push(charsets.uppercase[Math.floor(Math.random() * charsets.uppercase.length)]); }
    if (numbersOption.checked) { allChars += charsets.numbers; requiredChars.push(charsets.numbers[Math.floor(Math.random() * charsets.numbers.length)]); }
    if (symbolsOption.checked) { allChars += charsets.symbols; requiredChars.push(charsets.symbols[Math.floor(Math.random() * charsets.symbols.length)]); }
    if (allChars === charsets.lowercase && requiredChars.length === 0) { copyFeedback.textContent = 'Select at least one character type.'; setTimeout(() => copyFeedback.textContent = '', 3000); return; }

    let passwordArray = [...requiredChars];
    const remainingLength = length - passwordArray.length;
    if (remainingLength > 0) {
        const randomValues = new Uint32Array(remainingLength);
        window.crypto.getRandomValues(randomValues);
        for (let i = 0; i < remainingLength; i++) { passwordArray.push(allChars[randomValues[i] % allChars.length]); }
    }
    for (let i = passwordArray.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [passwordArray[i], passwordArray[j]] = [passwordArray[j], passwordArray[i]]; }
    const password = passwordArray.join('');
    
    generatedPasswordInput.value = password;
    passwordInput.value = password;
    analyzePassword(password);
    copyFeedback.textContent = '';
}

// --- Initial & Event Listeners ---
passwordInput.addEventListener('input', () => { clearTimeout(debounceTimer); debounceTimer = setTimeout(() => { analyzePassword(passwordInput.value); }, 300); });
toggleVisibilityBtn.addEventListener('click', () => { const isPassword = passwordInput.type === 'password'; passwordInput.type = isPassword ? 'text' : 'password'; toggleVisibilityBtn.innerHTML = isPassword ? '<i class="fa-solid fa-eye-slash text-xl"></i>' : '<i class="fa-solid fa-eye text-xl"></i>'; });
lengthSlider.addEventListener('input', () => { lengthValue.textContent = lengthSlider.value; });
generateButton.addEventListener('click', generateGuaranteedPassword);
copyButton.addEventListener('click', () => { if (!generatedPasswordInput.value) return; navigator.clipboard.writeText(generatedPasswordInput.value).then(() => { copyFeedback.textContent = 'Copied to clipboard!'; setTimeout(() => copyFeedback.textContent = '', 2000); }); });

// Set initial state on page load
resetUI();
