class SecureNotebook {
    constructor() {
        this.currentTheme = 'dark';
        this.noteContent = '';
        this.noteTitle = '';
        this.undoStack = [];
        this.redoStack = [];
        this.maxUndoSteps = 50;
        this.syntaxHighlightEnabled = false;
        this.currentSection = 'password';
        this.encryptionMode = null;
        this.initializeElements();
        this.bindEvents();
        this.loadTheme();
        this.initializeEditor();
        this.initializeNavigation();
    }

    initializeElements() {
        // Navigation elements
        this.navMenu = document.getElementById('navMenu');
        this.navToggle = document.getElementById('navToggle');
        this.navLinks = document.querySelectorAll('.nav-link');

        // Password elements
        this.passwordInput = document.getElementById('passwordInput');
        this.togglePasswordBtn = document.getElementById('togglePassword');
        this.checkPasswordBtn = document.getElementById('checkPassword');
        this.generatePasswordBtn = document.getElementById('generatePassword');
        this.clearPasswordBtn = document.getElementById('clearPassword');

        // Strength display elements
        this.strengthDisplay = document.getElementById('strengthDisplay');
        this.strengthLevel = document.getElementById('strengthLevel');
        this.strengthScore = document.getElementById('strengthScore');
        this.strengthFill = document.getElementById('strengthFill');
        this.strengthPercentage = document.getElementById('strengthPercentage');
        this.suggestions = document.getElementById('suggestions');
        this.suggestionsList = document.getElementById('suggestionsList');

        // Criteria elements
        this.criteriaLength = document.getElementById('criteriaLength');
        this.criteriaUppercase = document.getElementById('criteriaUppercase');
        this.criteriaLowercase = document.getElementById('criteriaLowercase');
        this.criteriaNumbers = document.getElementById('criteriaNumbers');
        this.criteriaSpecial = document.getElementById('criteriaSpecial');
        this.criteriaCommon = document.getElementById('criteriaCommon');

        // File upload elements
        this.dropZone = document.getElementById('dropZone');
        this.fileInput = document.getElementById('fileInput');
        this.browseFilesBtn = document.getElementById('browseFiles');

        // Encryption file upload elements
        this.encryptUploadZone = document.getElementById('encryptUploadZone');
        this.encryptFileInput = document.getElementById('encryptFileInput');
        this.browseEncryptFilesBtn = document.getElementById('browseEncryptFiles');

        // Decryption file upload elements
        this.decryptUploadZone = document.getElementById('decryptUploadZone');
        this.decryptFileInput = document.getElementById('decryptFileInput');
        this.browseDecryptFilesBtn = document.getElementById('browseDecryptFiles');
        this.manualEncryptedData = document.getElementById('manualEncryptedData');
        this.decryptManualBtn = document.getElementById('decryptManual');

        // Notebook elements
        this.noteTitleInput = document.getElementById('noteTitle');
        this.noteContentInput = document.getElementById('noteContent');
        this.newNoteBtn = document.getElementById('newNote');
        this.saveNoteBtn = document.getElementById('saveNote');
        this.downloadTxtBtn = document.getElementById('downloadTxt');
        this.downloadPdfBtn = document.getElementById('downloadPdf');
        this.boldTextBtn = document.getElementById('boldText');
        this.undoTextBtn = document.getElementById('undoText');
        this.redoTextBtn = document.getElementById('redoText');
        this.toggleSyntaxBtn = document.getElementById('toggleSyntax');
        this.fontSizeSlider = document.getElementById('fontSize');
        this.fontSizeValue = document.getElementById('fontSizeValue');
        this.wordCount = document.getElementById('wordCount');
        this.charCount = document.getElementById('charCount');
        this.lineNumbers = document.getElementById('lineNumbers');

        // Encryption elements
        this.encryptNoteBtn = document.getElementById('encryptNote');
        this.encryptedDataContainer = document.getElementById('encryptedDataContainer');
        this.encryptedData = document.getElementById('encryptedData');
        this.downloadEncryptedBtn = document.getElementById('downloadEncrypted');
        this.copyEncryptedBtn = document.getElementById('copyEncrypted');

        // Decryption elements
        this.decryptedDataContainer = document.getElementById('decryptedDataContainer');
        this.decryptedData = document.getElementById('decryptedData');
        this.downloadDecryptedBtn = document.getElementById('downloadDecrypted');
        this.loadToEditorBtn = document.getElementById('loadToEditor');
        this.copyDecryptedBtn = document.getElementById('copyDecrypted');

        // Modal elements
        this.encryptionModal = document.getElementById('encryptionModal');
        this.modalTitle = document.getElementById('modalTitle');
        this.encryptionPassword = document.getElementById('encryptionPassword');
        this.toggleEncryptionPassword = document.getElementById('toggleEncryptionPassword');
        this.confirmEncryption = document.getElementById('confirmEncryption');
        this.cancelEncryption = document.getElementById('cancelEncryption');
        this.modalClose = document.getElementById('modalClose');
        this.passwordStrengthMini = document.getElementById('passwordStrengthMini');
        this.strengthFillMini = document.getElementById('strengthFillMini');
        this.strengthTextMini = document.getElementById('strengthTextMini');

        // UI elements
        this.themeToggle = document.getElementById('themeToggle');
        this.loadingSpinner = document.getElementById('loadingSpinner');
        this.toast = document.getElementById('toast');
        this.toastIcon = document.getElementById('toastIcon');
        this.toastMessage = document.getElementById('toastMessage');
        this.toastClose = document.getElementById('toastClose');
    }

    bindEvents() {
        // Navigation events
        this.navToggle?.addEventListener('click', () => this.toggleNavigation());
        this.navLinks.forEach(link => {
            link.addEventListener('click', (e) => this.handleNavigation(e));
        });

        // Password events
        this.togglePasswordBtn?.addEventListener('click', () => this.togglePasswordVisibility());
        this.checkPasswordBtn?.addEventListener('click', () => this.checkPasswordStrength());
        this.generatePasswordBtn?.addEventListener('click', () => this.generateStrongPassword());
        this.clearPasswordBtn?.addEventListener('click', () => this.clearPassword());
        this.passwordInput?.addEventListener('input', () => this.onPasswordInput());
        this.passwordInput?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.checkPasswordStrength();
        });

        // File upload events (regular)
        this.browseFilesBtn?.addEventListener('click', () => this.fileInput.click());
        this.fileInput?.addEventListener('change', (e) => this.handleFileSelect(e));
        this.dropZone?.addEventListener('click', () => this.fileInput.click());
        this.dropZone?.addEventListener('dragover', (e) => this.handleDragOver(e, this.dropZone));
        this.dropZone?.addEventListener('dragleave', (e) => this.handleDragLeave(e, this.dropZone));
        this.dropZone?.addEventListener('drop', (e) => this.handleDrop(e, 'regular'));

        // Encryption file upload events
        this.browseEncryptFilesBtn?.addEventListener('click', () => this.encryptFileInput.click());
        this.encryptFileInput?.addEventListener('change', (e) => this.handleEncryptFileSelect(e));
        this.encryptUploadZone?.addEventListener('click', () => this.encryptFileInput.click());
        this.encryptUploadZone?.addEventListener('dragover', (e) => this.handleDragOver(e, this.encryptUploadZone));
        this.encryptUploadZone?.addEventListener('dragleave', (e) => this.handleDragLeave(e, this.encryptUploadZone));
        this.encryptUploadZone?.addEventListener('drop', (e) => this.handleDrop(e, 'encrypt'));

        // Decryption file upload events
        this.browseDecryptFilesBtn?.addEventListener('click', () => this.decryptFileInput.click());
        this.decryptFileInput?.addEventListener('change', (e) => this.handleDecryptFileSelect(e));
        this.decryptUploadZone?.addEventListener('click', () => this.decryptFileInput.click());
        this.decryptUploadZone?.addEventListener('dragover', (e) => this.handleDragOver(e, this.decryptUploadZone));
        this.decryptUploadZone?.addEventListener('dragleave', (e) => this.handleDragLeave(e, this.decryptUploadZone));
        this.decryptUploadZone?.addEventListener('drop', (e) => this.handleDrop(e, 'decrypt'));

        // Manual decryption
        this.decryptManualBtn?.addEventListener('click', () => this.decryptManualData());

        // Notebook events
        this.newNoteBtn?.addEventListener('click', () => this.newNote());
        this.saveNoteBtn?.addEventListener('click', () => this.saveNote());
        this.downloadTxtBtn?.addEventListener('click', () => this.downloadNote('txt'));
        this.downloadPdfBtn?.addEventListener('click', () => this.downloadNote('pdf'));
        this.boldTextBtn?.addEventListener('click', () => this.boldSelectedText());
        this.undoTextBtn?.addEventListener('click', () => this.undoEdit());
        this.redoTextBtn?.addEventListener('click', () => this.redoEdit());
        this.toggleSyntaxBtn?.addEventListener('click', () => this.toggleSyntaxHighlighting());
        this.fontSizeSlider?.addEventListener('input', (e) => this.changeFontSize(e.target.value));
        this.noteContentInput?.addEventListener('input', () => this.onContentChange());
        this.noteContentInput?.addEventListener('scroll', () => this.syncLineNumbers());
        this.noteTitleInput?.addEventListener('input', () => this.updateTitle());

        // Encryption events
        this.encryptNoteBtn?.addEventListener('click', () => this.showEncryptionModal('encrypt'));
        this.downloadEncryptedBtn?.addEventListener('click', () => this.downloadEncryptedFile());
        this.copyEncryptedBtn?.addEventListener('click', () => this.copyToClipboard(this.encryptedData.value, 'Encrypted data copied!'));

        // Decryption events
        this.downloadDecryptedBtn?.addEventListener('click', () => this.downloadDecryptedFile());
        this.loadToEditorBtn?.addEventListener('click', () => this.loadDecryptedToEditor());
        this.copyDecryptedBtn?.addEventListener('click', () => this.copyToClipboard(this.decryptedData.value, 'Decrypted content copied!'));
        
        // Modal events
        this.confirmEncryption?.addEventListener('click', () => this.handleEncryptionConfirm());
        this.cancelEncryption?.addEventListener('click', () => this.hideEncryptionModal());
        this.modalClose?.addEventListener('click', () => this.hideEncryptionModal());
        this.toggleEncryptionPassword?.addEventListener('click', () => this.toggleEncryptionPasswordVisibility());
        this.encryptionPassword?.addEventListener('input', () => this.checkModalPasswordStrength());

        // UI events
        this.themeToggle?.addEventListener('click', () => this.toggleTheme());
        this.toastClose?.addEventListener('click', () => this.hideToast());

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => this.handleKeyboard(e));

        // Click outside modal to close
        this.encryptionModal?.addEventListener('click', (e) => {
            if (e.target === this.encryptionModal) {
                this.hideEncryptionModal();
            }
        });
    }

    initializeEditor() {
        this.saveEditorState();
        this.updateLineNumbers();
        this.updateStats();
    }

    initializeNavigation() {
        // Show first section by default
        this.showSection('password');
    }

    // Navigation Methods
    toggleNavigation() {
        this.navMenu.classList.toggle('show');
    }

    handleNavigation(event) {
        event.preventDefault();
        const section = event.currentTarget.getAttribute('data-section');
        this.showSection(section);
        
        // Close mobile menu
        this.navMenu.classList.remove('show');
    }

    showSection(sectionName) {
        // Hide all sections
        const sections = document.querySelectorAll('.main-content > section');
        sections.forEach(section => section.classList.remove('active'));
        
        // Show target section
        const targetSection = document.getElementById(`${sectionName}-section`);
        if (targetSection) {
            targetSection.classList.add('active');
        }
        
        // Update navigation
        this.navLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('data-section') === sectionName) {
                link.classList.add('active');
            }
        });
        
        this.currentSection = sectionName;
    }

    // Password Methods
    togglePasswordVisibility() {
        const type = this.passwordInput.type === 'password' ? 'text' : 'password';
        this.passwordInput.type = type;
        const icon = this.togglePasswordBtn.querySelector('i');
        icon.className = type === 'password' ? 'fas fa-eye' : 'fas fa-eye-slash';
    }

    onPasswordInput() {
        if (this.passwordInput.value.length > 0) {
            clearTimeout(this.passwordTimeout);
            this.passwordTimeout = setTimeout(() => {
                this.checkPasswordStrength();
            }, 500);
        } else {
            this.hideStrengthDisplay();
        }
    }

    async checkPasswordStrength() {
        const password = this.passwordInput.value.trim();
        if (!password) {
            this.showToast('Please enter a password', 'error');
            return;
        }

        this.showLoading();
        try {
            const response = await fetch('/check-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ password })
            });

            const result = await response.json();
            if (result.success) {
                this.displayPasswordStrength(result.data);
            } else {
                this.showToast('Error checking password strength', 'error');
            }
        } catch (error) {
            console.error('Error:', error);
            this.showToast('Network error. Please try again.', 'error');
        } finally {
            this.hideLoading();
        }
    }

    async generateStrongPassword() {
        this.showLoading();
        try {
            const response = await fetch('/generate-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ length: 16 })
            });

            const result = await response.json();
            if (result.success) {
                this.passwordInput.value = result.password;
                this.displayPasswordStrength(result.strength);
                this.showToast('Strong password generated!', 'success');
            } else {
                this.showToast('Error generating password', 'error');
            }
        } catch (error) {
            console.error('Error:', error);
            this.showToast('Network error. Please try again.', 'error');
        } finally {
            this.hideLoading();
        }
    }

    clearPassword() {
        this.passwordInput.value = '';
        this.hideStrengthDisplay();
        this.passwordInput.focus();
    }

    displayPasswordStrength(data) {
        this.strengthDisplay.style.display = 'block';
        
        this.strengthLevel.textContent = `Password Strength: ${data.strength}`;
        this.strengthLevel.className = `strength-${data.strength.toLowerCase().replace(' ', '-')}`;
        this.strengthScore.textContent = `${data.score}/${data.max_score}`;
        
        this.strengthFill.style.width = `${data.percentage}%`;
        this.strengthPercentage.textContent = `${data.percentage}%`;
        
        this.updateCriteria(data.criteria);
        
        if (data.suggestions.length > 0) {
            this.suggestions.style.display = 'block';
            this.suggestionsList.innerHTML = '';
            data.suggestions.forEach(suggestion => {
                const li = document.createElement('li');
                li.textContent = suggestion;
                this.suggestionsList.appendChild(li);
            });
        } else {
            this.suggestions.style.display = 'none';
        }

        this.strengthDisplay.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    updateCriteria(criteria) {
        const criteriaMap = {
            'length': this.criteriaLength,
            'uppercase': this.criteriaUppercase,
            'lowercase': this.criteriaLowercase,
            'numbers': this.criteriaNumbers,
            'special': this.criteriaSpecial,
            'no_common': this.criteriaCommon
        };

        Object.entries(criteria).forEach(([key, value]) => {
            const element = criteriaMap[key];
            if (element) {
                const icon = element.querySelector('i');
                if (value) {
                    element.classList.add('valid');
                    icon.className = 'fas fa-check';
                } else {
                    element.classList.remove('valid');
                    icon.className = 'fas fa-times';
                }
            }
        });
    }

    hideStrengthDisplay() {
        this.strengthDisplay.style.display = 'none';
    }

    // File Upload Methods
    handleFileSelect(event) {
        const file = event.target.files[0];
        if (file) {
            this.processFile(file, 'regular');
        }
    }

    handleEncryptFileSelect(event) {
        const file = event.target.files[0];
        if (file) {
            this.processFile(file, 'encrypt');
        }
    }

    handleDecryptFileSelect(event) {
        const file = event.target.files[0];
        if (file) {
            this.processFile(file, 'decrypt');
        }
    }

    handleDragOver(event, element) {
        event.preventDefault();
        element.classList.add('drag-over');
    }

    handleDragLeave(event, element) {
        event.preventDefault();
        element.classList.remove('drag-over');
    }

    handleDrop(event, type) {
        event.preventDefault();
        const element = type === 'encrypt' ? this.encryptUploadZone : 
                       type === 'decrypt' ? this.decryptUploadZone : this.dropZone;
        element.classList.remove('drag-over');
        
        const files = event.dataTransfer.files;
        if (files.length > 0) {
            this.processFile(files[0], type);
        }
    }

    async processFile(file, type) {
        let endpoint = '/upload-file';
        let allowedExtensions = ['.txt'];
        let errorMessage = 'Only .txt files are supported';

        if (type === 'encrypt') {
            endpoint = '/upload-txt-for-encryption';
            allowedExtensions = ['.txt'];
            errorMessage = 'Only .txt files can be uploaded for encryption';
        } else if (type === 'decrypt') {
            endpoint = '/upload-encrypted-file';
            allowedExtensions = ['.encrypted', '.enc', '.txt'];
            errorMessage = 'Only .encrypted, .enc, or .txt files are supported for decryption';
        }

        // Check file extension
        const fileExt = '.' + file.name.split('.').pop().toLowerCase();
        if (!allowedExtensions.includes(fileExt)) {
            this.showToast(errorMessage, 'error');
            return;
        }

        this.showLoading();
        
        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                body: formData
            });

            const result = await response.json();
            if (result.success) {
                if (type === 'regular') {
                    this.noteContentInput.value = result.content;
                    this.noteTitleInput.value = result.filename.replace('.txt', '');
                    this.onContentChange();
                    this.showSection('notebook');
                    this.showToast(`File "${result.filename}" loaded successfully!`, 'success');
                } else if (type === 'encrypt') {
                    this.noteContentInput.value = result.content;
                    this.noteTitleInput.value = result.filename.replace('.txt', '');
                    this.onContentChange();
                    this.showSection('encryption');
                    this.showToast(`File "${result.filename}" loaded for encryption!`, 'success');
                } else if (type === 'decrypt') {
                    this.manualEncryptedData.value = result.content;
                    this.showToast(`Encrypted file "${result.filename}" loaded!`, 'success');
                }
            } else {
                this.showToast(result.error || 'Error uploading file', 'error');
            }
        } catch (error) {
            console.error('Error:', error);
            this.showToast('Network error. Please try again.', 'error');
        } finally {
            this.hideLoading();
        }
    }

    // Notebook Methods
    newNote() {
        this.noteTitleInput.value = '';
        this.noteContentInput.value = '';
        this.noteTitle = '';
        this.noteContent = '';
        this.undoStack = [];
        this.redoStack = [];
        this.updateStats();
        this.updateLineNumbers();
        this.noteTitleInput.focus();
        this.showToast('New note created', 'success');
    }

    saveNote() {
        const title = this.noteTitleInput.value.trim() || 'Untitled Note';
        const content = this.noteContentInput.value;
        
        if (!content.trim()) {
            this.showToast('Please write some content before saving', 'error');
            return;
        }

        const blob = new Blob([`# ${title}\n\n${content}`], { type: 'text/plain' });
        this.downloadBlob(blob, `${title}.txt`);
        this.showToast('Note saved successfully!', 'success');
    }

    async downloadNote(type) {
        const title = this.noteTitleInput.value.trim() || 'Untitled Note';
        const content = this.noteContentInput.value;

        if (!content.trim()) {
            this.showToast('Please write some content before downloading', 'error');
            return;
        }

        this.showLoading();

        try {
            const response = await fetch('/download-note', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    title: title,
                    content: content,
                    type: type
                })
            });

            if (response.ok) {
                const blob = await response.blob();
                const filename = `${title}.${type}`;
                this.downloadBlob(blob, filename);
                this.showToast(`${type.toUpperCase()} downloaded successfully!`, 'success');
            } else {
                const error = await response.json();
                this.showToast(error.error || 'Download failed', 'error');
            }
        } catch (error) {
            console.error('Error:', error);
            this.showToast('Network error. Please try again.', 'error');
        } finally {
            this.hideLoading();
        }
    }

    downloadBlob(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    boldSelectedText() {
        const textarea = this.noteContentInput;
        const start = textarea.selectionStart;
        const end = textarea.selectionEnd;
        const selectedText = textarea.value.substring(start, end);

        if (selectedText) {
            const boldText = `**${selectedText}**`;
            const newValue = textarea.value.substring(0, start) + boldText + textarea.value.substring(end);
            
            this.saveEditorState();
            textarea.value = newValue;
            textarea.setSelectionRange(start + 2, start + 2 + selectedText.length);
            this.onContentChange();
            this.showToast('Text formatted as bold', 'success');
        } else {
            this.showToast('Please select text to make bold', 'warning');
        }
    }

    saveEditorState() {
        if (this.undoStack.length >= this.maxUndoSteps) {
            this.undoStack.shift();
        }
        
        this.undoStack.push({
            content: this.noteContentInput.value,
            selectionStart: this.noteContentInput.selectionStart,
            selectionEnd: this.noteContentInput.selectionEnd
        });
        
        this.redoStack = [];
    }

    undoEdit() {
        if (this.undoStack.length > 1) {
            const currentState = this.undoStack.pop();
            this.redoStack.push(currentState);
            
            const previousState = this.undoStack[this.undoStack.length - 1];
            this.noteContentInput.value = previousState.content;
            this.noteContentInput.setSelectionRange(previousState.selectionStart, previousState.selectionEnd);
            
            this.onContentChange();
            this.showToast('Undo successful', 'info');
        } else {
            this.showToast('Nothing to undo', 'warning');
        }
    }

    redoEdit() {
        if (this.redoStack.length > 0) {
            const redoState = this.redoStack.pop();
            this.undoStack.push(redoState);
            
            this.noteContentInput.value = redoState.content;
            this.noteContentInput.setSelectionRange(redoState.selectionStart, redoState.selectionEnd);
            
            this.onContentChange();
            this.showToast('Redo successful', 'info');
        } else {
            this.showToast('Nothing to redo', 'warning');
        }
    }

    toggleSyntaxHighlighting() {
        this.syntaxHighlightEnabled = !this.syntaxHighlightEnabled;
        
        if (this.syntaxHighlightEnabled) {
            this.noteContentInput.classList.add('syntax-mode');
            this.lineNumbers.style.display = 'block';
            this.toggleSyntaxBtn.style.background = 'var(--primary-color)';
            this.showToast('Syntax highlighting enabled', 'success');
        } else {
            this.noteContentInput.classList.remove('syntax-mode');
            this.lineNumbers.style.display = 'none';
            this.toggleSyntaxBtn.style.background = 'transparent';
            this.showToast('Syntax highlighting disabled', 'info');
        }
        
        this.updateLineNumbers();
    }

    updateLineNumbers() {
        if (!this.syntaxHighlightEnabled) return;
        
        const lines = this.noteContentInput.value.split('\n').length;
        let lineNumbersText = '';
        
        for (let i = 1; i <= lines; i++) {
            lineNumbersText += i + '\n';
        }
        
        this.lineNumbers.textContent = lineNumbersText;
    }

    syncLineNumbers() {
        if (this.syntaxHighlightEnabled) {
            this.lineNumbers.scrollTop = this.noteContentInput.scrollTop;
        }
    }

    onContentChange() {
        this.updateStats();
        this.updateLineNumbers();
        
        // Auto-save editor state for undo/redo
        clearTimeout(this.contentChangeTimeout);
        this.contentChangeTimeout = setTimeout(() => {
            this.saveEditorState();
        }, 1000);
    }

    updateTitle() {
        this.noteTitle = this.noteTitleInput.value;
    }

    updateStats() {
        const content = this.noteContentInput.value;
        const words = content.trim() ? content.trim().split(/\s+/).length : 0;
        const chars = content.length;
        
        this.wordCount.textContent = `Words: ${words}`;
        this.charCount.textContent = `Characters: ${chars}`;
        this.noteContent = content;
    }

    changeFontSize(size) {
        this.noteContentInput.style.fontSize = `${size}px`;
        this.fontSizeValue.textContent = `${size}px`;
    }

    // Encryption Methods
    showEncryptionModal(mode) {
        this.encryptionMode = mode;
        
        if (mode === 'encrypt') {
            this.modalTitle.textContent = 'Encrypt Note';
            
            if (!this.noteContentInput.value.trim()) {
                this.showToast('Please write some content to encrypt', 'error');
                return;
            }
        } else if (mode === 'decrypt') {
            this.modalTitle.textContent = 'Decrypt Note';
            
            const encryptedContent = this.manualEncryptedData.value.trim();
            if (!encryptedContent) {
                this.showToast('No encrypted data found to decrypt', 'error');
                return;
            }
        }
        
        this.encryptionModal.style.display = 'flex';
        this.encryptionPassword.value = '';
        this.passwordStrengthMini.style.display = 'none';
        this.encryptionPassword.focus();
    }

    hideEncryptionModal() {
        this.encryptionModal.style.display = 'none';
        this.encryptionPassword.value = '';
        this.passwordStrengthMini.style.display = 'none';
    }

    toggleEncryptionPasswordVisibility() {
        const type = this.encryptionPassword.type === 'password' ? 'text' : 'password';
        this.encryptionPassword.type = type;
        const icon = this.toggleEncryptionPassword.querySelector('i');
        icon.className = type === 'password' ? 'fas fa-eye' : 'fas fa-eye-slash';
    }

    checkModalPasswordStrength() {
        const password = this.encryptionPassword.value;
        if (password.length > 0) {
            this.passwordStrengthMini.style.display = 'flex';
            
            // Simple strength calculation for modal
            let strength = 0;
            if (password.length >= 8) strength += 25;
            if (/[A-Z]/.test(password)) strength += 25;
            if (/[a-z]/.test(password)) strength += 25;
            if (/[0-9]/.test(password) && /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)) strength += 25;
            
            this.strengthFillMini.style.width = `${strength}%`;
            
            if (strength < 50) {
                this.strengthTextMini.textContent = 'Weak';
                this.strengthTextMini.style.color = 'var(--error-color)';
            } else if (strength < 75) {
                this.strengthTextMini.textContent = 'Medium';
                this.strengthTextMini.style.color = 'var(--warning-color)';
            } else {
                this.strengthTextMini.textContent = 'Strong';
                this.strengthTextMini.style.color = 'var(--success-color)';
            }
        } else {
            this.passwordStrengthMini.style.display = 'none';
        }
    }

    async handleEncryptionConfirm() {
        const password = this.encryptionPassword.value.trim();
        
        if (!password) {
            this.showToast('Please enter a password', 'error');
            return;
        }

        if (password.length < 8) {
            this.showToast('Password must be at least 8 characters long', 'error');
            return;
        }

        this.hideEncryptionModal();
        this.showLoading();

        try {
            if (this.encryptionMode === 'encrypt') {
                await this.encryptNote(password);
            } else if (this.encryptionMode === 'decrypt') {
                await this.decryptNote(password);
            }
        } catch (error) {
            console.error('Error:', error);
            this.showToast('Encryption/Decryption failed', 'error');
        } finally {
            this.hideLoading();
        }
    }

    async encryptNote(password) {
        const content = this.noteContentInput.value;
        
        try {
            const response = await fetch('/encrypt-text', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    text: content,
                    password: password
                })
            });

            const result = await response.json();
            
            if (result.success) {
                this.encryptedData.value = result.encrypted_data;
                this.encryptedDataContainer.style.display = 'block';
                this.showToast('Note encrypted successfully!', 'success');
            } else {
                this.showToast(result.error || 'Encryption failed', 'error');
            }
        } catch (error) {
            console.error('Error:', error);
            this.showToast('Network error during encryption', 'error');
        }
    }

    async decryptNote(password) {
        const encryptedData = this.manualEncryptedData.value;
        
        try {
            const response = await fetch('/decrypt-text', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    encrypted_data: encryptedData,
                    password: password
                })
            });

            const result = await response.json();
            
            if (result.success) {
                this.decryptedData.value = result.decrypted_text;
                this.decryptedDataContainer.style.display = 'block';
                this.showToast('Note decrypted successfully!', 'success');
            } else {
                this.showToast(result.error || 'Decryption failed', 'error');
            }
        } catch (error) {
            console.error('Error:', error);
            this.showToast('Network error during decryption', 'error');
        }
    }

    decryptManualData() {
        const encryptedContent = this.manualEncryptedData.value.trim();
        if (!encryptedContent) {
            this.showToast('Please enter encrypted data to decrypt', 'error');
            return;
        }
        
        this.showEncryptionModal('decrypt');
    }

    downloadEncryptedFile() {
        const encryptedContent = this.encryptedData.value;
        
        if (!encryptedContent.trim()) {
            this.showToast('No encrypted data to download', 'error');
            return;
        }

        const title = this.noteTitleInput.value.trim() || 'Encrypted Note';
        const blob = new Blob([encryptedContent], { type: 'text/plain' });
        this.downloadBlob(blob, `${title}.encrypted`);
        this.showToast('Encrypted file downloaded!', 'success');
    }

    downloadDecryptedFile() {
        const decryptedContent = this.decryptedData.value;
        
        if (!decryptedContent.trim()) {
            this.showToast('No decrypted data to download', 'error');
            return;
        }

        const title = this.noteTitleInput.value.trim() || 'Decrypted Note';
        const blob = new Blob([decryptedContent], { type: 'text/plain' });
        this.downloadBlob(blob, `${title}.txt`);
        this.showToast('Decrypted file downloaded!', 'success');
    }

    loadDecryptedToEditor() {
        const decryptedContent = this.decryptedData.value;
        
        if (!decryptedContent.trim()) {
            this.showToast('No decrypted data to load', 'error');
            return;
        }

        this.noteContentInput.value = decryptedContent;
        this.onContentChange();
        this.showSection('notebook');
        this.showToast('Decrypted content loaded to editor!', 'success');
    }

    async copyToClipboard(text, successMessage) {
        try {
            await navigator.clipboard.writeText(text);
            this.showToast(successMessage, 'success');
        } catch (error) {
            console.error('Error copying to clipboard:', error);
            this.showToast('Failed to copy to clipboard', 'error');
        }
    }

    // UI Methods
    toggleTheme() {
        this.currentTheme = this.currentTheme === 'dark' ? 'light' : 'dark';
        document.body.setAttribute('data-theme', this.currentTheme);
        
        const icon = this.themeToggle.querySelector('i');
        icon.className = this.currentTheme === 'light' ? 'fas fa-sun' : 'fas fa-moon';
        
        localStorage.setItem('theme', this.currentTheme);
        this.showToast(`Switched to ${this.currentTheme} theme`, 'info');
    }

    loadTheme() {
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme) {
            this.currentTheme = savedTheme;
            document.body.setAttribute('data-theme', this.currentTheme);
            const icon = this.themeToggle.querySelector('i');
            icon.className = this.currentTheme === 'light' ? 'fas fa-sun' : 'fas fa-moon';
        }
    }

    showLoading() {
        this.loadingSpinner.style.display = 'flex';
    }

    hideLoading() {
        this.loadingSpinner.style.display = 'none';
    }

    showToast(message, type = 'info') {
        this.toastMessage.textContent = message;
        this.toast.className = `toast ${type}`;
        
        // Set appropriate icon
        const iconClass = {
            'success': 'fas fa-check-circle',
            'error': 'fas fa-exclamation-circle',
            'warning': 'fas fa-exclamation-triangle',
            'info': 'fas fa-info-circle'
        };
        
        this.toastIcon.className = iconClass[type] || iconClass['info'];
        this.toast.classList.add('show');
        
        setTimeout(() => {
            this.hideToast();
        }, 4000);
    }

    hideToast() {
        this.toast.classList.remove('show');
    }

    handleKeyboard(event) {
        // Ctrl/Cmd + S to save
        if ((event.ctrlKey || event.metaKey) && event.key === 's') {
            event.preventDefault();
            this.saveNote();
        }

        // Ctrl/Cmd + N for new note
        if ((event.ctrlKey || event.metaKey) && event.key === 'n') {
            event.preventDefault();
            this.newNote();
        }

        // Ctrl + Z for undo
        if (event.ctrlKey && event.key === 'z' && !event.shiftKey) {
            if (document.activeElement === this.noteContentInput) {
                event.preventDefault();
                this.undoEdit();
            }
        }

        // Ctrl + Y or Ctrl + Shift + Z for redo
        if ((event.ctrlKey && event.key === 'y') || (event.ctrlKey && event.shiftKey && event.key === 'z')) {
            if (document.activeElement === this.noteContentInput) {
                event.preventDefault();
                this.redoEdit();
            }
        }

        // Ctrl + B for bold
        if (event.ctrlKey && event.key === 'b') {
            if (document.activeElement === this.noteContentInput) {
                event.preventDefault();
                this.boldSelectedText();
            }
        }

        // Escape to close modal or clear password
        if (event.key === 'Escape') {
            if (this.encryptionModal.style.display === 'flex') {
                this.hideEncryptionModal();
            } else if (document.activeElement === this.passwordInput) {
                this.clearPassword();
            }
        }

        // Enter in encryption modal
        if (event.key === 'Enter' && this.encryptionModal.style.display === 'flex') {
            this.handleEncryptionConfirm();
        }

        // Number keys for quick navigation
        if (event.altKey && event.key >= '1' && event.key <= '5') {
            event.preventDefault();
            const sections = ['password', 'file-upload', 'notebook', 'encryption', 'decryption'];
            const index = parseInt(event.key) - 1;
            if (sections[index]) {
                this.showSection(sections[index]);
            }
        }
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    new SecureNotebook();
});
