// Main JavaScript for SLRD Project Management System

document.addEventListener('DOMContentLoaded', function() {
    // Initialize all components
    initializeSidebar();
    initializeAlerts();
    initializeProgressBars();
    initializeTooltips();
    initializeFileUploads();
    initializeSearchFunctionality();
    initializeDateInputs();
    initializeFormValidation();
});

// Sidebar functionality
function initializeSidebar() {
    const sidebar = document.querySelector('.sidebar');
    const mainContent = document.querySelector('.main-content');
    
    // Mobile sidebar toggle
    const toggleButton = document.querySelector('[data-sidebar-toggle]');
    if (toggleButton) {
        toggleButton.addEventListener('click', function() {
            sidebar.classList.toggle('show');
        });
    }
    
    // Close sidebar when clicking outside on mobile
    document.addEventListener('click', function(e) {
        if (window.innerWidth <= 768 && 
            !sidebar.contains(e.target) && 
            !e.target.closest('[data-sidebar-toggle]')) {
            sidebar.classList.remove('show');
        }
    });
    
    // Highlight active navigation item
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.sidebar-nav .nav-link');
    
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
}

// Alert auto-dismiss
function initializeAlerts() {
    const alerts = document.querySelectorAll('.alert');
    
    alerts.forEach(alert => {
        // Auto-dismiss success alerts after 5 seconds
        if (alert.classList.contains('alert-success')) {
            setTimeout(() => {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }, 5000);
        }
    });
}

// Animated progress bars
function initializeProgressBars() {
    const progressBars = document.querySelectorAll('.progress-bar');
    
    // Animate progress bars when they come into view
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const progressBar = entry.target;
                const width = progressBar.style.width;
                progressBar.style.width = '0%';
                setTimeout(() => {
                    progressBar.style.width = width;
                }, 100);
            }
        });
    });
    
    progressBars.forEach(bar => {
        observer.observe(bar);
    });
}

// Initialize tooltips
function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// File upload enhancements
function initializeFileUploads() {
    const fileInputs = document.querySelectorAll('input[type="file"]');
    
    fileInputs.forEach(input => {
        // Create custom file input styling
        const wrapper = document.createElement('div');
        wrapper.className = 'file-input-wrapper';
        
        const label = document.createElement('label');
        label.className = 'file-input-label';
        label.htmlFor = input.id;
        label.innerHTML = '<i class="fas fa-cloud-upload-alt"></i> Choose File';
        
        const fileName = document.createElement('span');
        fileName.className = 'file-name';
        fileName.textContent = 'No file chosen';
        
        input.parentNode.insertBefore(wrapper, input);
        wrapper.appendChild(input);
        wrapper.appendChild(label);
        wrapper.appendChild(fileName);
        
        // Update file name display
        input.addEventListener('change', function() {
            if (this.files && this.files.length > 0) {
                fileName.textContent = this.files[0].name;
                wrapper.classList.add('has-file');
            } else {
                fileName.textContent = 'No file chosen';
                wrapper.classList.remove('has-file');
            }
        });
        
        // Drag and drop functionality
        wrapper.addEventListener('dragover', function(e) {
            e.preventDefault();
            wrapper.classList.add('drag-over');
        });
        
        wrapper.addEventListener('dragleave', function() {
            wrapper.classList.remove('drag-over');
        });
        
        wrapper.addEventListener('drop', function(e) {
            e.preventDefault();
            wrapper.classList.remove('drag-over');
            
            if (e.dataTransfer.files.length > 0) {
                input.files = e.dataTransfer.files;
                fileName.textContent = e.dataTransfer.files[0].name;
                wrapper.classList.add('has-file');
            }
        });
    });
}

// Search functionality
function initializeSearchFunctionality() {
    const searchInput = document.querySelector('.search-box input');
    if (!searchInput) return;
    
    let searchTimeout;
    
    searchInput.addEventListener('input', function() {
        clearTimeout(searchTimeout);
        const query = this.value.toLowerCase().trim();
        
        if (query.length === 0) {
            // Reset all items
            document.querySelectorAll('.project-card, .task-card, .team-member-card')
                .forEach(item => item.style.display = '');
            return;
        }
        
        searchTimeout = setTimeout(() => {
            performSearch(query);
        }, 300);
    });
    
    function performSearch(query) {
        const searchableItems = document.querySelectorAll('.project-card, .task-card, .team-member-card');
        
        searchableItems.forEach(item => {
            const text = item.textContent.toLowerCase();
            if (text.includes(query)) {
                item.style.display = '';
            } else {
                item.style.display = 'none';
            }
        });
    }
}

// Date input enhancements
function initializeDateInputs() {
    const dateInputs = document.querySelectorAll('input[type="date"]');
    
    dateInputs.forEach(input => {
        // Set minimum date to today for deadlines
        if (input.name === 'deadline') {
            const today = new Date().toISOString().split('T')[0];
            input.min = today;
        }
        
        // Add date validation
        input.addEventListener('change', function() {
            const selectedDate = new Date(this.value);
            const today = new Date();
            today.setHours(0, 0, 0, 0);
            
            if (selectedDate < today && this.name === 'deadline') {
                this.setCustomValidity('Deadline cannot be in the past');
                this.classList.add('is-invalid');
            } else {
                this.setCustomValidity('');
                this.classList.remove('is-invalid');
            }
        });
    });
}

// Form validation enhancements
function initializeFormValidation() {
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            if (!form.checkValidity()) {
                e.preventDefault();
                e.stopPropagation();
                
                // Focus on first invalid field
                const firstInvalid = form.querySelector(':invalid');
                if (firstInvalid) {
                    firstInvalid.focus();
                }
            }
            
            form.classList.add('was-validated');
        });
        
        // Real-time validation
        const inputs = form.querySelectorAll('input, textarea, select');
        inputs.forEach(input => {
            input.addEventListener('blur', function() {
                if (this.checkValidity()) {
                    this.classList.remove('is-invalid');
                    this.classList.add('is-valid');
                } else {
                    this.classList.remove('is-valid');
                    this.classList.add('is-invalid');
                }
            });
        });
    });
}

// Utility functions
const Utils = {
    // Debounce function for performance
    debounce: function(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },
    
    // Format file size
    formatFileSize: function(bytes) {
        if (bytes === 0) return '0 Bytes';
        
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    },
    
    // Show loading state
    showLoading: function(element, text = 'Loading...') {
        element.innerHTML = `<i class="fas fa-spinner fa-spin"></i> ${text}`;
        element.disabled = true;
    },
    
    // Hide loading state
    hideLoading: function(element, originalText) {
        element.innerHTML = originalText;
        element.disabled = false;
    },
    
    // Show notification
    showNotification: function(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} alert-dismissible fade show notification`;
        notification.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        // Add to page
        const container = document.querySelector('.content-area') || document.body;
        container.insertBefore(notification, container.firstChild);
        
        // Auto-dismiss
        setTimeout(() => {
            const alert = new bootstrap.Alert(notification);
            alert.close();
        }, 5000);
    }
};

// Task filtering functionality
function filterTasks(filter) {
    const tasks = document.querySelectorAll('.task-card');
    const buttons = document.querySelectorAll('.task-filters .btn');
    
    // Update active button
    buttons.forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    
    tasks.forEach(task => {
        const status = task.dataset.status;
        const isOverdue = task.dataset.overdue === 'true';
        
        let show = false;
        
        switch(filter) {
            case 'all':
                show = true;
                break;
            case 'in-progress':
                show = status === 'in-progress';
                break;
            case 'pending':
                show = status === 'pending';
                break;
            case 'completed':
                show = status === 'completed';
                break;
            case 'overdue':
                show = isOverdue;
                break;
        }
        
        if (show) {
            task.style.display = 'block';
            task.style.animation = 'fadeIn 0.3s ease';
        } else {
            task.style.display = 'none';
        }
    });
}

// Permission management functions
function selectAllPermissions() {
    const checkboxes = document.querySelectorAll('.permissions-matrix input[type="checkbox"]:not([disabled])');
    checkboxes.forEach(checkbox => {
        checkbox.checked = true;
    });
    
    Utils.showNotification('All permissions selected', 'success');
}

function clearAllPermissions() {
    const checkboxes = document.querySelectorAll('.permissions-matrix input[type="checkbox"]:not([disabled])');
    checkboxes.forEach(checkbox => {
        checkbox.checked = false;
    });
    
    Utils.showNotification('All permissions cleared', 'info');
}

// Real-time updates for progress
function updateProgress() {
    fetch('/api/progress-update')
        .then(response => response.json())
        .then(data => {
            // Update progress bars and statistics
            document.querySelectorAll('[data-project-id]').forEach(element => {
                const projectId = element.dataset.projectId;
                if (data.projects[projectId]) {
                    const progress = data.projects[projectId].progress;
                    const progressBar = element.querySelector('.progress-bar');
                    if (progressBar) {
                        progressBar.style.width = progress + '%';
                    }
                }
            });
        })
        .catch(error => console.error('Error updating progress:', error));
}

// Auto-save functionality for forms
function initializeAutoSave() {
    const forms = document.querySelectorAll('[data-autosave]');
    
    forms.forEach(form => {
        const inputs = form.querySelectorAll('input, textarea, select');
        
        inputs.forEach(input => {
            input.addEventListener('input', Utils.debounce(() => {
                saveFormData(form);
            }, 2000));
        });
    });
}

function saveFormData(form) {
    const formData = new FormData(form);
    const data = Object.fromEntries(formData);
    
    // Save to localStorage
    localStorage.setItem(`form_${form.id}`, JSON.stringify(data));
    
    // Show save indicator
    const saveIndicator = document.createElement('span');
    saveIndicator.className = 'save-indicator';
    saveIndicator.innerHTML = '<i class="fas fa-check"></i> Saved';
    
    form.appendChild(saveIndicator);
    setTimeout(() => saveIndicator.remove(), 2000);
}

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl/Cmd + K for search
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        const searchInput = document.querySelector('.search-box input');
        if (searchInput) {
            searchInput.focus();
        }
    }
    
    // Escape to close modals/dropdowns
    if (e.key === 'Escape') {
        const openDropdowns = document.querySelectorAll('.dropdown-menu.show');
        openDropdowns.forEach(dropdown => {
            const toggle = dropdown.previousElementSibling;
            if (toggle) {
                bootstrap.Dropdown.getOrCreateInstance(toggle).hide();
            }
        });
    }
});

// Performance monitoring
function monitorPerformance() {
    // Monitor page load time
    window.addEventListener('load', function() {
        const loadTime = performance.timing.loadEventEnd - performance.timing.navigationStart;
        console.log(`Page loaded in ${loadTime}ms`);
        
        // Track slow pages
        if (loadTime > 3000) {
            console.warn('Page load time is slow:', loadTime + 'ms');
        }
    });
    
    // Monitor memory usage
    if ('memory' in performance) {
        setInterval(() => {
            const memory = performance.memory;
            if (memory.usedJSHeapSize > 50 * 1024 * 1024) { // 50MB
                console.warn('High memory usage detected:', memory.usedJSHeapSize);
            }
        }, 30000);
    }
}

// Initialize performance monitoring in development
if (window.location.hostname === 'localhost') {
    monitorPerformance();
}

// Export utils for global access
window.ProjectManagement = {
    Utils,
    filterTasks,
    selectAllPermissions,
    clearAllPermissions,
    updateProgress
};

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    @keyframes slideIn {
        from { transform: translateX(-100%); }
        to { transform: translateX(0); }
    }
    
    .notification {
        animation: slideIn 0.3s ease;
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 9999;
        max-width: 400px;
    }
    
    .file-input-wrapper {
        position: relative;
        border: 2px dashed #e2e8f0;
        border-radius: 8px;
        padding: 20px;
        text-align: center;
        transition: all 0.3s ease;
    }
    
    .file-input-wrapper.drag-over {
        border-color: #4a90b8;
        background-color: #f0f8ff;
    }
    
    .file-input-wrapper.has-file {
        border-color: #3db570;
        background-color: #f0fff4;
    }
    
    .file-input-wrapper input[type="file"] {
        position: absolute;
        opacity: 0;
        width: 100%;
        height: 100%;
        cursor: pointer;
    }
    
    .file-input-label {
        display: block;
        color: #4a90b8;
        font-weight: 500;
        cursor: pointer;
        margin-bottom: 8px;
    }
    
    .file-name {
        display: block;
        color: #64748b;
        font-size: 0.9rem;
    }
    
    .save-indicator {
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: #3db570;
        color: white;
        padding: 8px 16px;
        border-radius: 4px;
        font-size: 0.9rem;
        animation: slideIn 0.3s ease;
    }
`;
document.head.appendChild(style);
