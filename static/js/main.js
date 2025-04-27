/**
 * Web Server Security Scanner - Main JavaScript
 * 
 * This file contains client-side functionality for the security scanner application.
 */

// Handle form validation
document.addEventListener('DOMContentLoaded', function() {
    const targetInput = document.getElementById('target');
    
    // If the input exists (we're on the scan form page)
    if (targetInput) {
        targetInput.addEventListener('input', function() {
            validateTarget(this);
        });
    }
    
    // Initialize tooltips if Bootstrap is loaded
    if (typeof bootstrap !== 'undefined' && bootstrap.Tooltip) {
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }
});

/**
 * Validate the target input
 * @param {HTMLInputElement} inputElement - The input element to validate
 */
function validateTarget(inputElement) {
    const value = inputElement.value.trim();
    
    // Simple validation for domain or IP
    const domainRegex = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    
    if (value === '') {
        inputElement.setCustomValidity('');
        return;
    }
    
    if (!domainRegex.test(value) && !ipRegex.test(value)) {
        inputElement.setCustomValidity('Please enter a valid domain name, URL, or IP address');
    } else {
        inputElement.setCustomValidity('');
    }
}

/**
 * Update progress bar during scan
 * @param {number} progress - Progress percentage (0-100)
 * @param {string} status - Status message
 */
function updateProgress(progress, status) {
    const progressBar = document.getElementById('scanProgressBar');
    const statusElement = document.getElementById('scanStatus');
    
    if (progressBar && statusElement) {
        progressBar.style.width = progress + '%';
        progressBar.setAttribute('aria-valuenow', progress);
        statusElement.textContent = status;
    }
}

/**
 * Format timestamp for better readability
 * @param {string} timestamp - ISO timestamp string
 * @returns {string} Formatted date/time
 */
function formatTimestamp(timestamp) {
    if (!timestamp) return '';
    
    const date = new Date(timestamp);
    return date.toLocaleString();
}

/**
 * Toggle visibility of advanced options
 */
function toggleAdvancedOptions() {
    const advancedOptions = document.getElementById('advancedOptions');
    
    if (advancedOptions) {
        advancedOptions.classList.toggle('d-none');
    }
}
