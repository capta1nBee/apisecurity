/**
 * API Security Dashboard - Main JavaScript
 */

// Global configuration
const API_BASE_URL = '';

// Utility functions
function formatNumber(num) {
    if (num >= 1000000) {
        return (num / 1000000).toFixed(1) + 'M';
    } else if (num >= 1000) {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
}

function showNotification(message, type = 'info') {
    // Simple notification system
    const alertClass = `alert-${type}`;
    const alert = $(`
        <div class="alert ${alertClass} alert-dismissible fade show position-fixed top-0 end-0 m-3" role="alert" style="z-index: 9999;">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `);
    
    $('body').append(alert);
    
    setTimeout(() => {
        alert.alert('close');
    }, 5000);
}

function showError(message) {
    showNotification(message, 'danger');
}

function showSuccess(message) {
    showNotification(message, 'success');
}

// API call wrapper
async function apiCall(endpoint, options = {}) {
    try {
        const response = await fetch(API_BASE_URL + endpoint, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'API call failed');
        }
        
        return data;
    } catch (error) {
        console.error('API Error:', error);
        showError(error.message);
        throw error;
    }
}

// Export functions
function exportToCSV(data, filename) {
    const csv = convertToCSV(data);
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    window.URL.revokeObjectURL(url);
}

function convertToCSV(data) {
    if (!data || data.length === 0) return '';
    
    const headers = Object.keys(data[0]);
    const rows = data.map(row => 
        headers.map(header => JSON.stringify(row[header] || '')).join(',')
    );
    
    return [headers.join(','), ...rows].join('\n');
}

function exportToJSON(data, filename) {
    const json = JSON.stringify(data, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    window.URL.revokeObjectURL(url);
}

// Chart helpers
function createLineChart(ctx, labels, datasets, options = {}) {
    return new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: datasets
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'top'
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            },
            ...options
        }
    });
}

function createBarChart(ctx, labels, data, options = {}) {
    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: options.label || 'Value',
                data: data,
                backgroundColor: options.backgroundColor || '#007bff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            ...options
        }
    });
}

function createDoughnutChart(ctx, labels, data, options = {}) {
    return new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: options.backgroundColor || [
                    '#007bff', '#28a745', '#ffc107', '#dc3545', '#17a2b8'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            ...options
        }
    });
}

// Date range presets
function setDateRangePreset(preset) {
    const endDate = new Date();
    const startDate = new Date();
    
    switch(preset) {
        case 'today':
            // Today
            break;
        case 'yesterday':
            startDate.setDate(startDate.getDate() - 1);
            endDate.setDate(endDate.getDate() - 1);
            break;
        case 'last7days':
            startDate.setDate(startDate.getDate() - 7);
            break;
        case 'last30days':
            startDate.setDate(startDate.getDate() - 30);
            break;
        case 'thisMonth':
            startDate.setDate(1);
            break;
        case 'lastMonth':
            startDate.setMonth(startDate.getMonth() - 1);
            startDate.setDate(1);
            endDate.setDate(0);
            break;
    }
    
    $('#startDate').val(startDate.toISOString().split('T')[0]);
    $('#endDate').val(endDate.toISOString().split('T')[0]);
}

// Loading state management
function showLoading(element) {
    $(element).html(`
        <div class="text-center p-5">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <p class="mt-2">Loading data...</p>
        </div>
    `);
}

function hideLoading(element) {
    $(element).find('.spinner-border').parent().remove();
}

// Table helpers
function createDataTable(tableId, options = {}) {
    return $(tableId).DataTable({
        responsive: true,
        pageLength: 20,
        order: [[0, 'asc']],
        ...options
    });
}

// Security score helpers
function getScoreColor(score) {
    if (score >= 90) return '#28a745'; // Green
    if (score >= 75) return '#17a2b8'; // Blue
    if (score >= 60) return '#ffc107'; // Yellow
    if (score >= 40) return '#fd7e14'; // Orange
    return '#dc3545'; // Red
}

function getScoreLevel(score) {
    if (score >= 90) return 'Excellent';
    if (score >= 75) return 'Good';
    if (score >= 60) return 'Fair';
    if (score >= 40) return 'Poor';
    return 'Critical';
}

function createScoreBadge(score) {
    const level = getScoreLevel(score);
    const color = getScoreColor(score);
    return `<span class="badge" style="background-color: ${color}">${level} (${score.toFixed(1)})</span>`;
}

// Recommendation helpers
function getSeverityClass(severity) {
    const classes = {
        'critical': 'danger',
        'high': 'warning',
        'medium': 'info',
        'low': 'success'
    };
    return classes[severity] || 'secondary';
}

function getSeverityIcon(severity) {
    const icons = {
        'critical': 'fa-exclamation-circle',
        'high': 'fa-exclamation-triangle',
        'medium': 'fa-info-circle',
        'low': 'fa-check-circle'
    };
    return icons[severity] || 'fa-circle';
}

// Initialize tooltips and popovers
$(document).ready(function() {
    // Initialize Bootstrap tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize Bootstrap popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
});

// Global error handler
window.addEventListener('error', function(e) {
    console.error('Global error:', e.error);
});

// Export global functions
window.apiCall = apiCall;
window.showNotification = showNotification;
window.showError = showError;
// Export Report Functions
async function exportReport(apiId, format) {
    try {
        // Get current date range and ES name from the page
        const startDate = document.getElementById('startDate')?.value ||
                         new Date(Date.now() - 7*24*60*60*1000).toISOString().split('T')[0];
        const endDate = document.getElementById('endDate')?.value ||
                       new Date().toISOString().split('T')[0];
        const esName = document.getElementById('esSelect')?.value || 'PROD-ES';

        // Show loading notification
        showNotification(`Generating ${format.toUpperCase()} report...`, 'info');

        // Build URL with query parameters
        const url = `${API_BASE_URL}/api/apis/${apiId}/export/${format}?start_date=${startDate}&end_date=${endDate}&es_name=${esName}`;

        // Download file
        const response = await fetch(url);

        if (!response.ok) {
            throw new Error('Failed to generate report');
        }

        // Get filename from Content-Disposition header or create default
        const contentDisposition = response.headers.get('Content-Disposition');
        let filename = `security_report_${apiId}_${new Date().getTime()}.${format === 'pdf' ? 'pdf' : 'xlsx'}`;

        if (contentDisposition) {
            const filenameMatch = contentDisposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
            if (filenameMatch && filenameMatch[1]) {
                filename = filenameMatch[1].replace(/['"]/g, '');
            }
        }

        // Create blob and download
        const blob = await response.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(downloadUrl);
        document.body.removeChild(a);

        showSuccess(`${format.toUpperCase()} report downloaded successfully!`);
    } catch (error) {
        console.error('Export error:', error);
        showError(`Failed to export report: ${error.message}`);
    }
}

// Share Report Function
async function shareReport(apiId) {
    try {
        // Get current date range and ES name
        const startDate = document.getElementById('startDate')?.value ||
                         new Date(Date.now() - 7*24*60*60*1000).toISOString().split('T')[0];
        const endDate = document.getElementById('endDate')?.value ||
                       new Date().toISOString().split('T')[0];
        const esName = document.getElementById('esSelect')?.value || 'PROD-ES';

        // Ask for email (optional)
        const email = prompt('Enter email address to send report (or leave empty to just get link):');

        // Call share API
        const response = await apiCall(`/api/apis/${apiId}/share`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                start_date: startDate,
                end_date: endDate,
                es_name: esName,
                email: email || null
            })
        });

        if (response.success) {
            const shareUrl = response.data.share_url;

            // Copy to clipboard
            if (navigator.clipboard) {
                await navigator.clipboard.writeText(shareUrl);
                showSuccess('Share link copied to clipboard!');
            }

            // Show modal with share link
            const modal = `
                <div class="modal fade" id="shareModal" tabindex="-1">
                    <div class="modal-dialog">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title">Share Report</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                            </div>
                            <div class="modal-body">
                                <p><strong>API:</strong> ${response.data.api_name}</p>
                                ${response.data.email_sent ? `<p class="text-success"><i class="fas fa-check-circle"></i> Report sent to ${response.data.email}</p>` : ''}
                                <div class="mb-3">
                                    <label class="form-label">Share Link:</label>
                                    <div class="input-group">
                                        <input type="text" class="form-control" value="${shareUrl}" id="shareUrlInput" readonly>
                                        <button class="btn btn-outline-secondary" onclick="copyShareLink()">
                                            <i class="fas fa-copy"></i> Copy
                                        </button>
                                    </div>
                                </div>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                            </div>
                        </div>
                    </div>
                </div>
            `;

            // Remove existing modal if any
            $('#shareModal').remove();

            // Add and show modal
            $('body').append(modal);
            const shareModalEl = new bootstrap.Modal(document.getElementById('shareModal'));
            shareModalEl.show();

            // Clean up modal after it's hidden
            document.getElementById('shareModal').addEventListener('hidden.bs.modal', function () {
                this.remove();
            });
        } else {
            showError('Failed to generate share link');
        }
    } catch (error) {
        console.error('Share error:', error);
        showError(`Failed to share report: ${error.message}`);
    }
}

function copyShareLink() {
    const input = document.getElementById('shareUrlInput');
    input.select();
    document.execCommand('copy');
    showSuccess('Link copied to clipboard!');
}

window.showSuccess = showSuccess;
window.formatNumber = formatNumber;
window.formatDate = formatDate;
window.exportToCSV = exportToCSV;
window.exportToJSON = exportToJSON;
window.getScoreColor = getScoreColor;
window.getScoreLevel = getScoreLevel;
window.createScoreBadge = createScoreBadge;
window.exportReport = exportReport;
window.shareReport = shareReport;
window.copyShareLink = copyShareLink;

