// Real-time scan progress updates
function startScan() {
    fetch('/start_scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'scan_started') {
            updateScanProgress();
        }
    })
    .catch(error => {
        console.error('Error starting scan:', error);
    });
}

function updateScanProgress() {
    const progressInterval = setInterval(() => {
        fetch('/scan_status')
            .then(response => response.json())
            .then(data => {
                // Update progress bar
                const progressFill = document.getElementById('progress-fill');
                const progressText = document.getElementById('progress-text');
                
                if (progressFill && progressText) {
                    progressFill.style.width = data.progress + '%';
                    progressText.textContent = data.progress + '%';
                }

                // Update current task
                const currentTask = document.getElementById('current-task');
                if (currentTask) {
                    currentTask.textContent = data.current_task;
                }

                // Update current URL
                const currentUrl = document.getElementById('current-url');
                if (currentUrl && data.current_url) {
                    currentUrl.textContent = data.current_url;
                }

                // Update vulnerability count
                const vulnCount = document.getElementById('vuln-count');
                if (vulnCount) {
                    vulnCount.textContent = data.vulnerabilities_found;
                }

                // Update terminal
                const terminal = document.getElementById('scan-terminal');
                if (terminal && data.log_messages) {
                    // Only add new messages
                    const currentMessages = Array.from(terminal.children).map(el => el.textContent);
                    data.log_messages.forEach(message => {
                        if (!currentMessages.includes(message)) {
                            const newLine = document.createElement('div');
                            newLine.className = 'terminal-line';
                            newLine.textContent = message;
                            terminal.appendChild(newLine);
                            terminal.scrollTop = terminal.scrollHeight;
                        }
                    });
                }

                // Redirect when scan completes
                if (!data.active && data.progress === 100) {
                    clearInterval(progressInterval);
                    setTimeout(() => {
                        window.location.href = '/results';
                    }, 2000);
                }
            })
            .catch(error => {
                console.error('Error fetching scan status:', error);
            });
    }, 1000);
}

// Chart initialization for dashboard
function initializeCharts() {
    // Vulnerability distribution chart
    const vulnCtx = document.getElementById('vulnChart');
    if (vulnCtx) {
        new Chart(vulnCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [12, 19, 8, 15],
                    backgroundColor: ['#e74c3c', '#e67e22', '#f39c12', '#3498db']
                }]
            }
        });
    }
}

// PDF export with animation
function exportPDF() {
    const btn = event.target;
    const originalText = btn.innerHTML;
    
    btn.innerHTML = '⏳ Generating PDF...';
    btn.disabled = true;
    
    setTimeout(() => {
        window.location.href = '/export_pdf';
        btn.innerHTML = originalText;
        btn.disabled = false;
    }, 2000);
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    
    // Add floating animation to cards
    const cards = document.querySelectorAll('.stat-card, .action-card');
    cards.forEach((card, index) => {
        card.style.animationDelay = (index * 0.1) + 's';
    });
});