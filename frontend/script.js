// Hamburger menu toggle for mobile
document.getElementById('hamburger').addEventListener('click', () => {
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('open');
});

// File upload and segregated data display
document.getElementById('uploadBtn').addEventListener('click', () => {
    const button = document.getElementById('uploadBtn');
    setLoading(button, true);
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    if (!file) {
        alert('Please select a file.');
        setLoading(button, false);
        return;
    }
    
    const reader = new FileReader();
    reader.onload = async (e) => {
        const content = e.target.result;
        
        // Send to backend for processing
        const formData = new FormData();
        formData.append('file', file);
        try {
            const response = await fetch('http://localhost:5000/upload', {
                method: 'POST',
                body: formData
            });
            const data = await response.json();
            if (data.error) {
                alert(data.error);
            } else {
                // Store data for report generation
                window.uploadedData = data;
                
                // Display segregated data with animation
                const container = document.getElementById('segregatedDataContainer');
                const thead = document.getElementById('segregatedTableHead');
                const tbody = document.getElementById('segregatedTableBody');
                
                // Create header
                const columns = Object.keys(data.summary.segregated_data[0] || {});
                thead.innerHTML = '<tr>' + columns.map(col => `<th>${col}</th>`).join('') + '</tr>';
                
                // Create rows with staggered animation
                tbody.innerHTML = '';
                data.summary.segregated_data.forEach((row, i) => {
                    const tr = document.createElement('tr');
                    tr.style.animationDelay = `${i * 0.1}s`;
                    tr.innerHTML = columns.map(col => `<td>${row[col]}</td>`).join('');
                    tbody.appendChild(tr);
                });
                
                container.style.display = 'block';
                container.style.animation = 'fadeIn 0.5s ease-out';
                alert('File processed successfully. Segregated data displayed. Click "Generate Report" for graphs.');
            }
        } catch (error) {
            alert('Error uploading file.');
        } finally {
            setLoading(button, false);
        }
    };
    reader.readAsText(file);
});

// Load Data Report with multiple graphs
document.getElementById('loadReportBtn').addEventListener('click', () => {
    const button = document.getElementById('loadReportBtn');
    setLoading(button, true);
    if (!window.uploadedData) {
        alert('Please upload a file first.');
        setLoading(button, false);
        return;
    }
    
    const data = window.uploadedData;
    const summaryText = document.getElementById('summaryText');
    summaryText.textContent = `Rows: ${data.summary.rows}, Columns: ${data.summary.columns.join(', ')}, Benign: ${data.summary.benign_count}, Intrusions: ${data.summary.intrusion_count}`;
    
    // Pie Chart
    const pieCtx = document.getElementById('pieChart').getContext('2d');
    new Chart(pieCtx, {
        type: 'pie',
        data: {
            labels: data.graph_data.pie.labels,
            datasets: [{
                data: data.graph_data.pie.values,
                backgroundColor: ['#2196F3', '#f44336']
            }]
        },
        options: { title: { display: true, text: 'Benign vs Intrusion' }, animation: { animateScale: true } }
    });
    
    // Bar Chart
    const barCtx = document.getElementById('barChart').getContext('2d');
    new Chart(barCtx, {
        type: 'bar',
        data: {
            labels: data.graph_data.bar.labels,
            datasets: [{
                label: 'Average Value',
                data: data.graph_data.bar.values,
                backgroundColor: '#2196F3'
            }]
        },
        options: { title: { display: true, text: 'Top Feature Distributions' }, animation: { animateScale: true } }
    });
    
    // Line Chart
    const lineCtx = document.getElementById('lineChart').getContext('2d');
    new Chart(lineCtx, {
        type: 'line',
        data: {
            labels: data.graph_data.line.labels,
            datasets: [{
                label: 'Trend',
                data: data.graph_data.line.values,
                borderColor: '#f44336',
                fill: false
            }]
        },
        options: { title: { display: true, text: 'Simulated Trend' }, animation: { animateScale: true } }
    });
    
    setLoading(button, false);
});

// Blockchain Report
async function loadBlockchainReport() {
    try {
        const response = await fetch('http://localhost:5000/threat_log');
        const log = await response.json();
        const tbody = document.querySelector('#blockchainTable tbody');
        tbody.innerHTML = '';
        log.forEach(entry => {
            const row = document.createElement('tr');
            row.innerHTML = `<td>${entry.entry}</td><td>${entry.hash}</td><td>${entry.prev_hash}</td><td>Pending</td>`;
            tbody.appendChild(row);
        });
    } catch (error) {
        console.error('Error loading blockchain report.');
    }
}

document.getElementById('verifyChainBtn').addEventListener('click', () => {
    // Simple chain verification
    const rows = document.querySelectorAll('#blockchainTable tbody tr');
    rows.forEach((row, i) => {
        const prevHash = i === 0 ? '0'.repeat(64) : rows[i-1].querySelector('td:nth-child(2)').textContent;
        const currentPrev = row.querySelector('td:nth-child(3)').textContent;
        const valid = prevHash === currentPrev ? 'Yes' : 'No';
        row.querySelector('td:nth-child(4)').textContent = valid;
    });
});

// Simulation
document.getElementById('simulateBtn').addEventListener('click', async () => {
    const button = document.getElementById('simulateBtn');
    setLoading(button, true);
    const resultsDiv = document.getElementById('simulationResults');
    resultsDiv.innerHTML = '<p>Simulating...</p>';
    
    try {
        const response = await fetch('http://localhost:5000/simulate');
        const results = await response.json();
        resultsDiv.innerHTML = '';
        results.forEach((result, i) => {
            const p = document.createElement('p');
            p.className = result.prediction === 'Intrusion' ? 'alert' : 'success';
            p.textContent = `Flow ${i}: ${result.prediction} - ${result.action}`;
            resultsDiv.appendChild(p);
        });
        loadBlockchainReport();  // Refresh log
    } catch (error) {
        resultsDiv.innerHTML = '<p>Error simulating flows.</p>';
    } finally {
        setLoading(button, false);
    }
});

// Explanation
document.getElementById('explainBtn').addEventListener('click', async () => {
    const button = document.getElementById('explainBtn');
    setLoading(button, true);
    const flowInput = document.getElementById('flowInput').value;
    const resultsDiv = document.getElementById('explanationResults');
    try {
        const flow = flowInput.split(',').map(Number);
        const response = await fetch('http://localhost:5000/explain', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ flow })
        });
        const data = await response.json();
        resultsDiv.innerHTML = '<h3>Top 5 Features:</h3><ul>';
        data.top_features.forEach(([feature, value]) => {
            resultsDiv.innerHTML += `<li>Feature ${feature}: ${value.toFixed(4)}</li>`;
        });
        resultsDiv.innerHTML += '</ul>';
    } catch (error) {
        resultsDiv.innerHTML = '<p>Error explaining prediction.</p>';
    } finally {
        setLoading(button, false);
    }
});

// Background Particles: Generate more floating particles
function createBackgroundParticles() {
    const container = document.getElementById('particles-bg') || document.createElement('div');
    container.id = 'particles-bg';
    document.body.appendChild(container);

    const particleCount = 150; // Increased for "more" particles
    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.width = Math.random() * 4 + 2 + 'px'; // 2-6px size
        particle.style.height = particle.style.width;
        particle.style.left = Math.random() * 100 + 'vw';
        particle.style.animationDelay = Math.random() * 10 + 's'; // Staggered start
        particle.style.animationDuration = (Math.random() * 5 + 5) + 's'; // 5-10s duration
        container.appendChild(particle);
    }
}

// Cursor Particles: Spread particles on mouse move (with lower sparkle)
const canvas = document.createElement('canvas');
canvas.id = 'cursor-particles';
document.body.appendChild(canvas);
const ctx = canvas.getContext('2d');
canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

let particles = [];
const maxParticles = 100; // Limit for performance

class CursorParticle {
    constructor(x, y) {
        this.x = x;
        this.y = y;
        this.size = Math.random() * 3 + 1; // 1-4px
        this.speedX = (Math.random() - 0.5) * 0,5; // Spread direction
        this.speedY = (Math.random() - 0.5) * 0.5;
        this.opacity = 0.2;
        this.color = '#00ff00';
    }

    update() {
        this.x += this.speedX;
        this.y += this.speedY;
        this.opacity -= 0.02; // Fade out
        this.size *= 0.98; // Shrink
    }

    draw() {
        ctx.globalAlpha = this.opacity;
        ctx.fillStyle = this.color;
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowColor = this.color;
        ctx.shadowBlur = 2; // Reduced for lower sparkle
    }
}

function handleMouseMove(e) {
    // Create 2-4 particles per move (reduced for lower density)
    for (let i = 0; i < Math.random() * 2 + 2; i++) {
        particles.push(new CursorParticle(e.clientX, e.clientY));
    }
    if (particles.length > maxParticles) {
        particles = particles.slice(-maxParticles); // Keep only recent ones
    }
}

function animateParticles() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    particles.forEach((p, index) => {
        p.update();
        p.draw();
        if (p.opacity <= 0) {
            particles.splice(index, 1); // Remove faded particles
        }
    });
    requestAnimationFrame(animateParticles);
}

// Load blockchain on page load
loadBlockchainReport();

// Utility function for loading state
function setLoading(button, loading) {
    if (loading) {
        button.classList.add('loading');
        button.disabled = true;
    } else {
        button.classList.remove('loading');
        button.disabled = false;
    }
}

// Initialize particles on load
document.addEventListener('DOMContentLoaded', () => {
    createBackgroundParticles();
    document.addEventListener('mousemove', handleMouseMove);
    animateParticles();

    // Resize canvas on window resize
    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });

    // Respect reduced motion
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        document.getElementById('particles-bg').style.display = 'none';
        document.removeEventListener('mousemove', handleMouseMove);
    }
});


// Chatbot functionality
const chatbotIcon = document.getElementById('chatbotIcon');
const chatbotPortal = document.getElementById('chatbotPortal');
const closeChat = document.getElementById('closeChat');
const chatInput = document.getElementById('chatInput');
const sendBtn = document.getElementById('sendBtn');
const chatMessages = document.getElementById('chatMessages');

// Toggle chatbot portal
chatbotIcon.addEventListener('click', () => {
    chatbotPortal.style.display = chatbotPortal.style.display === 'flex' ? 'flex' : 'flex';
});

closeChat.addEventListener('click', () => {
    chatbotPortal.style.display = 'none';
});

// Send message
sendBtn.addEventListener('click', sendMessage);
chatInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') sendMessage();
});

function sendMessage() {
    const message = chatInput.value.trim();
    if (message) {
        // Add user message
        const userMsg = document.createElement('div');
        userMsg.className = 'message user';
        userMsg.textContent = message;
        chatMessages.appendChild(userMsg);
        
        // Clear input
        chatInput.value = '';
        
        // Simulate bot response (replace with actual logic)
        setTimeout(() => {
            const botMsg = document.createElement('div');
            botMsg.className = 'message bot';
            botMsg.textContent = 'This is a placeholder response. Integrate with your AI/ML backend for real answers!';
            chatMessages.appendChild(botMsg);
            chatMessages.scrollTop = chatMessages.scrollHeight; // Auto-scroll
        }, 1000);
        
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
}
