// // // Hamburger menu toggle for mobile
// // document.getElementById('hamburger').addEventListener('click', () => {
// //     const sidebar = document.getElementById('sidebar');
// //     sidebar.classList.toggle('open');
// // });

// // // File upload and segregated data display
// // document.getElementById('uploadBtn').addEventListener('click', () => {
// //     const button = document.getElementById('uploadBtn');
// //     setLoading(button, true);
// //     const fileInput = document.getElementById('fileInput');
// //     const file = fileInput.files[0];
// //     if (!file) {
// //         alert('Please select a file.');
// //         setLoading(button, false);
// //         return;
// //     }
    
// //     const reader = new FileReader();
// //     reader.onload = async (e) => {
// //         const content = e.target.result;
        
// //         // Send to backend for processing
// //         const formData = new FormData();
// //         formData.append('file', file);
// //         try {
// //             const response = await fetch('http://localhost:5000/upload', {
// //                 method: 'POST',
// //                 body: formData
// //             });
// //             const data = await response.json();
// //             if (data.error) {
// //                 alert(data.error);
// //             } else {
// //                 // Store data for report generation
// //                 window.uploadedData = data;
                
// //                 // Display segregated data with animation
// //                 const container = document.getElementById('segregatedDataContainer');
// //                 const thead = document.getElementById('segregatedTableHead');
// //                 const tbody = document.getElementById('segregatedTableBody');
                
// //                 // Create header
// //                 const columns = Object.keys(data.summary.segregated_data[0] || {});
// //                 thead.innerHTML = '<tr>' + columns.map(col => `<th>${col}</th>`).join('') + '</tr>';
                
// //                 // Create rows with staggered animation
// //                 tbody.innerHTML = '';
// //                 data.summary.segregated_data.forEach((row, i) => {
// //                     const tr = document.createElement('tr');
// //                     tr.style.animationDelay = `${i * 0.1}s`;
// //                     tr.innerHTML = columns.map(col => `<td>${row[col]}</td>`).join('');
// //                     tbody.appendChild(tr);
// //                 });
                
// //                 container.style.display = 'block';
// //                 container.style.animation = 'fadeIn 0.5s ease-out';
// //                 alert('File processed successfully. Segregated data displayed. Click "Generate Report" for graphs.');
// //             }
// //         } catch (error) {
// //             alert('Error uploading file.');
// //         } finally {
// //             setLoading(button, false);
// //         }
// //     };
// //     reader.readAsText(file);
// // });

// // // Load Data Report with multiple graphs
// // document.getElementById('loadReportBtn').addEventListener('click', () => {
// //     const button = document.getElementById('loadReportBtn');
// //     setLoading(button, true);
// //     if (!window.uploadedData) {
// //         alert('Please upload a file first.');
// //         setLoading(button, false);
// //         return;
// //     }
    
// //     const data = window.uploadedData;
// //     const summaryText = document.getElementById('summaryText');
// //     summaryText.textContent = `Rows: ${data.summary.rows}, Columns: ${data.summary.columns.join(', ')}, Benign: ${data.summary.benign_count}, Intrusions: ${data.summary.intrusion_count}`;
    
// //     // Pie Chart
// //     const pieCtx = document.getElementById('pieChart').getContext('2d');
// //     new Chart(pieCtx, {
// //         type: 'pie',
// //         data: {
// //             labels: data.graph_data.pie.labels,
// //             datasets: [{
// //                 data: data.graph_data.pie.values,
// //                 backgroundColor: ['#000000ff', '#ff0000ff']
// //             }]
// //         },
// //         options: { title: { display: true, text: 'Benign vs Intrusion' }, animation: { animateScale: true } }
// //     });
    
// //     // Bar Chart
// //     const barCtx = document.getElementById('barChart').getContext('2d');
// //     new Chart(barCtx, {
// //         type: 'bar',
// //         data: {
// //             labels: data.graph_data.bar.labels,
// //             datasets: [{
// //                 label: 'Average Value',
// //                 data: data.graph_data.bar.values,
// //                 backgroundColor: '#ff0000ff'
// //             }]
// //         },
// //         options: { title: { display: true, text: 'Top Feature Distributions' }, animation: { animateScale: true } }
// //     });
    
// //     // Line Chart
// //     const lineCtx = document.getElementById('lineChart').getContext('2d');
// //     new Chart(lineCtx, {
// //         type: 'line',
// //         data: {
// //             labels: data.graph_data.line.labels,
// //             datasets: [{
// //                 label: 'Trend',
// //                 data: data.graph_data.line.values,
// //                 borderColor: '#ff1100ff',
// //                 fill: false
// //             }]
// //         },
// //         options: { title: { display: true, text: 'Simulated Trend' }, animation: { animateScale: true } }
// //     });
    
// //     setLoading(button, false);
// // });

// // // Blockchain Report
// // async function loadBlockchainReport() {
// //     try {
// //         const response = await fetch('http://localhost:5000/threat_log');
// //         const log = await response.json();
// //         const tbody = document.querySelector('#blockchainTable tbody');
// //         tbody.innerHTML = '';
// //         log.forEach(entry => {
// //             const row = document.createElement('tr');
// //             row.innerHTML = `<td>${entry.entry}</td><td>${entry.hash}</td><td>${entry.prev_hash}</td><td>Pending</td>`;
// //             tbody.appendChild(row);
// //         });
// //     } catch (error) {
// //         console.error('Error loading blockchain report.');
// //     }
// // }

// // document.getElementById('verifyChainBtn').addEventListener('click', () => {
// //     // Simple chain verification
// //     const rows = document.querySelectorAll('#blockchainTable tbody tr');
// //     rows.forEach((row, i) => {
// //         const prevHash = i === 0 ? '0'.repeat(64) : rows[i-1].querySelector('td:nth-child(2)').textContent;
// //         const currentPrev = row.querySelector('td:nth-child(3)').textContent;
// //         const valid = prevHash === currentPrev ? 'Yes' : 'No';
// //         row.querySelector('td:nth-child(4)').textContent = valid;
// //     });
// // });

// // // Simulation
// // document.getElementById('simulateBtn').addEventListener('click', async () => {
// //     const button = document.getElementById('simulateBtn');
// //     setLoading(button, true);
// //     const resultsDiv = document.getElementById('simulationResults');
// //     resultsDiv.innerHTML = '<p>Simulating...</p>';
    
// //     try {
// //         const response = await fetch('http://localhost:5000/simulate');
// //         const results = await response.json();
// //         resultsDiv.innerHTML = '';
// //         results.forEach((result, i) => {
// //             const p = document.createElement('p');
// //             p.className = result.prediction === 'Intrusion' ? 'alert' : 'success';
// //             p.textContent = `Flow ${i}: ${result.prediction} - ${result.action}`;
// //             resultsDiv.appendChild(p);
// //         });
// //         loadBlockchainReport();  // Refresh log
// //     } catch (error) {
// //         resultsDiv.innerHTML = '<p>Error simulating flows.</p>';
// //     } finally {
// //         setLoading(button, false);
// //     }
// // });

// // // Explanation
// // document.getElementById('explainBtn').addEventListener('click', async () => {
// //     const button = document.getElementById('explainBtn');
// //     setLoading(button, true);
// //     const flowInput = document.getElementById('flowInput').value;
// //     const resultsDiv = document.getElementById('explanationResults');
// //     try {
// //         const flow = flowInput.split(',').map(Number);
// //         const response = await fetch('http://localhost:5000/explain', {
// //             method: 'POST',
// //             headers: { 'Content-Type': 'application/json' },
// //             body: JSON.stringify({ flow })
// //         });
// //         const data = await response.json();
// //         resultsDiv.innerHTML = '<h3>Top 5 Features:</h3><ul>';
// //         data.top_features.forEach(([feature, value]) => {
// //             resultsDiv.innerHTML += `<li>Feature ${feature}: ${value.toFixed(4)}</li>`;
// //         });
// //         resultsDiv.innerHTML += '</ul>';
// //     } catch (error) {
// //         resultsDiv.innerHTML = '<p>Error explaining prediction.</p>';
// //     } finally {
// //         setLoading(button, false);
// //     }
// // });

// // // Background Particles: Generate more floating particles
// // function createBackgroundParticles() {
// //     const container = document.getElementById('particles-bg') || document.createElement('div');
// //     container.id = 'particles-bg';
// //     document.body.appendChild(container);

// //     const particleCount = 150; // Increased for "more" particles
// //     for (let i = 0; i < particleCount; i++) {
// //         const particle = document.createElement('div');
// //         particle.className = 'particle';
// //         particle.style.width = Math.random() * 4 + 2 + 'px'; // 2-6px size
// //         particle.style.height = particle.style.width;
// //         particle.style.left = Math.random() * 100 + 'vw';
// //         particle.style.animationDelay = Math.random() * 10 + 's'; // Staggered start
// //         particle.style.animationDuration = (Math.random() * 5 + 5) + 's'; // 5-10s duration
// //         container.appendChild(particle);
// //     }
// // }

// // // Cursor Particles: Spread particles on mouse move (with lower sparkle)
// // const canvas = document.createElement('canvas');
// // canvas.id = 'cursor-particles';
// // document.body.appendChild(canvas);
// // const ctx = canvas.getContext('2d');
// // canvas.width = window.innerWidth;
// // canvas.height = window.innerHeight;

// // let particles = [];
// // const maxParticles = 100; // Limit for performance

// // class CursorParticle {
// //     constructor(x, y) {
// //         this.x = x;
// //         this.y = y;
// //         this.size = Math.random() * 3 + 1; // 1-4px
// //         this.speedX = (Math.random() - 0.5) * 0,5; // Spread direction
// //         this.speedY = (Math.random() - 0.5) * 0.5;
// //         this.opacity = 0.2;
// //         this.color = '#00ff00';
// //     }

// //     update() {
// //         this.x += this.speedX;
// //         this.y += this.speedY;
// //         this.opacity -= 0.02; // Fade out
// //         this.size *= 0.98; // Shrink
// //     }

// //     draw() {
// //         ctx.globalAlpha = this.opacity;
// //         ctx.fillStyle = this.color;
// //         ctx.beginPath();
// //         ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
// //         ctx.fill();
// //         ctx.shadowColor = this.color;
// //         ctx.shadowBlur = 2; // Reduced for lower sparkle
// //     }
// // }

// // function handleMouseMove(e) {
// //     // Create 2-4 particles per move (reduced for lower density)
// //     for (let i = 0; i < Math.random() * 2 + 2; i++) {
// //         particles.push(new CursorParticle(e.clientX, e.clientY));
// //     }
// //     if (particles.length > maxParticles) {
// //         particles = particles.slice(-maxParticles); // Keep only recent ones
// //     }
// // }

// // function animateParticles() {
// //     ctx.clearRect(0, 0, canvas.width, canvas.height);
// //     particles.forEach((p, index) => {
// //         p.update();
// //         p.draw();
// //         if (p.opacity <= 0) {
// //             particles.splice(index, 1); // Remove faded particles
// //         }
// //     });
// //     requestAnimationFrame(animateParticles);
// // }

// // // Load blockchain on page load
// // loadBlockchainReport();

// // // Utility function for loading state
// // function setLoading(button, loading) {
// //     if (loading) {
// //         button.classList.add('loading');
// //         button.disabled = true;
// //     } else {
// //         button.classList.remove('loading');
// //         button.disabled = false;
// //     }
// // }

// // // Initialize particles on load
// // document.addEventListener('DOMContentLoaded', () => {
// //     createBackgroundParticles();
// //     document.addEventListener('mousemove', handleMouseMove);
// //     animateParticles();

// //     // Resize canvas on window resize
// //     window.addEventListener('resize', () => {
// //         canvas.width = window.innerWidth;
// //         canvas.height = window.innerHeight;
// //     });

// //     // Respect reduced motion
// //     if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
// //         document.getElementById('particles-bg').style.display = 'none';
// //         document.removeEventListener('mousemove', handleMouseMove);
// //     }
// // });

// // // Chatbot functionality
// // const chatbotIcon = document.getElementById('chatbotIcon');
// // const chatbotPortal = document.getElementById('chatbotPortal');
// // const closeChat = document.getElementById('closeChat');
// // const chatInput = document.getElementById('chatInput');
// // const sendBtn = document.getElementById('sendBtn');
// // const chatMessages = document.getElementById('chatMessages');

// // // Toggle chatbot portal
// // chatbotIcon.addEventListener('click', () => {
// //     chatbotPortal.style.display = chatbotPortal.style.display === 'flex' ? 'flex' : 'flex';
// // });

// // closeChat.addEventListener('click', () => {
// //     chatbotPortal.style.display = 'none';
// // });

// // // Send message
// // sendBtn.addEventListener('click', sendMessage);
// // chatInput.addEventListener('keypress', (e) => {
// //     if (e.key === 'Enter') sendMessage();
// // });

// // function sendMessage() {
// //     const message = chatInput.value.trim();
// //     if (message) {
// //         // Add user message
// //         const userMsg = document.createElement('div');
// //         userMsg.className = 'message user';
// //         userMsg.textContent = message;
// //         chatMessages.appendChild(userMsg);
        
// //         // Clear input
// //         chatInput.value = '';
        
// //         // Simulate bot response (replace with actual logic)
// //         setTimeout(() => {
// //             const botMsg = document.createElement('div');
// //             botMsg.className = 'message bot';
// //             botMsg.textContent = 'This is a placeholder response. Integrate with your AI/ML backend for real answers!';
// //             chatMessages.appendChild(botMsg);
// //             chatMessages.scrollTop = chatMessages.scrollHeight; // Auto-scroll
// //         }, 1000);
        
// //         chatMessages.scrollTop = chatMessages.scrollHeight;
// //     }
// // }
// // async function loadBlockchainReport() {
// //     try {
// //         const response = await fetch('http://localhost:5000/threat_log');
// //         const log = await response.json();
// //         const tbody = document.querySelector('#blockchainTable tbody');
// //         tbody.innerHTML = '';
// //         log.forEach(entry => {
// //             const row = document.createElement('tr');
// //             row.innerHTML = `<td>${entry.entry}</td><td>${entry.hash}</td><td>${entry.prev_hash}</td><td>Pending</td>`;
// //             tbody.appendChild(row);
// //         });

// //         // Enable scroll only if rows > 2
// //         const wrapper = document.getElementById('blockchainTableWrapper');
// //         if (log.length > 2) {
// //             wrapper.style.overflowY = 'auto';
// //             wrapper.style.maxHeight = '120px'; // or adjust height as needed
// //             wrapper.style.border = '2px solid #00ff00';
// //         } else {
// //             // Disable scroll, auto height
// //             wrapper.style.overflowY = 'visible';
// //             wrapper.style.maxHeight = 'none';
// //             wrapper.style.border = 'none';
// //         }
        
// //     } catch (error) {
// //         console.error('Error loading blockchain report.');
// //     }
// // }
// // // 

// // // Add export buttons to UI
// // document.getElementById('generateReportBtn').addEventListener('click', () => {
// //     generateReport();
// //     showExportOptions();  // Show export menu after report
// // });

// // async function showExportOptions() {
// //     const exportMenu = document.createElement('div');
// //     exportMenu.className = 'export-menu';
// //     exportMenu.innerHTML = `
// //         <div class="export-popup">
// //             <h3>📥 Export Threat Report</h3>
// //             <button class="export-btn" onclick="exportFormat('pdf')">
// //                 📄 Export as PDF
// //             </button>
// //             <button class="export-btn" onclick="exportFormat('txt')">
// //                 📝 Export as TXT (RAG)
// //             </button>
// //             <button class="export-btn" onclick="exportFormat('rag-kb')">
// //                 🤖 Export RAG Knowledge Base
// //             </button>
// //             <button class="export-btn" onclick="exportFormat('all')">
// //                 📦 Export All Formats
// //             </button>
// //             <button class="close-btn" onclick="this.parentElement.parentElement.remove()">
// //                 ✕ Close
// //             </button>
// //         </div>
// //     `;
// //     document.body.appendChild(exportMenu);
// // }

// // async function exportFormat(format) {
// //     try {
// //         const response = await fetch(`http://localhost:5000/export/${format}`);
// //         const data = await response.json();
        
// //         if (data.download_url) {
// //             // Download file
// //             window.location.href = `http://localhost:5000${data.download_url}`;
// //             alert(`✅ ${data.filename} downloaded successfully!`);
// //         } else {
// //             alert(`✅ ${data.message}`);
// //         }
// //     } catch (error) {
// //         alert(`❌ Export failed: ${error.message}`);
// //     }
// // }
// // // ==================== EXPORT FUNCTIONALITY ====================

// // // Show export section after report is generated
// // function showExportSection() {
// //     const exportSection = document.getElementById('exportSection');
// //     if (exportSection) {
// //         exportSection.style.display = 'block';
// //     }
// // }

// // // Export report in specified format
// // async function exportReport(format) {
// //     const button = event.target;
// //     const originalText = button.innerHTML;
    
// //     try {
// //         button.innerHTML = '⏳ Generating...';
// //         button.disabled = true;
        
// //         const response = await fetch(`http://localhost:5000/export/${format}`);
// //         const data = await response.json();
        
// //         if (response.ok) {
// //             // Success notification
// //             showNotification(`✅ ${data.filename} generated successfully!`, 'success');
            
// //             // Download the file if download_url is provided
// //             if (data.download_url) {
// //                 const downloadUrl = `http://localhost:5000${data.download_url}`;
// //                 const link = document.createElement('a');
// //                 link.href = downloadUrl;
// //                 link.download = data.filename;
// //                 document.body.appendChild(link);
// //                 link.click();
// //                 document.body.removeChild(link);
// //             }
            
// //             // Show details for 'all' format
// //             if (format === 'all' && data.exports) {
// //                 let message = 'All formats exported:\n';
// //                 for (const [type, info] of Object.entries(data.exports)) {
// //                     message += `\n${info.filename} (${formatBytes(info.size)})`;
// //                 }
// //                 showNotification(message, 'success');
// //             }
// //         } else {
// //             showNotification(`❌ Export failed: ${data.detail}`, 'error');
// //         }
// //     } catch (error) {
// //         console.error('Export error:', error);
// //         showNotification(`❌ Export failed: ${error.message}`, 'error');
// //     } finally {
// //         button.innerHTML = originalText;
// //         button.disabled = false;
// //     }
// // }

// // // Show notification popup
// // function showNotification(message, type = 'info') {
// //     const notification = document.createElement('div');
// //     notification.className = `notification ${type}`;
// //     notification.style.cssText = `
// //         position: fixed;
// //         top: 20px;
// //         right: 20px;
// //         background: ${type === 'success' ? '#00ff00' : '#ff0000'};
// //         color: #000;
// //         padding: 15px 25px;
// //         border-radius: 8px;
// //         font-weight: bold;
// //         z-index: 10000;
// //         box-shadow: 0 0 20px ${type === 'success' ? '#00ff00' : '#ff0000'};
// //         animation: slideIn 0.3s ease;
// //         white-space: pre-line;
// //     `;
// //     notification.textContent = message;
    
// //     document.body.appendChild(notification);
    
// //     // Auto remove after 5 seconds
// //     setTimeout(() => {
// //         notification.style.animation = 'slideOut 0.3s ease';
// //         setTimeout(() => notification.remove(), 300);
// //     }, 5000);
// // }

// // // Format bytes to human readable
// // function formatBytes(bytes) {
// //     if (bytes === 0) return '0 Bytes';
// //     const k = 1024;
// //     const sizes = ['Bytes', 'KB', 'MB', 'GB'];
// //     const i = Math.floor(Math.log(bytes) / Math.log(k));
// //     return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
// // }

// // // Update the generateReport function to show export section
// // // Find your existing generateReport function and add this at the end:
// // // showExportSection();



// // ==================== GLOBAL VARIABLES ====================
// let particles = [];
// const maxParticles = 100;

// // ==================== UTILITY FUNCTIONS ====================
// function setLoading(button, loading) {
//     if (loading) {
//         button.classList.add('loading');
//         button.disabled = true;
//     } else {
//         button.classList.remove('loading');
//         button.disabled = false;
//     }
// }

// function formatBytes(bytes) {
//     if (bytes === 0) return '0 Bytes';
//     const k = 1024;
//     const sizes = ['Bytes', 'KB', 'MB', 'GB'];
//     const i = Math.floor(Math.log(bytes) / Math.log(k));
//     return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
// }

// // ==================== HAMBURGER MENU ====================
// document.getElementById('hamburger').addEventListener('click', () => {
//     const sidebar = document.getElementById('sidebar');
//     sidebar.classList.toggle('open');
// });

// // ==================== FILE UPLOAD ====================
// document.getElementById('uploadBtn').addEventListener('click', () => {
//     const button = document.getElementById('uploadBtn');
//     setLoading(button, true);
//     const fileInput = document.getElementById('fileInput');
//     const file = fileInput.files[0];
    
//     if (!file) {
//         alert('Please select a file.');
//         setLoading(button, false);
//         return;
//     }
    
//     const reader = new FileReader();
//     reader.onload = async (e) => {
//         const content = e.target.result;
        
//         // Send to backend for processing
//         const formData = new FormData();
//         formData.append('file', file);
        
//         try {
//             const response = await fetch('http://localhost:5000/upload', {
//                 method: 'POST',
//                 body: formData
//             });
//             const data = await response.json();
            
//             if (data.error) {
//                 alert(data.error);
//             } else {
//                 // Store data for report generation
//                 window.uploadedData = data;
                
//                 // Display segregated data with animation
//                 const container = document.getElementById('segregatedDataContainer');
//                 const thead = document.getElementById('segregatedTableHead');
//                 const tbody = document.getElementById('segregatedTableBody');
                
//                 // Create header
//                 const columns = Object.keys(data.summary.segregated_data[0] || {});
//                 thead.innerHTML = '<tr>' + columns.map(col => `<th>${col}</th>`).join('') + '</tr>';
                
//                 // Create rows with staggered animation
//                 tbody.innerHTML = '';
//                 data.summary.segregated_data.forEach((row, i) => {
//                     const tr = document.createElement('tr');
//                     tr.style.animationDelay = `${i * 0.1}s`;
//                     tr.innerHTML = columns.map(col => `<td>${row[col]}</td>`).join('');
//                     tbody.appendChild(tr);
//                 });
                
//                 container.style.display = 'block';
//                 container.style.animation = 'fadeIn 0.5s ease-out';
                
//                 // Load blockchain report after upload
//                 loadBlockchainReport();
                
//                 alert('File processed successfully. Segregated data displayed. Click "Generate Report" for graphs.');
//             }
//         } catch (error) {
//             console.error('Upload error:', error);
//             alert('Error uploading file.');
//         } finally {
//             setLoading(button, false);
//         }
//     };
//     reader.readAsText(file);
// });

// // ==================== GENERATE REPORT ====================
// document.getElementById('loadReportBtn').addEventListener('click', () => {
//     const button = document.getElementById('loadReportBtn');
//     setLoading(button, true);
    
//     if (!window.uploadedData) {
//         alert('Please upload a file first.');
//         setLoading(button, false);
//         return;
//     }
    
//     const data = window.uploadedData;
//     const summaryText = document.getElementById('summaryText');
//     summaryText.textContent = `Rows: ${data.summary.rows}, Columns: ${data.summary.columns.join(', ')}, Benign: ${data.summary.benign_count}, Intrusions: ${data.summary.intrusion_count}`;
    
//     // Destroy existing charts if they exist
//     if (window.pieChart) window.pieChart.destroy();
//     if (window.barChart) window.barChart.destroy();
//     if (window.lineChart) window.lineChart.destroy();
    
//     // Pie Chart
//     const pieCtx = document.getElementById('pieChart').getContext('2d');
//     window.pieChart = new Chart(pieCtx, {
//         type: 'pie',
//         data: {
//             labels: data.graph_data.pie.labels,
//             datasets: [{
//                 data: data.graph_data.pie.values,
//                 backgroundColor: ['#00ff00', '#ff0000']
//             }]
//         },
//         options: {
//             responsive: true,
//             plugins: {
//                 title: { display: true, text: 'Benign vs Intrusion' },
//                 legend: { labels: { color: '#00ff00' } }
//             },
//             animation: { animateScale: true }
//         }
//     });
    
//     // Bar Chart
//     const barCtx = document.getElementById('barChart').getContext('2d');
//     window.barChart = new Chart(barCtx, {
//         type: 'bar',
//         data: {
//             labels: data.graph_data.bar.labels,
//             datasets: [{
//                 label: 'Severity Distribution',
//                 data: data.graph_data.bar.values,
//                 backgroundColor: '#ff0000'
//             }]
//         },
//         options: {
//             responsive: true,
//             plugins: {
//                 title: { display: true, text: 'Threat Severity Levels' },
//                 legend: { labels: { color: '#00ff00' } }
//             },
//             scales: {
//                 y: { ticks: { color: '#00ff00' } },
//                 x: { ticks: { color: '#00ff00' } }
//             },
//             animation: { animateScale: true }
//         }
//     });
    
//     // Line Chart
//     const lineCtx = document.getElementById('lineChart').getContext('2d');
//     window.lineChart = new Chart(lineCtx, {
//         type: 'line',
//         data: {
//             labels: data.graph_data.line.labels,
//             datasets: [{
//                 label: 'Confidence Trend',
//                 data: data.graph_data.line.values,
//                 borderColor: '#ff0000',
//                 backgroundColor: 'rgba(255, 0, 0, 0.1)',
//                 fill: true
//             }]
//         },
//         options: {
//             responsive: true,
//             plugins: {
//                 title: { display: true, text: 'Detection Confidence Over Time' },
//                 legend: { labels: { color: '#00ff00' } }
//             },
//             scales: {
//                 y: { ticks: { color: '#00ff00' } },
//                 x: { ticks: { color: '#00ff00' } }
//             },
//             animation: { animateScale: true }
//         }
//     });
//     showExportSection();
//     setLoading(button, false);
//     document.getElementById('reportContent').scrollIntoView({ behavior: 'smooth' });
// });

// // ==================== BLOCKCHAIN REPORT ====================
// async function loadBlockchainReport() {
//     try {
//         const response = await fetch('http://localhost:5000/threat_log');
//         const log = await response.json();
//         const tbody = document.querySelector('#blockchainTable tbody');
//         tbody.innerHTML = '';
        
//         log.forEach(entry => {
//             const row = document.createElement('tr');
//             row.innerHTML = `
//                 <td>${entry.entry}</td>
//                 <td>${entry.hash.substring(0, 16)}...</td>
//                 <td>${entry.prev_hash.substring(0, 16)}...</td>
//                 <td>Pending</td>
//             `;
//             tbody.appendChild(row);
//         });

//         // Enable scroll only if rows > 2
//         const wrapper = document.getElementById('blockchainTableWrapper');
//         if (log.length > 2) {
//             wrapper.style.overflowY = 'auto';
//             wrapper.style.maxHeight = '120px';
//             wrapper.style.border = '2px solid #00ff00';
//         } else {
//             wrapper.style.overflowY = 'visible';
//             wrapper.style.maxHeight = 'none';
//             wrapper.style.border = 'none';
//         }
        
//     } catch (error) {
//         console.error('Error loading blockchain report:', error);
//     }
// }

// document.getElementById('verifyChainBtn').addEventListener('click', () => {
//     const rows = document.querySelectorAll('#blockchainTable tbody tr');
//     rows.forEach((row, i) => {
//         const prevHash = i === 0 ? '0'.repeat(64) : rows[i-1].querySelector('td:nth-child(2)').textContent;
//         const currentPrev = row.querySelector('td:nth-child(3)').textContent;
//         const valid = prevHash === currentPrev ? 'Yes' : 'No';
//         row.querySelector('td:nth-child(4)').textContent = valid;
//         row.querySelector('td:nth-child(4)').style.color = valid === 'Yes' ? '#00ff00' : '#ff0000';
//     });
// });

// // ==================== SIMULATION ====================
// document.getElementById('simulateBtn').addEventListener('click', async () => {
//     const button = document.getElementById('simulateBtn');
//     setLoading(button, true);
//     const resultsDiv = document.getElementById('simulationResults');
//     resultsDiv.innerHTML = '<p>Simulating real-time network flows...</p>';
    
//     try {
//         const response = await fetch('http://localhost:5000/simulate');
//         const results = await response.json();
//         resultsDiv.innerHTML = '';
        
//         results.forEach((result, i) => {
//             const p = document.createElement('p');
//             p.className = result.prediction === 'Intrusion' ? 'alert' : 'success';
//             p.textContent = `Flow ${i + 1}: ${result.prediction} - ${result.action}`;
//             if (result.severity) {
//                 p.textContent += ` | Severity: ${result.severity}`;
//             }
//             resultsDiv.appendChild(p);
//         });
        
//         // Refresh blockchain log
//         loadBlockchainReport();
//     } catch (error) {
//         console.error('Simulation error:', error);
//         resultsDiv.innerHTML = '<p class="alert">Error simulating flows.</p>';
//     } finally {
//         setLoading(button, false);
//     }
// });

// // ==================== EXPLANATION (SHAP) ====================
// document.getElementById('explainBtn').addEventListener('click', async () => {
//     const button = document.getElementById('explainBtn');
//     setLoading(button, true);
//     const flowInput = document.getElementById('flowInput').value;
//     const resultsDiv = document.getElementById('explanationResults');
    
//     try {
//         const flow = flowInput.split(',').map(Number);
//         const response = await fetch('http://localhost:5000/explain', {
//             method: 'POST',
//             headers: { 'Content-Type': 'application/json' },
//             body: JSON.stringify({ flow })
//         });
//         const data = await response.json();
        
//         resultsDiv.innerHTML = `
//             <h3>Prediction: ${data.prediction}</h3>
//             <p>Confidence: ${data.confidence}</p>
//             <h4>Top 5 Contributing Features:</h4>
//             <ul>
//         `;
        
//         data.top_features.forEach(([feature, value]) => {
//             const impact = value > 0 ? 'increases' : 'decreases';
//             const color = value > 0 ? '#ff0000' : '#00ff00';
//             resultsDiv.innerHTML += `<li style="color: ${color}">
//                 ${feature}: ${value.toFixed(4)} (${impact} attack probability)
//             </li>`;
//         });
        
//         resultsDiv.innerHTML += '</ul>';
        
//         if (data.explanation) {
//             resultsDiv.innerHTML += `<p><strong>Explanation:</strong> ${data.explanation}</p>`;
//         }
        
//     } catch (error) {
//         console.error('Explanation error:', error);
//         resultsDiv.innerHTML = '<p class="alert">Error explaining prediction.</p>';
//     } finally {
//         setLoading(button, false);
//     }
// });

// // ==================== EXPORT FUNCTIONALITY ====================
// function showExportSection() {
//     const exportSection = document.getElementById('exportSection');
//     if (exportSection) {
//         exportSection.style.display = 'block';
//         exportSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
//     }
// }

// async function exportReport(format) {
//     const button = event.target;
//     const originalText = button.innerHTML;
    
//     try {
//         button.innerHTML = '⏳ Generating...';
//         button.disabled = true;
        
//         console.log(`Exporting ${format} format...`);
//         const response = await fetch(`http://localhost:5000/export/${format}`);
//         const data = await response.json();
        
//         if (response.ok) {
//             showNotification(`✅ ${data.filename} generated successfully!`, 'success');
            
//             // Download the file if download_url is provided
//             if (data.download_url) {
//                 const downloadUrl = `http://localhost:5000${data.download_url}`;
//                 const link = document.createElement('a');
//                 link.href = downloadUrl;
//                 link.download = data.filename;
//                 document.body.appendChild(link);
//                 link.click();
//                 document.body.removeChild(link);
//             }
            
//             // Show details for 'all' format
//             if (format === 'all' && data.exports) {
//                 let message = 'All formats exported:\n';
//                 for (const [type, info] of Object.entries(data.exports)) {
//                     message += `\n${info.filename} (${formatBytes(info.size)})`;
//                 }
//                 showNotification(message, 'success');
//             }
//         } else {
//             showNotification(`❌ Export failed: ${data.detail || 'Unknown error'}`, 'error');
//         }
//     } catch (error) {
//         console.error('Export error:', error);
//         showNotification(`❌ Export failed: ${error.message}`, 'error');
//     } finally {
//         button.innerHTML = originalText;
//         button.disabled = false;
//     }
// }

// function showNotification(message, type = 'info') {
//     const notification = document.createElement('div');
//     notification.className = `notification ${type}`;
//     notification.style.cssText = `
//         position: fixed;
//         top: 20px;
//         right: 20px;
//         background: ${type === 'success' ? 'rgba(0, 255, 0, 0.2)' : 'rgba(255, 0, 0, 0.2)'};
//         color: ${type === 'success' ? '#00ff00' : '#ff0000'};
//         padding: 15px 25px;
//         border-radius: 0;
//         border: 2px solid ${type === 'success' ? '#00ff00' : '#ff0000'};
//         font-weight: bold;
//         z-index: 10000;
//         box-shadow: 0 0 20px ${type === 'success' ? 'rgba(0, 255, 0, 0.5)' : 'rgba(255, 0, 0, 0.5)'};
//         animation: slideIn 0.3s ease;
//         white-space: pre-line;
//         backdrop-filter: blur(10px);
//         -webkit-backdrop-filter: blur(10px);
//     `;
//     notification.textContent = message;
    
//     document.body.appendChild(notification);
    
//     // Auto remove after 5 seconds
//     setTimeout(() => {
//         notification.style.animation = 'slideOut 0.3s ease';
//         setTimeout(() => notification.remove(), 300);
//     }, 5000);
// }

// // ==================== BACKGROUND PARTICLES ====================
// function createBackgroundParticles() {
//     const container = document.getElementById('particles-bg') || document.createElement('div');
//     container.id = 'particles-bg';
//     if (!document.getElementById('particles-bg')) {
//         document.body.appendChild(container);
//     }

//     const particleCount = 150;
//     for (let i = 0; i < particleCount; i++) {
//         const particle = document.createElement('div');
//         particle.className = 'particle';
//         particle.style.width = Math.random() * 4 + 2 + 'px';
//         particle.style.height = particle.style.width;
//         particle.style.left = Math.random() * 100 + 'vw';
//         particle.style.animationDelay = Math.random() * 10 + 's';
//         particle.style.animationDuration = (Math.random() * 5 + 5) + 's';
//         container.appendChild(particle);
//     }
// }

// // ==================== CURSOR PARTICLES ====================
// const canvas = document.createElement('canvas');
// canvas.id = 'cursor-particles';
// document.body.appendChild(canvas);
// const ctx = canvas.getContext('2d');
// canvas.width = window.innerWidth;
// canvas.height = window.innerHeight;

// class CursorParticle {
//     constructor(x, y) {
//         this.x = x;
//         this.y = y;
//         this.size = Math.random() * 3 + 1;
//         this.speedX = (Math.random() - 0.5) * 0.5;
//         this.speedY = (Math.random() - 0.5) * 0.5;
//         this.opacity = 0.2;
//         this.color = '#00ff00';
//     }

//     update() {
//         this.x += this.speedX;
//         this.y += this.speedY;
//         this.opacity -= 0.02;
//         this.size *= 0.98;
//     }

//     draw() {
//         ctx.globalAlpha = this.opacity;
//         ctx.fillStyle = this.color;
//         ctx.beginPath();
//         ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
//         ctx.fill();
//         ctx.shadowColor = this.color;
//         ctx.shadowBlur = 2;
//     }
// }

// function handleMouseMove(e) {
//     for (let i = 0; i < Math.random() * 2 + 2; i++) {
//         particles.push(new CursorParticle(e.clientX, e.clientY));
//     }
//     if (particles.length > maxParticles) {
//         particles = particles.slice(-maxParticles);
//     }
// }

// function animateParticles() {
//     ctx.clearRect(0, 0, canvas.width, canvas.height);
//     particles.forEach((p, index) => {
//         p.update();
//         p.draw();
//         if (p.opacity <= 0) {
//             particles.splice(index, 1);
//         }
//     });
//     requestAnimationFrame(animateParticles);
// }

// // ==================== CHATBOT FUNCTIONALITY ====================
// const chatbotIcon = document.getElementById('chatbotIcon');
// const chatbotPortal = document.getElementById('chatbotPortal');
// const closeChat = document.getElementById('closeChat');
// const chatInput = document.getElementById('chatInput');
// const sendBtn = document.getElementById('sendBtn');
// const chatMessages = document.getElementById('chatMessages');

// chatbotIcon.addEventListener('click', () => {
//     chatbotPortal.style.display = chatbotPortal.style.display === 'flex' ? 'none' : 'flex';
//     if (chatbotPortal.style.display === 'flex') {
//         chatInput.focus();
//     }
// });

// closeChat.addEventListener('click', () => {
//     chatbotPortal.style.display = 'none';
// });

// sendBtn.addEventListener('click', sendMessage);
// chatInput.addEventListener('keypress', (e) => {
//     if (e.key === 'Enter') sendMessage();
// });

// function sendMessage() {
//     const message = chatInput.value.trim();
//     if (message) {
//         // Add user message
//         const userMsg = document.createElement('div');
//         userMsg.className = 'message user';
//         userMsg.textContent = message;
//         chatMessages.appendChild(userMsg);
        
//         // Clear input
//         chatInput.value = '';
        
//         // Simulate bot response (integrate with RAG chatbot backend)
//         setTimeout(() => {
//             const botMsg = document.createElement('div');
//             botMsg.className = 'message bot';
//             botMsg.textContent = 'This is a placeholder response. Integrate with your RAG chatbot for real threat intelligence Q&A!';
//             chatMessages.appendChild(botMsg);
//             chatMessages.scrollTop = chatMessages.scrollHeight;
//         }, 1000);
        
//         chatMessages.scrollTop = chatMessages.scrollHeight;
//     }
// }

// // ==================== INITIALIZATION ====================
// document.addEventListener('DOMContentLoaded', () => {
//     createBackgroundParticles();
//     document.addEventListener('mousemove', handleMouseMove);
//     animateParticles();
    
//     // Load blockchain on page load
//     loadBlockchainReport();

//     // Resize canvas on window resize
//     window.addEventListener('resize', () => {
//         canvas.width = window.innerWidth;
//         canvas.height = window.innerHeight;
//     });

//     // Respect reduced motion preference
//     if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
//         const particlesBg = document.getElementById('particles-bg');
//         if (particlesBg) particlesBg.style.display = 'none';
//         document.removeEventListener('mousemove', handleMouseMove);
//     }
// });


// ==================== GLOBAL VARIABLES ====================
let particles = [];
const maxParticles = 100;

// ==================== UTILITY FUNCTIONS ====================
function setLoading(button, loading) {
    if (loading) {
        button.classList.add('loading');
        button.disabled = true;
    } else {
        button.classList.remove('loading');
        button.disabled = false;
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${type === 'success' ? 'rgba(0, 255, 0, 0.2)' : 'rgba(255, 0, 0, 0.2)'};
        color: ${type === 'success' ? '#00ff00' : '#ff0000'};
        padding: 15px 25px;
        border-radius: 0;
        border: 2px solid ${type === 'success' ? '#00ff00' : '#ff0000'};
        font-weight: bold;
        z-index: 10000;
        box-shadow: 0 0 20px ${type === 'success' ? 'rgba(0, 255, 0, 0.5)' : 'rgba(255, 0, 0, 0.5)'};
        white-space: pre-line;
        backdrop-filter: blur(10px);
    `;
    notification.textContent = message;
    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.opacity = '0';
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

// ==================== BLOCKCHAIN LOADING ====================
async function loadBlockchainReport() {
    try {
        const response = await fetch('http://localhost:5000/threat_log');
        const log = await response.json();
        const tbody = document.querySelector('#blockchainTable tbody');
        
        if (tbody) {
            tbody.innerHTML = '';
            log.forEach((entry, index) => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${index + 1}</td>
                    <td>${entry.hash ? entry.hash.substring(0, 16) + '...' : 'N/A'}</td>
                    <td>${entry.prev_hash ? entry.prev_hash.substring(0, 16) + '...' : 'Genesis'}</td>
                    <td>${entry.valid !== undefined ? (entry.valid ? '✓' : '✗') : '✓'}</td>
                `;
                tbody.appendChild(row);
            });
        }
    } catch (error) {
        console.error('Blockchain loading error:', error);
    }
}

// ==================== FILE UPLOAD ====================
const uploadBtn = document.getElementById('uploadBtn');
if (uploadBtn) {
    uploadBtn.addEventListener('click', async () => {
        const button = uploadBtn;
        setLoading(button, true);
        
        const fileInput = document.getElementById('fileInput');
        const file = fileInput.files[0];
        
        if (!file) {
            alert('Please select a file.');
            setLoading(button, false);
            return;
        }

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

                // Display segregated data
                const thead = document.getElementById('segregatedTableHead');
                const tbody = document.getElementById('segregatedTableBody');

                if (thead && tbody && data.summary.segregated_data && data.summary.segregated_data.length > 0) {
                    // Create header
                    const columns = Object.keys(data.summary.segregated_data[0]);
                    thead.innerHTML = '<tr>' + columns.map(col => 
                        `<th>${col.replace(/_/g, ' ').toUpperCase()}</th>`
                    ).join('') + '</tr>';

                    // Create rows
                    tbody.innerHTML = '';
                    data.summary.segregated_data.forEach(row => {
                        const tr = document.createElement('tr');
                        columns.forEach(col => {
                            const td = document.createElement('td');
                            const value = row[col];
                            
                            if (Array.isArray(value)) {
                                td.textContent = value.map(item => 
                                    Array.isArray(item) ? `${item[0]}: ${item[1]}` : item
                                ).join(', ');
                            } else if (typeof value === 'object' && value !== null) {
                                td.textContent = JSON.stringify(value);
                            } else {
                                td.textContent = value !== null && value !== undefined ? value : 'N/A';
                            }
                            
                            tr.appendChild(td);
                        });
                        tbody.appendChild(tr);
                    });

                    // Show container
                    const container = document.getElementById('segregatedDataContainer');
                    if (container) {
                        container.style.display = 'block';
                    }
                }

                showNotification(`✅ File processed: ${data.summary.intrusion_count} intrusions, ${data.summary.benign_count} benign flows`, 'success');
                
                // Refresh blockchain
                loadBlockchainReport();
            }
        } catch (error) {
            console.error('Upload error:', error);
            alert('Error uploading file: ' + error.message);
        } finally {
            setLoading(button, false);
        }
    });
}

// ==================== GENERATE REPORT (CHARTS) ====================
const loadReportBtn = document.getElementById('loadReportBtn');
if (loadReportBtn) {
    loadReportBtn.addEventListener('click', () => {
        const button = loadReportBtn;
        
        if (!window.uploadedData) {
            alert('Please upload a file first.');
            return;
        }
        
        setLoading(button, true);
        
        const data = window.uploadedData;
        
        // Populate summary text
        const summaryText = document.getElementById('summaryText');
        if (summaryText) {
            summaryText.textContent = `Rows: ${data.summary.rows}, Benign: ${data.summary.benign_count}, Intrusions: ${data.summary.intrusion_count}`;
        }
        
        // SAFE: Destroy existing charts if they exist
        if (window.pieChart && typeof window.pieChart.destroy === 'function') {
            window.pieChart.destroy();
            window.pieChart = null;
        }
        if (window.barChart && typeof window.barChart.destroy === 'function') {
            window.barChart.destroy();
            window.barChart = null;
        }
        if (window.lineChart && typeof window.lineChart.destroy === 'function') {
            window.lineChart.destroy();
            window.lineChart = null;
        }
        
        // PIE CHART - Benign vs Intrusion
        const pieCtx = document.getElementById('pieChart');
        if (pieCtx) {
            window.pieChart = new Chart(pieCtx.getContext('2d'), {
                type: 'pie',
                data: {
                    labels: data.graph_data.pie.labels,
                    datasets: [{
                        data: data.graph_data.pie.values,
                        backgroundColor: ['#00ff00', '#ff0000'],
                        borderColor: ['#00ff00', '#ff0000'],
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            labels: {
                                color: '#00ff00',
                                font: { size: 14 }
                            }
                        },
                        title: {
                            display: true,
                            text: 'Benign vs Intrusion Distribution',
                            color: '#00ff00',
                            font: { size: 16, weight: 'bold' }
                        }
                    }
                }
            });
        } else {
            console.error('pieChart canvas not found');
        }
        
        // BAR CHART - Severity Distribution
        const barCtx = document.getElementById('barChart');
        if (barCtx) {
            window.barChart = new Chart(barCtx.getContext('2d'), {
                type: 'bar',
                data: {
                    labels: data.graph_data.bar.labels,
                    datasets: [{
                        label: 'Severity Count',
                        data: data.graph_data.bar.values,
                        backgroundColor: ['#ff0000', '#ff4400', '#ff8800', '#ffcc00'],
                        borderColor: ['#ff0000', '#ff4400', '#ff8800', '#ffcc00'],
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { color: '#00ff00' },
                            grid: { color: 'rgba(0, 255, 0, 0.1)' }
                        },
                        x: {
                            ticks: { color: '#00ff00' },
                            grid: { color: 'rgba(0, 255, 0, 0.1)' }
                        }
                    },
                    plugins: {
                        legend: {
                            labels: {
                                color: '#00ff00',
                                font: { size: 14 }
                            }
                        },
                        title: {
                            display: true,
                            text: 'Threat Severity Distribution',
                            color: '#00ff00',
                            font: { size: 16, weight: 'bold' }
                        }
                    }
                }
            });
        } else {
            console.error('barChart canvas not found');
        }
        
        // LINE CHART - Confidence Trend
        const lineCtx = document.getElementById('lineChart');
        if (lineCtx) {
            window.lineChart = new Chart(lineCtx.getContext('2d'), {
                type: 'line',
                data: {
                    labels: data.graph_data.line.labels,
                    datasets: [{
                        label: 'Detection Confidence',
                        data: data.graph_data.line.values,
                        borderColor: '#ff0000',
                        backgroundColor: 'rgba(255, 0, 0, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 1,
                            ticks: { 
                                color: '#00ff00',
                                callback: function(value) {
                                    return (value * 100).toFixed(0) + '%';
                                }
                            },
                            grid: { color: 'rgba(0, 255, 0, 0.1)' }
                        },
                        x: {
                            ticks: { color: '#00ff00' },
                            grid: { color: 'rgba(0, 255, 0, 0.1)' }
                        }
                    },
                    plugins: {
                        legend: {
                            labels: {
                                color: '#00ff00',
                                font: { size: 14 }
                            }
                        },
                        title: {
                            display: true,
                            text: 'Intrusion Detection Confidence Trend',
                            color: '#00ff00',
                            font: { size: 16, weight: 'bold' }
                        }
                    }
                }
            });
        } else {
            console.error('lineChart canvas not found');
        }
        
        // Show export section
        if (typeof showExportSection === 'function') {
            showExportSection();
        }
        
        setLoading(button, false);
        
        // Scroll to charts
        const reportContent = document.getElementById('reportContent');
        if (reportContent) {
            reportContent.scrollIntoView({ behavior: 'smooth' });
        }
    });
}

// ==================== SIMULATE FLOWS ====================
const simulateBtn = document.getElementById('simulateBtn');
if (simulateBtn) {
    simulateBtn.addEventListener('click', async () => {
        const button = simulateBtn;
        setLoading(button, true);
        
        const resultsDiv = document.getElementById('simulationResults');
        if (resultsDiv) {
            resultsDiv.innerHTML = '<p>⏳ Simulating real-time network flows...</p>';
        }

        try {
            const response = await fetch('http://localhost:5000/simulate');
            const results = await response.json();
            
            if (resultsDiv) {
                resultsDiv.innerHTML = '';
                results.forEach((result, i) => {
                    const p = document.createElement('p');
                    p.className = result.prediction === 'Intrusion' ? 'alert' : 'success';
                    p.textContent = `Flow ${i + 1}: ${result.prediction} - ${result.action}`;
                    if (result.severity) {
                        p.textContent += ` | Severity: ${result.severity}`;
                    }
                    resultsDiv.appendChild(p);
                });
            }
            
            // Refresh blockchain log
            loadBlockchainReport();
        } catch (error) {
            console.error('Simulation error:', error);
            if (resultsDiv) {
                resultsDiv.innerHTML = '<p class="alert">❌ Error simulating flows.</p>';
            }
        } finally {
            setLoading(button, false);
        }
    });
}

// ==================== EXPLANATION (SHAP) ====================
const explainBtn = document.getElementById('explainBtn');
if (explainBtn) {
    explainBtn.addEventListener('click', async () => {
        const button = explainBtn;
        setLoading(button, true);
        
        const flowInput = document.getElementById('flowInput');
        const resultsDiv = document.getElementById('explanationResults');
        
        if (!flowInput) {
            console.error('flowInput element not found');
            setLoading(button, false);
            return;
        }

        try {
            const flow = flowInput.value.split(',').map(Number);
            const response = await fetch('http://localhost:5000/explain', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ flow })
            });

            const data = await response.json();

            if (resultsDiv) {
                resultsDiv.innerHTML = `
                    <h3>${data.prediction === 'Intrusion' ? '🚨 INTRUSION DETECTED' : '✅ Benign Flow'}</h3>
                    <p><strong>Prediction:</strong> ${data.prediction}</p>
                    <p><strong>Confidence:</strong> ${data.confidence}</p>
                    <p><strong>Attack Type:</strong> ${data.attack_type || 'N/A'}</p>
                    <p><strong>Explanation:</strong> ${data.explanation}</p>
                `;
            }
        } catch (error) {
            console.error('Explanation error:', error);
            if (resultsDiv) {
                resultsDiv.innerHTML = '<p class="alert">❌ Error explaining prediction.</p>';
            }
        } finally {
            setLoading(button, false);
        }
    });
}

// ==================== EXPORT FUNCTIONALITY ====================
// function showExportSection() {
//     const exportSection = document.getElementById('exportSection');
//     if (exportSection) {
//         exportSection.style.display = 'block';
//         exportSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
//     }
// }

// async function exportReport(format) {
//     const button = event.target;
//     const originalText = button.innerHTML;
    
//     try {
//         button.innerHTML = '⏳ Generating...';
//         button.disabled = true;

//         const response = await fetch(`http://localhost:5000/export/${format}`);
//         const data = await response.json();

//         if (response.ok) {
//             showNotification(`✅ ${data.filename} generated successfully!`, 'success');
            
//             if (data.download_url) {
//                 const downloadUrl = `http://localhost:5000${data.download_url}`;
//                 const link = document.createElement('a');
//                 link.href = downloadUrl;
//                 link.download = data.filename;
//                 document.body.appendChild(link);
//                 link.click();
//                 document.body.removeChild(link);
//             }

//             if (format === 'all' && data.exports) {
//                 let message = 'All formats exported:\n';
//                 for (const [type, info] of Object.entries(data.exports)) {
//                     message += `\n${info.filename} (${formatBytes(info.size)})`;
//                 }
//                 showNotification(message, 'success');
//             }
//         } else {
//             showNotification(`❌ Export failed: ${data.detail || 'Unknown error'}`, 'error');
//         }
//     } catch (error) {
//         console.error('Export error:', error);
//         showNotification(`❌ Export failed: ${error.message}`, 'error');
//     } finally {
//         button.innerHTML = originalText;
//         button.disabled = false;
//     }
// }

// ==================== BACKGROUND PARTICLES ====================
function createBackgroundParticles() {
    const container = document.getElementById('particles-bg') || document.createElement('div');
    container.id = 'particles-bg';
    if (!document.getElementById('particles-bg')) {
        document.body.appendChild(container);
    }

    const particleCount = 150;
    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.width = Math.random() * 4 + 2 + 'px';
        particle.style.height = particle.style.width;
        particle.style.left = Math.random() * 100 + 'vw';
        particle.style.animationDelay = Math.random() * 10 + 's';
        particle.style.animationDuration = (Math.random() * 5 + 5) + 's';
        container.appendChild(particle);
    }
}

// ==================== CURSOR PARTICLES ====================
const canvas = document.createElement('canvas');
canvas.id = 'cursor-particles';
document.body.appendChild(canvas);
const ctx = canvas.getContext('2d');
canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

class CursorParticle {
    constructor(x, y) {
        this.x = x;
        this.y = y;
        this.size = Math.random() * 3 + 1;
        this.speedX = (Math.random() - 0.5) * 0.5;
        this.speedY = (Math.random() - 0.5) * 0.5;
        this.opacity = 0.2;
        this.color = '#00ff00';
    }

    update() {
        this.x += this.speedX;
        this.y += this.speedY;
        this.opacity -= 0.02;
        this.size *= 0.98;
    }

    draw() {
        ctx.globalAlpha = this.opacity;
        ctx.fillStyle = this.color;
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowColor = this.color;
        ctx.shadowBlur = 2;
    }
}

function handleMouseMove(e) {
    for (let i = 0; i < Math.random() * 2 + 2; i++) {
        particles.push(new CursorParticle(e.clientX, e.clientY));
    }
    if (particles.length > maxParticles) {
        particles = particles.slice(-maxParticles);
    }
}

function animateParticles() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    particles.forEach((p, index) => {
        p.update();
        p.draw();
        if (p.opacity <= 0) {
            particles.splice(index, 1);
        }
    });
    requestAnimationFrame(animateParticles);
}

// ==================== CHATBOT FUNCTIONALITY ====================
const chatbotIcon = document.getElementById('chatbotIcon');
const chatbotPortal = document.getElementById('chatbotPortal');
const closeChat = document.getElementById('closeChat');
const chatInput = document.getElementById('chatInput');
const sendBtn = document.getElementById('sendBtn');
const chatMessages = document.getElementById('chatMessages');

if (chatbotIcon && chatbotPortal) {
    chatbotIcon.addEventListener('click', () => {
        chatbotPortal.style.display = chatbotPortal.style.display === 'flex' ? 'none' : 'flex';
        if (chatbotPortal.style.display === 'flex' && chatInput) {
            chatInput.focus();
        }
    });
}

if (closeChat && chatbotPortal) {
    closeChat.addEventListener('click', () => {
        chatbotPortal.style.display = 'none';
    });
}

if (sendBtn) {
    sendBtn.addEventListener('click', sendMessage);
}

if (chatInput) {
    chatInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });
}

function sendMessage() {
    if (!chatInput || !chatMessages) return;
    
    const message = chatInput.value.trim();
    if (message) {
        const userMsg = document.createElement('div');
        userMsg.className = 'message user';
        userMsg.textContent = message;
        chatMessages.appendChild(userMsg);

        chatInput.value = '';

        setTimeout(() => {
            const botMsg = document.createElement('div');
            botMsg.className = 'message bot';
            botMsg.textContent = 'This is a placeholder response. Integrate with your RAG chatbot for real threat intelligence Q&A!';
            chatMessages.appendChild(botMsg);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }, 1000);

        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
}

// ==================== INITIALIZATION ====================
document.addEventListener('DOMContentLoaded', () => {
    createBackgroundParticles();
    document.addEventListener('mousemove', handleMouseMove);
    animateParticles();
    loadBlockchainReport();

    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });

    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        const particlesBg = document.getElementById('particles-bg');
        if (particlesBg) particlesBg.style.display = 'none';
        document.removeEventListener('mousemove', handleMouseMove);
    }
});


function downloadCSV() {
    let table = document.getElementById("myTable");
    let rows = table.querySelectorAll("tr");
    let csv = [];

    rows.forEach(row => {
        let cols = row.querySelectorAll("td, th");
        let rowData = [];
        cols.forEach(col => rowData.push(col.innerText));
        csv.push(rowData.join(","));
    });

    let csvContent = "data:text/csv;charset=utf-8," + csv.join("\n");
    let hiddenElement = document.createElement("a");
    hiddenElement.href = encodeURI(csvContent);
    hiddenElement.download = "table.csv";
    hiddenElement.click();
}