let threatChart = null;

async function runAnalysis() {
    const url = document.getElementById('urlInput').value;
    const loader = document.getElementById('loader');
    const dashboard = document.getElementById('dashboardGrid');
    
    if (!url) return;

    // Show loading state
    loader.classList.remove('hidden');
    dashboard.classList.add('hidden');

    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url: url})
        });
        const data = await response.json();
        
        updateUI(data);
    } catch (err) {
        console.error("Analysis failed", err);
    } finally {
        loader.classList.add('hidden');
    }
}

function updateUI(data) {
    const dashboard = document.getElementById('dashboardGrid');
    dashboard.classList.remove('hidden');

    // 1. Update Verdict
    const vText = document.getElementById('verdictText');
    const isPhishing = data.prediction.toLowerCase().includes('phishing');
    
    vText.innerText = isPhishing ? "MALICIOUS" : "CLEAN";
    vText.className = isPhishing ? "status-phishing" : "status-safe";
    document.getElementById('confidenceText').innerText = `CONFIDENCE: ${(data.confidence * 100).toFixed(2)}%`;

    // 2. Update WHOIS
    const whoisDiv = document.getElementById('whoisData');
    whoisDiv.innerHTML = Object.entries(data.whois).map(([k, v]) => `
        <div style="display:flex; justify-content:space-between; border-bottom:1px solid #222; padding: 4px 0;">
            <span style="color:#888">${k.toUpperCase()}</span>
            <span>${v}</span>
        </div>
    `).join('');

    // 3. Update Explanation
    const expList = document.getElementById('explanationList');
    expList.innerHTML = data.explanation.map(item => `
        <li style="margin-bottom: 8px; font-family: 'JetBrains Mono'; font-size: 0.9rem;">
            > ${item}
        </li>
    `).join('');

    // 4. Radar Chart
    initChart(data.threat_scores);
}

function initChart(scores) {
    const ctx = document.getElementById('threatChart').getContext('2d');
    
    if (threatChart) threatChart.destroy();

    threatChart = new Chart(ctx, {
        type: 'radar',
        data: {
            labels: ['URL Structure', 'Domain Rep', 'SSL Status', 'Content'],
            datasets: [{
                label: 'Risk Score',
                data: [scores.url_structure, scores.domain_reputation, scores.ssl_status, scores.content_analysis],
                backgroundColor: 'rgba(255, 255, 255, 0.1)',
                borderColor: '#ffffff',
                borderWidth: 2,
                pointBackgroundColor: '#ffffff'
            }]
        },
        options: {
            scales: {
                r: {
                    angleLines: { color: '#333' },
                    grid: { color: '#333' },
                    pointLabels: { color: '#888', font: { size: 10 } },
                    ticks: { display: false, max: 100 }
                }
            },
            plugins: { legend: { display: false } }
        }
    });
}
