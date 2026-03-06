// Initialize Globe
const globe = Globe()
    (document.getElementById('globeViz'))
    .globeImageUrl('//unpkg.com/three-globe/example/img/earth-night.jpg')
    .bumpImageUrl('//unpkg.com/three-globe/example/img/earth-topology.png')
    .backgroundColor('rgba(0,0,0,0)')
    .showAtmosphere(true)
    .atmosphereColor('#00f2ff')
    .atmosphereDaylightAlpha(0.1);

// Initialize Chart
const ctx = document.getElementById('threatChart').getContext('2d');
const threatChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
        labels: ['Safe', 'Phishing', 'Malware', 'Suspicious'],
        datasets: [{
            data: [65, 15, 10, 10],
            backgroundColor: ['#00ffcc', '#ff3333', '#ff9900', '#9900ff'],
            borderWidth: 0
        }]
    },
    options: { plugins: { legend: { labels: { color: '#fff' } } } }
});

// Fetch Dashboard Data
async function updateDashboard() {
    const response = await fetch('/api/stats');
    const data = await response.json();

    // Update Globe Points
    globe.pointsData(data.threat_map)
        .pointAltitude(0.1)
        .pointColor('color')
        .pointRadius(0.5);

    // Update Text Stats
    document.getElementById('totalScanned').innerText = data.total_scanned.toLocaleString();
    document.getElementById('totalThreats').innerText = data.threats_detected.toLocaleString();
    document.getElementById('activeNodes').innerText = data.active_nodes;
}

// URL Analysis Function
async function analyzeURL() {
    const url = document.getElementById('urlInput').value;
    const btn = document.querySelector('button');
    const resultBox = document.getElementById('resultBox');
    
    if(!url) return alert("Please enter a URL");

    btn.innerText = "SCANNING...";
    
    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url: url})
        });
        const result = await response.json();
        
        resultBox.classList.remove('hidden');
        const pred = document.getElementById('prediction');
        
        if(result.prediction === 'phishing' || result.label === '1') {
            pred.innerText = "🚨 PHISHING DETECTED";
            pred.className = "text-2xl font-bold text-red-500 animate-pulse";
        } else {
            pred.innerText = "✅ LINK SECURE";
            pred.className = "text-2xl font-bold text-green-500";
        }
    } catch (e) {
        console.error(e);
    } finally {
        btn.innerText = "SCAN LINK";
    }
}

// Run on load
updateDashboard();
setInterval(updateDashboard, 5000); // Auto-refresh every 5 seconds
