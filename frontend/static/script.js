document.addEventListener("DOMContentLoaded", () => {
    const analyzeBtn = document.getElementById("analyzeBtn");
    const urlInput = document.getElementById("urlInput");
    const loader = document.getElementById("loader");
    const dashboardGrid = document.getElementById("dashboardGrid");
    const verdictWrapper = document.getElementById("verdictWrapper");

    const verdictText = document.getElementById("verdictText");
    const riskScore = document.getElementById("riskScore");
    const expandedUrl = document.getElementById("expandedUrl");
    const domainAge = document.getElementById("domainAge");
    const registrar = document.getElementById("registrar");
    const redirectCount = document.getElementById("redirectCount");
    const reasonsList = document.getElementById("reasonsList");
    
    // Map elements
    const geoTarget = document.getElementById("geoTarget");
    const geoIp = document.getElementById("geoIp");
    const geoLoc = document.getElementById("geoLoc");

    let threatChartInstance = null;

    urlInput.addEventListener("keypress", (e) => { if (e.key === "Enter") analyzeBtn.click(); });

    analyzeBtn.addEventListener("click", async () => {
        const url = urlInput.value.trim();
        if (!url) return;

        dashboardGrid.classList.add("hidden");
        loader.classList.remove("hidden");
        reasonsList.innerHTML = "";

        try {
            const response = await fetch("/api/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: url })
            });
            const data = await response.json();
            if (response.ok) updateDashboard(data);
            else { alert("Error: " + data.error); loader.classList.add("hidden"); }
        } catch (error) {
            console.error("Backend error:", error);
            loader.classList.add("hidden");
        }
    });

    function updateDashboard(data) {
        loader.classList.add("hidden");
        dashboardGrid.classList.remove("hidden");

        verdictText.innerText = data.status;
        verdictText.className = "";
        
        if (data.status === "SAFE") {
            verdictText.classList.add("status-safe");
            verdictWrapper.style.borderTopColor = "var(--safe)";
        } else if (data.status === "PHISHING") {
            verdictText.classList.add("status-phishing");
            verdictWrapper.style.borderTopColor = "var(--phishing)";
        } else {
            verdictText.classList.add("status-suspicious");
            verdictWrapper.style.borderTopColor = "var(--suspicious)";
        }

        riskScore.innerText = `Risk Score: ${data.confidence_score}%`;
        expandedUrl.innerText = data.expanded_url;
        domainAge.innerText = data.domain_age_days ? data.domain_age_days + " days" : "Hidden";
        registrar.innerText = data.registrar || "Unknown";
        redirectCount.innerText = data.redirect_count || 0;

        reasonsList.innerHTML = "";
        (data.reasons || []).forEach(reason => {
            const li = document.createElement("li");
            li.innerText = reason;
            reasonsList.appendChild(li);
        });

        // Trigger Visuals
        generateThreatChart(data.status, data.confidence_score);
        simulateGeoTrace(data.expanded_url);
    }

    // --- ADDED MISSING FUNCTIONS ---
    function generateThreatChart(status, score) {
        const ctx = document.getElementById('threatChart').getContext('2d');
        if (threatChartInstance) threatChartInstance.destroy();

        let dataScores = status === "SAFE" ? [10, 5, 20, 0, 15, 10] : [score, score*0.8, score*0.9, score*0.7, score, 80];
        let color = status === "SAFE" ? "#00ff66" : "#ff3333";

        threatChartInstance = new Chart(ctx, {
            type: 'radar',
            data: {
                labels: ['Lexical', 'DNS', 'IP', 'SSL', 'Age', 'Redirects'],
                datasets: [{ data: dataScores, backgroundColor: color + "33", borderColor: color, borderWidth: 1 }]
            },
            options: { responsive: true, maintainAspectRatio: false, scales: { r: { ticks: { display: false } } } }
        });
    }

    function simulateGeoTrace(url) {
        const locations = [
            { loc: "Frankfurt, DE", ip: "18.192.45.1", x: 520, y: 140 },
            { loc: "Ashburn, VA", ip: "54.210.11.2", x: 260, y: 160 },
            { loc: "Singapore", ip: "47.100.89.3", x: 780, y: 260 }
        ];
        const target = locations[url.length % locations.length];
        geoIp.innerText = target.ip;
        geoLoc.innerText = target.loc;
        geoTarget.setAttribute("transform", `translate(${target.x}, ${target.y})`);
    }
});