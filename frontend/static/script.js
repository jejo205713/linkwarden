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
        domainAge.innerText = (data.domain_age_days && data.domain_age_days !== "Unknown")
            ? data.domain_age_days + " days"
            : "Unknown";
        registrar.innerText = data.registrar || "Unknown";
        redirectCount.innerText = data.redirect_count || 0;

        reasonsList.innerHTML = "";
        (data.reasons || []).forEach(reason => {
            const li = document.createElement("li");
            li.innerText = reason;
            reasonsList.appendChild(li);
        });
        (data.triggered_rules || []).forEach(rule => {
            const li = document.createElement("li");
            li.innerText = "[rule] " + rule;
            li.style.opacity = "0.75";
            reasonsList.appendChild(li);
        });

        // Trigger Visuals — radar uses real backend risk_factors.
        generateThreatChart(data.status, data.risk_factors || {});
        traceGeo(data.expanded_url);
    }

    function generateThreatChart(status, riskFactors) {
        const ctx = document.getElementById('threatChart').getContext('2d');
        if (threatChartInstance) threatChartInstance.destroy();

        const labels = ['URL Structure', 'Domain Trust', 'Social Eng.', 'Technical Obfusc.'];
        const dataScores = [
            riskFactors.url_structure || 0,
            riskFactors.domain_trust || 0,
            riskFactors.social_engineering || 0,
            riskFactors.technical_obfuscation || 0,
        ];

        const color = status === "SAFE" ? "#00ff66"
                    : status === "PHISHING" ? "#ff3333"
                    : "#ffaa00";

        threatChartInstance = new Chart(ctx, {
            type: 'radar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Risk vector (0-100)',
                    data: dataScores,
                    backgroundColor: color + "33",
                    borderColor: color,
                    borderWidth: 2,
                    pointBackgroundColor: color
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: { r: { suggestedMin: 0, suggestedMax: 100, ticks: { display: false } } },
                plugins: { legend: { labels: { color: '#888', font: { size: 11 } } } }
            }
        });
    }

    async function traceGeo(url) {
        geoIp.innerText = "resolving...";
        geoLoc.innerText = "...";
        try {
            const response = await fetch("/api/geo", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url }),
            });
            const data = await response.json();
            geoIp.innerText = data.ip || "—";
            geoLoc.innerText = data.ok ? `${data.city}, ${data.country}` : "Lookup failed";

            // Project (lat, lon) onto the 1000x500 viewBox of the world-map SVG.
            // Equirectangular: x = (lon + 180) * (1000/360); y = (90 - lat) * (500/180)
            const x = ((data.lon || 0) + 180) * (1000 / 360);
            const y = (90 - (data.lat || 0)) * (500 / 180);
            geoTarget.setAttribute("transform", `translate(${x.toFixed(1)}, ${y.toFixed(1)})`);
        } catch (err) {
            console.error("Geo lookup failed:", err);
            geoIp.innerText = "—";
            geoLoc.innerText = "Lookup failed";
        }
    }
});