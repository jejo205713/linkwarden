document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("incidentForm");
    const reportCard = document.getElementById("reportCard");
    const successCard = document.getElementById("successCard");
    const submitBtn = document.getElementById("submitReportBtn");

    if (!form) return;

    form.addEventListener("submit", async (event) => {
        event.preventDefault();

        const payload = {
            name: document.getElementById("victimName").value.trim(),
            email: document.getElementById("victimEmail").value.trim(),
            phishing_url: document.getElementById("phishingUrl").value.trim(),
            incident_date: document.getElementById("incidentDate").value,
            financial_loss: document.getElementById("financialLoss").value,
            details: document.getElementById("incidentDetails").value.trim(),
        };

        if (!payload.email || !payload.phishing_url) {
            alert("Email and Phishing URL are required.");
            return;
        }

        submitBtn.disabled = true;
        submitBtn.innerText = "TRANSMITTING...";

        try {
            const response = await fetch("/api/report", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });
            const data = await response.json();

            if (response.ok && data.status === "success") {
                reportCard.classList.add("hidden");
                successCard.classList.remove("hidden");
            } else {
                alert("Submission failed: " + (data.error || "unknown error"));
                submitBtn.disabled = false;
                submitBtn.innerText = "SUBMIT ENCRYPTED REPORT";
            }
        } catch (err) {
            console.error("Report submit failed:", err);
            alert("Network error — could not submit report.");
            submitBtn.disabled = false;
            submitBtn.innerText = "SUBMIT ENCRYPTED REPORT";
        }
    });
});
