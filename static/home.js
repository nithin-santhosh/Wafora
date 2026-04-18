let wafChart = null;
const WAF_API_URL = "/api/stats";
const LOG_API_URL = "/api/live-logs"; // Endpoint for live logs

// Custom colors based on the Dark Green/Copper theme
const CHART_COLORS = {
    valid: 'rgba(40, 180, 99, 0.8)',      // Functional Green
    malicious_signature: 'rgba(255, 151, 67, 0.8)', // Muted Copper/Accent
    malicious_ml: 'rgba(231, 76, 60, 0.8)'     // Functional Red 
};

const TEXT_COLOR = '#DCD7C9'; 
const TOTAL_FONT_COLOR = '#3F4F44'; 
const ML_THRESHOLD = 0.5; 

// --- CUSTOM PLUGIN TO DISPLAY PERCENTAGE LABELS (UNCHANGED) ---
const chartDataLabels = {
    id: 'chartDataLabels',
    afterDatasetsDraw(chart) {
        const { ctx, data } = chart;
        const total = data.datasets[0].data.reduce((a, b) => a + b, 0);

        data.datasets.forEach((dataset, datasetIndex) => {
            ctx.font = 'bold 14px "Orbitron"'; 
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            const meta = chart.getDatasetMeta(datasetIndex);

            dataset.data.forEach((datapoint, index) => {
                if (datapoint > 0 && total > 0) {
                    const arc = meta.data[index];
                    const angle = (arc.startAngle + arc.endAngle) / 2;
                    const radius = arc.outerRadius * 0.75;
                    const x = arc.x + Math.cos(angle) * radius;
                    const y = arc.y + Math.sin(angle) * radius;

                    const percentage = ((datapoint / total) * 100).toFixed(1);
                    if (parseFloat(percentage) < 3.0) return;

                    const color = (index === 0) ? TOTAL_FONT_COLOR : TEXT_COLOR;
                    ctx.fillStyle = color;
                    ctx.fillText(percentage + '%', x, y);
                }
            });
        });
    }
};

// --- CHART CREATION / UPDATE (UNCHANGED) ---
function updateChart(stats) {
    const data = [stats.valid, stats.malicious_signature, stats.malicious_ml]; 

    if (wafChart) {
        wafChart.data.datasets[0].data = data;
        wafChart.update('active');
        return;
    }

    const ctx = document.getElementById('wafPieChart').getContext('2d');
    wafChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Valid Requests', 'Malicious (Signature/Blacklist)', 'Malicious (AI/ML)'],
            datasets: [{
                data: data,
                backgroundColor: [
                    CHART_COLORS.valid,
                    CHART_COLORS.malicious_signature,
                    CHART_COLORS.malicious_ml
                ],
                hoverOffset: 10
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 1000, easing: 'easeOutCubic' },
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: TEXT_COLOR, font: { size: 14, family: 'Orbitron' } }
                },
                title: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(32, 32, 32, 0.9)',
                    bodyColor: TEXT_COLOR,
                    callbacks: {
                        label: function (context) {
                            let label = context.label || '';
                            let value = context.parsed;
                            let sum = context.chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
                            let percentage = ((value * 100) / sum).toFixed(1) + '%';
                            return `${label}: ${percentage} (${value} total)`;
                        }
                    }
                }
            }
        },
        plugins: [chartDataLabels]
    });
}

// --- AUTO FETCH STATS ---
let lastStats = null;

function fetchAndUpdateStats() {
    const url = WAF_API_URL + '?t=' + Date.now(); // cache-busting

    fetch(url)
        .then(response => {
            if (!response.ok) throw new Error(`HTTP status ${response.status} from Stats API`);
            return response.json();
        })
        .then(stats => {
            if (JSON.stringify(stats) !== JSON.stringify(lastStats)) {
                updateChart(stats);
                lastStats = stats;
            }
        })
        .catch(error => {
            console.error("CRITICAL ERROR fetching WAF stats:", error);
        });
}

// --- HTML ESCAPE HELPER ---
function escapeHtml(str) {
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(String(str)));
    return div.innerHTML;
}

// --- LIVE LOG FETCHING ---
function fetchLiveLogs() {
    const url = LOG_API_URL + '?t=' + Date.now(); // cache-busting

    fetch(url)
        .then(response => {
             if (!response.ok) throw new Error(`HTTP status ${response.status} from Logs API`);
             return response.json();
        })
        .then(data => {
            const logContainer = document.getElementById('live-log-container');
            if (logContainer) {
                const maxLogs = 15;
                const logsToDisplay = data.logs.slice(-maxLogs);

                let logHTML = logsToDisplay.map(log => {
                    const match = log.match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - (.*)$/);
                    let timestamp = '';
                    let message = log;

                    if (match) {
                        timestamp = match[1].split(' ')[1].split(',')[0];
                        message = match[2];
                    }

                    let statusClass = "log-pass";
                    let icon = "✅";

                    if (message.includes("BLOCK (403)")) {
                        statusClass = "log-block";
                        icon = "🚨";
                    } else if (message.includes("ERROR")) {
                        statusClass = "log-error";
                        icon = "❌";
                    }

                    return `
                        <div class="log-entry ${statusClass}">
                            <span class="log-icon">${icon}</span>
                            <span class="log-time">[${escapeHtml(timestamp)}]</span>
                            <span class="log-message">${escapeHtml(message)}</span>
                        </div>
                    `;
                }).join('');

                if (logHTML.length === 0) {
                     logHTML = `<p style="text-align: center; color: rgba(220, 215, 201, 0.5);">No recent traffic detected.</p>`;
                }

                logContainer.innerHTML = logHTML;
                logContainer.scrollTop = logContainer.scrollHeight;

                if (!document.getElementById('log-viewer-style')) {
                     const style = document.createElement("style");
                     style.id = 'log-viewer-style';
                     style.innerHTML = `
                        #live-log-container {
                            max-height: 250px;
                            overflow-y: scroll;
                            padding: 0.5rem;
                            border: 1px solid rgba(162, 123, 92, 0.2);
                            border-radius: 8px;
                            background: rgba(0, 0, 0, 0.1);
                            display: flex;
                            flex-direction: column;
                        }
                        .log-entry {
                            padding: 0.25rem 0;
                            border-bottom: 1px dashed rgba(220, 215, 201, 0.1);
                            font-family: 'Courier New', Courier, monospace;
                            font-size: 0.75rem;
                            white-space: pre-wrap;
                            display: flex;
                            gap: 10px;
                        }
                        .log-entry:last-child {
                            border-bottom: none;
                        }
                        .log-icon { font-size: 1rem; }
                        .log-time { color: rgba(220, 215, 201, 0.5); min-width: 60px; }
                        .log-message { flex-grow: 1; }
                        .log-block .log-message { color: #e74c3c; font-weight: bold; }
                        .log-pass .log-message { color: #2ecc71; }
                        .log-error .log-message { color: #95a5a6; }
                     `;
                     document.head.appendChild(style);
                }
            }
        })
        .catch(error => {
            console.error("CRITICAL ERROR fetching live logs:", error);
        });
}

// --- WAF CHECKER LOGIC (UNCHANGED) ---
document.getElementById("submit-btn").addEventListener("click", function () {
    let userInput = document.getElementById("user-input").value;
    let resultsArea = document.getElementById("waf-results-area");
    
    resultsArea.style.display = 'grid';
    document.getElementById("loading").style.display = "block";
    document.getElementById("final-verdict").className = "final-status";
    document.getElementById("final-verdict").innerText = "Final Verdict: Scanning...";
    document.getElementById("layer-signature").className = "layer-item not-checked";
    document.getElementById("signature-status-text").innerText = "Scanning against known attack database (Layer 1)...";
    document.getElementById("layer-ml").className = "layer-item not-checked";
    document.getElementById("ml-status-text").innerText = "Status: Awaiting Layer 1 Verdict...";
    document.getElementById("ml-score-container").style.display = 'none';
    document.getElementById("features-display").style.display = 'none';
    document.getElementById("decision-message").innerText = "WAFity begins processing the request payload.";

    setTimeout(() => {
        fetch("/check_request", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ user_request: userInput })
        })
        .then(async response => {
            if (response.status === 403) {
                return response.json().then(data => {
                    data.http_status = 403;
                    return data;
                });
            } else if (!response.ok) {
                return response.json().then(errorData => {
                    throw new Error(errorData.message || `Server returned unhandled status: ${response.status}`);
                }).catch(() => {
                    throw new Error(`HTTP Error ${response.status}: Failed to get JSON response.`);
                });
            }
            return response.json();
        })
        .then(data => {
            document.getElementById("loading").style.display = "none";
            
            if (data.is_blacklisted) {
                document.getElementById("layer-signature").className = "layer-item blocked";
                document.getElementById("layer-ml").className = "layer-item not-checked";
                document.getElementById("ml-status-text").innerText = "Status: Not required (Fast path block).";
                updateVerdict("malicious", "BLOCKED (Layer 0)", "Request was an exact match to a previously confirmed attack and was dropped instantly.");
                fetchAndUpdateStats();
                fetchLiveLogs();
                return;
            }
            
            const sigLayer = document.getElementById("layer-signature");
            const sigText = document.getElementById("signature-status-text");
            
            if (data.signature_status === "Signature") {
                sigLayer.className = "layer-item blocked";
                sigText.innerHTML = `**BLOCKED!** Direct match found in known threat database (Layer 1).`;
                updateVerdict("malicious", "BLOCKED (Layer 1)", "Request blocked. Signature match indicates a known SQLi or XSS attack. Payload added to Blacklist.");
            } else if (data.signature_status === "obfuscated") {
                sigLayer.className = "layer-item obfuscated";
                sigText.innerHTML = `**SUSPICIOUS!** Obfuscation detected. Passing to AI for deep analysis (Layer 2).`;
            } else {
                sigLayer.className = "layer-item passed";
                sigText.innerHTML = `**CLEARED!** No obvious threats detected.`;
            }
            
            const mlLayer = document.getElementById("layer-ml");
            const mlText = document.getElementById("ml-status-text");
            const mlScoreContainer = document.getElementById("ml-score-container");
            
            if (data.signature_status === "obfuscated") {
                mlScoreContainer.style.display = 'block';
                const score = (data.ml_score * 100).toFixed(2);
                const scoreFill = document.getElementById("ml-score-fill");
                const scoreLabel = document.getElementById("ml-score-label");

                scoreFill.style.width = `${score}%`;
                
                const isBlockedByML = data.status === "malicious"; 
                if (isBlockedByML) {
                    scoreFill.style.background = 'linear-gradient(90deg, #e74c3c, #cc3333)';
                } else {
                    scoreFill.style.background = 'linear-gradient(90deg, #2ecc71, #189e4c)';
                }

                scoreLabel.innerHTML = `ML Confidence: ${score}% (Threshold: ${ML_THRESHOLD * 100}%)`;
                
                if (isBlockedByML) {
                    mlLayer.className = "layer-item blocked";
                    mlText.innerHTML = `**BLOCKED!** AI confidence (${score}%) exceeds threshold. Threat confirmed.`;
                    updateVerdict("malicious", "BLOCKED (Layer 2)", `AI identified an anomalous attack. Request dropped and payload added to Blacklist.`);
                } else {
                    mlLayer.className = "layer-item passed";
                    mlText.innerHTML = `**CLEARED!** AI confidence (${score}%) is below threshold. Request approved.`;
                    updateVerdict("valid", "VALID (Passed)", "Request was suspicious but AI analysis confirmed it is safe. Passed to application.");
                }
                
                if (!isBlockedByML) {
                    displayFeatures(data.features);
                }

            } else if (data.signature_status === "Valid") {
                mlLayer.className = "layer-item not-checked";
                mlText.innerHTML = `**Skipped!** Request cleared by Signature Check (Layer 1).`;
                updateVerdict("valid", "VALID (Passed)", "Request passed all security layers. Passed to application.");
            }
            
            fetchAndUpdateStats();
            fetchLiveLogs();
        })
        .catch(error => {
            console.error("Error:", error);
            document.getElementById("loading").style.display = "none";
            updateVerdict("error", "WAF Error", error.message);
        });
    }, 500);
});

function updateVerdict(status, title, message) {
    const verdictBox = document.getElementById("final-verdict");
    verdictBox.className = `final-status status-${status}`;
    verdictBox.innerHTML = `Final Verdict: ${title}`;
    document.getElementById("decision-message").innerText = message;
}

function displayFeatures(features) {
    if (!features || features.length === 0) {
        document.getElementById("features-display").style.display = 'none';
        return;
    }

    const featureNames = [
        "URI_Length", "GET_Length", "POST_Length", 
        "URI_Entropy", "GET_Entropy", "POST_Entropy",
        "Numeric_Text_Ratio", "Special_Char_Count"
    ];
    
    let tableBody = `<tr><th>Feature</th><th>Value</th></tr>`;

    features.forEach((value, index) => {
        let displayValue = (typeof value === 'number') ? value.toFixed(4) : value;
        tableBody += `<tr><td>${featureNames[index]}</td><td>${displayValue}</td></tr>`;
    });

    document.getElementById("features-table-content").innerHTML = tableBody;
    document.getElementById("features-display").style.display = 'block';
}

// --- TIP NAVIGATION + AUTO REFRESH ---
document.addEventListener("DOMContentLoaded", function () {
    const prevButton = document.querySelector(".tip-nav-btn.prev");
    const nextButton = document.querySelector(".tip-nav-btn.next");
    const slides = document.querySelectorAll(".tip-slide");
    let currentIndex = 0;

    function changeSlide() {
        slides.forEach((slide, index) => {
            slide.classList.remove("active");
            if (index === currentIndex) {
                slide.style.opacity = 1;
                slide.style.transform = 'translateX(0)';
                slide.classList.add("active");
            } else {
                if (index > currentIndex) {
                    slide.style.transform = 'translateX(100%)';
                } else {
                    slide.transform = 'translateX(-100%)';
                }
            }
        });
    }

    prevButton.addEventListener("click", () => {
        currentIndex = (currentIndex === 0) ? slides.length - 1 : currentIndex - 1;
        changeSlide();
    });

    nextButton.addEventListener("click", () => {
        currentIndex = (currentIndex === slides.length - 1) ? 0 : currentIndex + 1;
        changeSlide();
    });

    slides.forEach((slide, index) => {
        if (index === 0) {
            slide.classList.add("active");
            slide.style.transform = 'translateX(0)';
        } else {
            slide.style.transform = 'translateX(100%)';
        }
    });

    // --- Polling Initialization ---
    (function startPolling() {
        fetchAndUpdateStats();
        fetchLiveLogs();

        setTimeout(startPolling, 5000);
    })();

    // Force update when tab becomes visible (in case of throttling)
    document.addEventListener('visibilitychange', function() {
        if (!document.hidden) {
            fetchAndUpdateStats();
            fetchLiveLogs();
        }
    });
});
