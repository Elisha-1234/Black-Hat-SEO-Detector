document.getElementById('scanBtn').addEventListener('click', () => {
    let btn = document.getElementById('scanBtn');
    let resultDiv = document.getElementById('result');
    
    btn.innerText = "Scanning Server & AI Models...";
    btn.disabled = true;
    
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        let currentUrl = tabs[0].url;
        
        fetch('http://127.0.0.1:5000/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: currentUrl })
        })
        .then(response => response.json())
        .then(data => {
            resultDiv.style.display = "block";
            let color = data.status.includes('Critical') || data.status.includes('Failed') ? '#ff3333' : '#00ff66';
            if (data.status.includes('Suspicious')) color = '#ffaa00';
            
            //To remove unnecessary words from the resulting results
            let cleanSummary = data.genai_summary.replace("aY4 - ", "").replace("aY4-", "").trim();

            resultDiv.innerHTML = `
                <div class="status" style="color: ${color}">${data.status}</div>
                <div style="background: rgba(217, 70, 239, 0.1); border-left: 3px solid #d946ef; padding: 10px; margin-bottom: 15px; border-radius: 4px;">
                    <div style="color: #d946ef; font-weight: bold; font-size: 12px; margin-bottom: 5px;"> GenAI Verdict:</div>
                    <div style="color: #fff; font-size: 12px; font-style: italic;">"${cleanSummary}"</div>
                </div>
                <div style="color: #00e5ff; font-weight: bold; margin-bottom: 5px; font-size: 12px;">Category:</div>
                <div style="color: #cbd5e1; margin-bottom: 10px; font-size: 12px;">${data.category}</div>
                <div style="color: #00e5ff; font-weight: bold; margin-bottom: 5px; font-size: 12px;">Advisory:</div>
                <div style="color: #cbd5e1; font-size: 12px;">${data.advice}</div>
            `;
            btn.innerText = "Scan Complete";
            btn.disabled = false;
        })
        .catch(err => {
            resultDiv.style.display = "block";
            resultDiv.innerHTML = `<span style="color:#ff3333;">Error: Ensure Flask server is running!</span>`;
            btn.innerText = "Scan Failed";
            btn.disabled = false;
        });
    });
});