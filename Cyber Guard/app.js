/**
 * CYBERGUARD APPLICATION CONTROLLER
 * Connects UI interactions, DOM events, PhishingEngine, and PasswordEngine
 */

document.addEventListener('DOMContentLoaded', () => {

    // ==========================================
    // 1. NAVIGATION & TAB SYSTEM
    // ==========================================
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    const subtabBtns = document.querySelectorAll('.subtab-btn');
    const subcontents = document.querySelectorAll('.subcontent');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => {
                b.classList.remove('active');
                b.setAttribute('aria-selected', 'false');
            });
            tabContents.forEach(c => c.classList.remove('active'));

            btn.classList.add('active');
            btn.setAttribute('aria-selected', 'true');
            const targetId = btn.getAttribute('data-tab');
            const targetTab = document.getElementById(targetId);
            if (targetTab) targetTab.classList.add('active');
        });
    });

    subtabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            subtabBtns.forEach(b => b.classList.remove('active'));
            subcontents.forEach(c => c.classList.remove('active'));

            btn.classList.add('active');
            const targetId = btn.getAttribute('data-subnav');
            const targetSubcontent = document.getElementById(targetId);
            if (targetSubcontent) targetSubcontent.classList.add('active');
        });
    });


    // ==========================================
    // 2. PHISHING URL SCANNER CONTROLLER
    // ==========================================
    const urlInput = document.getElementById('urlInput');
    const scanUrlBtn = document.getElementById('scanUrlBtn');
    const urlResults = document.getElementById('urlResults');
    const urlGaugeFill = document.getElementById('urlGaugeFill');
    const urlRiskScore = document.getElementById('urlRiskScore');
    const urlVerdict = document.getElementById('urlVerdict');
    const urlSummaryText = document.getElementById('urlSummaryText');
    const urlHeuristicsList = document.getElementById('urlHeuristicsList');
    const urlRecText = document.getElementById('urlRecText');
    const metaProtocol = document.getElementById('metaProtocol');
    const metaDomain = document.getElementById('metaDomain');
    const metaTLD = document.getElementById('metaTLD');

    function executeUrlScan(inputVal) {
        if (!inputVal) return;
        const result = PhishingEngine.analyzeUrl(inputVal);

        if (result.error) {
            showToast(result.error);
            return;
        }

        urlResults.classList.remove('hidden');

        // Update Score & Gauge Meter
        urlRiskScore.textContent = result.riskScore;
        
        // Gauge circumference is ~534px for r=85
        const offset = 534 - (534 * (result.riskScore / 100));
        urlGaugeFill.style.strokeDashoffset = offset;

        // Color based on risk
        let gaugeColor = 'var(--color-safe)';
        let badgeClass = 'safe';

        if (result.riskScore >= 75) {
            gaugeColor = 'var(--color-danger)';
            badgeClass = 'critical';
        } else if (result.riskScore >= 45) {
            gaugeColor = 'var(--color-caution)';
            badgeClass = 'high';
        } else if (result.riskScore >= 20) {
            gaugeColor = 'var(--accent-cyan)';
            badgeClass = 'low';
        }

        urlGaugeFill.style.stroke = gaugeColor;
        urlVerdict.textContent = result.verdict;
        urlVerdict.className = `verdict-badge ${badgeClass}`;
        urlSummaryText.textContent = result.summary;

        // Meta
        metaProtocol.textContent = result.protocol ? result.protocol.toUpperCase() : '-';
        metaDomain.textContent = result.hostname || '-';
        metaTLD.textContent = result.tld || '-';

        // Heuristics List
        urlHeuristicsList.innerHTML = '';
        result.heuristics.forEach(h => {
            const item = document.createElement('div');
            item.className = 'heuristic-item';
            item.innerHTML = `
                <div class="item-icon ${h.type}"><i class="fa-solid ${h.icon}"></i></div>
                <div class="item-content">
                    <h4>${h.title}</h4>
                    <p>${h.desc}</p>
                </div>
            `;
            urlHeuristicsList.appendChild(item);
        });

        urlRecText.textContent = result.recommendation;
    }

    scanUrlBtn.addEventListener('click', () => executeUrlScan(urlInput.value));
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') executeUrlScan(urlInput.value);
    });

    // Preset URL Chip Buttons
    document.querySelectorAll('.preset-btn[data-url]').forEach(btn => {
        btn.addEventListener('click', () => {
            const presetUrl = btn.getAttribute('data-url');
            urlInput.value = presetUrl;
            executeUrlScan(presetUrl);
        });
    });


    // ==========================================
    // 3. PHISHING EMAIL / SMS CONTROLLER
    // ==========================================
    const emailInput = document.getElementById('emailInput');
    const analyzeEmailBtn = document.getElementById('analyzeEmailBtn');
    const emailResults = document.getElementById('emailResults');
    const emailRiskScore = document.getElementById('emailRiskScore');
    const emailVerdict = document.getElementById('emailVerdict');
    const emailSummaryText = document.getElementById('emailSummaryText');
    const emailIndicatorsList = document.getElementById('emailIndicatorsList');

    function executeEmailScan(textVal) {
        const result = PhishingEngine.analyzeEmail(textVal);
        if (result.error) {
            showToast(result.error);
            return;
        }

        emailResults.classList.remove('hidden');
        emailRiskScore.textContent = result.riskScore;
        emailSummaryText.textContent = result.summary;

        let badgeClass = 'safe';
        if (result.riskScore >= 60) badgeClass = 'critical';
        else if (result.riskScore >= 30) badgeClass = 'suspicious';

        emailVerdict.textContent = result.verdict;
        emailVerdict.className = `verdict-badge ${badgeClass}`;

        emailIndicatorsList.innerHTML = '';
        if (result.indicators.length === 0) {
            emailIndicatorsList.innerHTML = `
                <div class="heuristic-item">
                    <div class="item-icon safe"><i class="fa-solid fa-circle-check"></i></div>
                    <div class="item-content">
                        <h4>No Threat Indicators Found</h4>
                        <p>The text does not contain common phishing triggers, artificial urgency, or high-risk solicitation.</p>
                    </div>
                </div>
            `;
        } else {
            result.indicators.forEach(ind => {
                const item = document.createElement('div');
                item.className = 'heuristic-item';
                item.innerHTML = `
                    <div class="item-icon ${ind.type}"><i class="fa-solid fa-triangle-exclamation"></i></div>
                    <div class="item-content">
                        <h4>${ind.title}</h4>
                        <p>${ind.desc}</p>
                    </div>
                `;
                emailIndicatorsList.appendChild(item);
            });
        }
    }

    analyzeEmailBtn.addEventListener('click', () => executeEmailScan(emailInput.value));

    // Preset Email Buttons
    document.getElementById('samplePhishEmail1').addEventListener('click', () => {
        const text = "URGENT NOTICE: Your Bank Account has been temporarily restricted due to unauthorized login attempts. Click here immediately to verify your SSN and credit card details within 24 hours or your funds will be permanently blocked: http://bank-security-verify.top/login";
        emailInput.value = text;
        executeEmailScan(text);
    });

    document.getElementById('samplePhishEmail2').addEventListener('click', () => {
        const text = "CONGRATULATIONS! You have been selected to win a $1,000 Amazon Gift Card! Dear Customer, click here right now to claim your gift card prize before it expires in 12 hours: http://amazon-prize-winner.xyz/claim";
        emailInput.value = text;
        executeEmailScan(text);
    });

    document.getElementById('sampleSafeEmail').addEventListener('click', () => {
        const text = "Hi Team, Please review the attached quarterly presentation slides before our team sync meeting tomorrow at 10 AM. Let me know if you have any questions or agenda additions.";
        emailInput.value = text;
        executeEmailScan(text);
    });


    // ==========================================
    // 4. PASSWORD STRENGTH ANALYZER CONTROLLER
    // ==========================================
    const pwdInput = document.getElementById('pwdInput');
    const togglePwdVisibility = document.getElementById('togglePwdVisibility');
    const eyeIcon = document.getElementById('eyeIcon');
    const pwdRatingBadge = document.getElementById('pwdRatingBadge');
    const pwdStrengthBar = document.getElementById('pwdStrengthBar');
    const statEntropy = document.getElementById('statEntropy');
    const statLength = document.getElementById('statLength');
    const statBreach = document.getElementById('statBreach');
    const statVariety = document.getElementById('statVariety');
    const crackOnline = document.getElementById('crackOnline');
    const crackFastOnline = document.getElementById('crackFastOnline');
    const crackOfflineGpu = document.getElementById('crackOfflineGpu');
    const crackQuantum = document.getElementById('crackQuantum');
    const pwdChecklist = document.getElementById('pwdChecklist');

    // Show/Hide password toggle
    togglePwdVisibility.addEventListener('click', () => {
        if (pwdInput.type === 'password') {
            pwdInput.type = 'text';
            eyeIcon.className = 'fa-solid fa-eye-slash';
        } else {
            pwdInput.type = 'password';
            eyeIcon.className = 'fa-solid fa-eye';
        }
    });

    function updatePasswordAnalysis(pwd) {
        const evalRes = PasswordEngine.evaluatePassword(pwd);

        // Strength Bar & Badge
        pwdRatingBadge.textContent = evalRes.rating;
        pwdStrengthBar.style.width = `${evalRes.score}%`;

        let barColor = 'var(--color-danger)';
        if (evalRes.score >= 80) barColor = 'var(--color-safe)';
        else if (evalRes.score >= 50) barColor = 'var(--accent-cyan)';
        else if (evalRes.score >= 30) barColor = 'var(--color-caution)';

        pwdStrengthBar.style.backgroundColor = barColor;
        pwdRatingBadge.style.color = barColor;

        // Stats
        statEntropy.textContent = `${evalRes.entropy} bits`;
        statLength.textContent = `${evalRes.length} chars`;
        
        if (evalRes.isBreached) {
            statBreach.textContent = 'BREACHED!';
            statBreach.style.color = 'var(--color-danger)';
        } else {
            statBreach.textContent = 'SAFE';
            statBreach.style.color = 'var(--color-safe)';
        }

        statVariety.textContent = `${evalRes.varietyCount} / 4`;

        // Crack Times
        crackOnline.textContent = evalRes.crackTimes.online;
        crackFastOnline.textContent = evalRes.crackTimes.fastOnline;
        crackOfflineGpu.textContent = evalRes.crackTimes.offlineGpu;
        crackQuantum.textContent = evalRes.crackTimes.quantum;

        // Checklist
        pwdChecklist.innerHTML = '';
        evalRes.checklist.forEach(item => {
            const li = document.createElement('li');
            const iconClass = item.pass ? 'fa-solid fa-check pass' : 'fa-solid fa-xmark fail';
            li.innerHTML = `<i class="${iconClass}"></i> ${item.text}`;
            pwdChecklist.appendChild(li);
        });
    }

    pwdInput.addEventListener('input', (e) => updatePasswordAnalysis(e.target.value));

    // Preset password sample buttons
    document.querySelectorAll('.pwd-sample-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const samplePwd = btn.getAttribute('data-pwd');
            pwdInput.value = samplePwd;
            updatePasswordAnalysis(samplePwd);
        });
    });


    // ==========================================
    // 5. SECURE PASSWORD GENERATOR CONTROLLER
    // ==========================================
    const genModeRandom = document.getElementById('genModeRandom');
    const genModePassphrase = document.getElementById('genModePassphrase');
    const randomGenControls = document.getElementById('randomGenControls');
    const passphraseGenControls = document.getElementById('passphraseGenControls');
    const genOutputText = document.getElementById('genOutputText');
    const generateBtn = document.getElementById('generateBtn');
    const copyGenBtn = document.getElementById('copyGenBtn');

    // Controls
    const genLengthRange = document.getElementById('genLengthRange');
    const genLengthVal = document.getElementById('genLengthVal');
    const chkUpper = document.getElementById('chkUpper');
    const chkLower = document.getElementById('chkLower');
    const chkNumbers = document.getElementById('chkNumbers');
    const chkSymbols = document.getElementById('chkSymbols');
    const chkAmbiguous = document.getElementById('chkAmbiguous');

    const phraseWordsRange = document.getElementById('phraseWordsRange');
    const phraseWordsVal = document.getElementById('phraseWordsVal');
    const phraseSeparatorSelect = document.getElementById('phraseSeparatorSelect');
    const chkPhraseCapitalize = document.getElementById('chkPhraseCapitalize');
    const chkPhraseNumber = document.getElementById('chkPhraseNumber');

    let currentGenMode = 'random';

    // Mode Toggle
    genModeRandom.addEventListener('click', () => {
        currentGenMode = 'random';
        genModeRandom.classList.add('active');
        genModePassphrase.classList.remove('active');
        randomGenControls.classList.remove('hidden');
        passphraseGenControls.classList.add('hidden');
        triggerGeneration();
    });

    genModePassphrase.addEventListener('click', () => {
        currentGenMode = 'passphrase';
        genModePassphrase.classList.add('active');
        genModeRandom.classList.remove('active');
        passphraseGenControls.classList.remove('hidden');
        randomGenControls.classList.add('hidden');
        triggerGeneration();
    });

    genLengthRange.addEventListener('input', (e) => {
        genLengthVal.textContent = e.target.value;
        triggerGeneration();
    });

    phraseWordsRange.addEventListener('input', (e) => {
        phraseWordsVal.textContent = `${e.target.value} words`;
        triggerGeneration();
    });

    [chkUpper, chkLower, chkNumbers, chkSymbols, chkAmbiguous, phraseSeparatorSelect, chkPhraseCapitalize, chkPhraseNumber].forEach(el => {
        el.addEventListener('change', () => triggerGeneration());
    });

    function triggerGeneration() {
        let generated = '';
        if (currentGenMode === 'random') {
            generated = PasswordEngine.generateRandomPassword({
                length: parseInt(genLengthRange.value, 10),
                useUpper: chkUpper.checked,
                useLower: chkLower.checked,
                useNumbers: chkNumbers.checked,
                useSymbols: chkSymbols.checked,
                avoidAmbiguous: chkAmbiguous.checked
            });
        } else {
            generated = PasswordEngine.generatePassphrase({
                wordCount: parseInt(phraseWordsRange.value, 10),
                separator: phraseSeparatorSelect.value,
                capitalize: chkPhraseCapitalize.checked,
                includeNumber: chkPhraseNumber.checked
            });
        }

        genOutputText.textContent = generated;
    }

    generateBtn.addEventListener('click', triggerGeneration);

    copyGenBtn.addEventListener('click', () => {
        const textToCopy = genOutputText.textContent;
        if (textToCopy && textToCopy !== 'Click Generate') {
            navigator.clipboard.writeText(textToCopy).then(() => {
                showToast('Password copied to clipboard!');
            }).catch(() => {
                showToast('Copied password!');
            });
        }
    });


    // ==========================================
    // 6. PHISHING QUIZ SIMULATOR CONTROLLER
    // ==========================================
    let currentQuizIndex = 0;
    let quizScore = 0;
    let quizStreak = 0;

    const quizScoreVal = document.getElementById('quizScoreVal');
    const quizStreakVal = document.getElementById('quizStreakVal');
    const quizProgressVal = document.getElementById('quizProgressVal');
    
    const scenarioCategory = document.getElementById('scenarioCategory');
    const scenarioTitle = document.getElementById('scenarioTitle');
    const mockSender = document.getElementById('mockSender');
    const mockSubject = document.getElementById('mockSubject');
    const mockBody = document.getElementById('mockBody');

    const choosePhishBtn = document.getElementById('choosePhishBtn');
    const chooseLegitBtn = document.getElementById('chooseLegitBtn');
    const quizFeedbackBox = document.getElementById('quizFeedbackBox');
    const feedbackHeader = document.getElementById('feedbackHeader');
    const feedbackExplanation = document.getElementById('feedbackExplanation');
    const nextQuestionBtn = document.getElementById('nextQuestionBtn');

    function loadQuizScenario(index) {
        const scenarios = PhishingEngine.QUIZ_SCENARIOS;
        const current = scenarios[index];

        quizProgressVal.textContent = `${index + 1} / ${scenarios.length}`;
        scenarioCategory.textContent = current.category;
        scenarioTitle.textContent = current.title;
        mockSender.textContent = current.sender;
        mockSubject.textContent = current.subject;
        mockBody.textContent = current.body;

        quizFeedbackBox.classList.add('hidden');
        choosePhishBtn.disabled = false;
        chooseLegitBtn.disabled = false;
    }

    function handleQuizAnswer(userChoiceIsPhish) {
        const scenarios = PhishingEngine.QUIZ_SCENARIOS;
        const current = scenarios[currentQuizIndex];

        const isCorrect = (userChoiceIsPhish === current.isPhishing);

        choosePhishBtn.disabled = true;
        chooseLegitBtn.disabled = true;

        if (isCorrect) {
            quizScore += 100;
            quizStreak += 1;
            feedbackHeader.textContent = 'CORRECT SPOT!';
            feedbackHeader.className = 'feedback-header correct';
        } else {
            quizStreak = 0;
            feedbackHeader.textContent = 'INCORRECT IDENTIFICATION!';
            feedbackHeader.className = 'feedback-header incorrect';
        }

        quizScoreVal.textContent = quizScore;
        quizStreakVal.textContent = `🔥 ${quizStreak}`;

        feedbackExplanation.textContent = current.explanation;
        quizFeedbackBox.classList.remove('hidden');
    }

    choosePhishBtn.addEventListener('click', () => handleQuizAnswer(true));
    chooseLegitBtn.addEventListener('click', () => handleQuizAnswer(false));

    nextQuestionBtn.addEventListener('click', () => {
        const scenarios = PhishingEngine.QUIZ_SCENARIOS;
        currentQuizIndex = (currentQuizIndex + 1) % scenarios.length;
        loadQuizScenario(currentQuizIndex);
    });

    // Initialize initial state
    updatePasswordAnalysis('P@ssw0rd2026!Pro');
    triggerGeneration();
    loadQuizScenario(0);


    // ==========================================
    // 7. TOAST NOTIFICATION HELPER
    // ==========================================
    const toast = document.getElementById('toast');
    const toastMsg = document.getElementById('toastMsg');
    let toastTimeout;

    function showToast(msg) {
        toastMsg.textContent = msg;
        toast.classList.remove('hidden');
        clearTimeout(toastTimeout);
        toastTimeout = setTimeout(() => {
            toast.classList.add('hidden');
        }, 3000);
    }
});
