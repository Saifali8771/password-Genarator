/**
 * CYBERGUARD PHISHING DETECTION ENGINE
 * Includes URL Heuristic Scanner, Email Text Analyzer, and Phishing Quiz Scenarios
 */

const PhishingEngine = (function() {

    // Known High-Risk TLDs frequently abused in phishing campaigns
    const SUSPICIOUS_TLDS = [
        'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'click', 'download',
        'account', 'verify', 'live', 'rest', 'icu', 'fit', 'buzz', 'surf', 'loan', 'racing'
    ];

    // Popular Target Brands monitored for Typosquatting & Impersonation
    const POPULAR_BRANDS = [
        { name: 'PayPal', domain: 'paypal.com', keywords: ['paypal', 'pay-pal', 'paypa1', 'paypaI'] },
        { name: 'Google', domain: 'google.com', keywords: ['google', 'goog1e', 'g00gle'] },
        { name: 'Apple', domain: 'apple.com', keywords: ['apple', 'appleid', 'app1e'] },
        { name: 'Microsoft', domain: 'microsoft.com', keywords: ['microsoft', 'm1crosoft', 'micr0soft', 'msn', 'outlook', 'office365'] },
        { name: 'Amazon', domain: 'amazon.com', keywords: ['amazon', 'amaz0n', 'amz'] },
        { name: 'Netflix', domain: 'netflix.com', keywords: ['netflix', 'netf1ix', 'netfllx'] },
        { name: 'Meta / Facebook', domain: 'facebook.com', keywords: ['facebook', 'meta', 'instagram', 'fb-verify'] },
        { name: 'Chase Bank', domain: 'chase.com', keywords: ['chase', 'chasebank'] },
        { name: 'Bank of America', domain: 'bankofamerica.com', keywords: ['bankofamerica', 'bofa'] },
        { name: 'Wells Fargo', domain: 'wellsfargo.com', keywords: ['wellsfargo'] },
        { name: 'Binance / Crypto', domain: 'binance.com', keywords: ['binance', 'coinbase', 'metamask', 'trustwallet'] },
        { name: 'Stripe', domain: 'stripe.com', keywords: ['stripe'] }
    ];

    // Suspicious path terms targeting login/security credentials
    const SENSITIVE_KEYWORDS = [
        'login', 'signin', 'sign-in', 'verify', 'verification', 'account-update',
        'billing', 'security-check', 'webmail', 'wallet-connect', 'reset-password',
        'confirm-identity', 'suspension', 'secure-update', 'banking'
    ];

    /**
     * Calculates Shannon Entropy of a string to detect random generated substrings
     */
    function calculateStringEntropy(str) {
        if (!str) return 0;
        const len = str.length;
        const freq = {};
        for (let i = 0; i < len; i++) {
            const char = str[i];
            freq[char] = (freq[char] || 0) + 1;
        }
        let entropy = 0;
        for (const char in freq) {
            const p = freq[char] / len;
            entropy -= p * Math.log2(p);
        }
        return entropy;
    }

    /**
     * URL Safety & Heuristic Threat Scanner
     */
    function analyzeUrl(rawUrl) {
        let riskScore = 0;
        const heuristics = [];
        let normalizedUrl = rawUrl.trim();
        
        if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
            normalizedUrl = 'http://' + normalizedUrl;
        }

        let parsedUrl;
        try {
            parsedUrl = new URL(normalizedUrl);
        } catch (e) {
            return {
                error: 'Invalid URL format. Please enter a valid Web address.',
                riskScore: 100,
                verdict: 'CRITICAL',
                summary: 'Malformed URL syntax.'
            };
        }

        const protocol = parsedUrl.protocol;
        const hostname = parsedUrl.hostname.toLowerCase();
        const pathname = parsedUrl.pathname.toLowerCase();
        const search = parsedUrl.search.toLowerCase();
        const fullUrl = parsedUrl.href;

        // 1. HTTPS / SSL Check
        if (protocol === 'http:') {
            riskScore += 15;
            heuristics.push({
                title: 'Unencrypted Connection (HTTP)',
                desc: 'The website uses plain HTTP without SSL/TLS encryption. Sensitive data like passwords can be intercepted.',
                type: 'warning',
                icon: 'fa-triangle-exclamation'
            });
        } else {
            heuristics.push({
                title: 'HTTPS Encryption Active',
                desc: 'Connection uses secure SSL/TLS protocol.',
                type: 'safe',
                icon: 'fa-circle-check'
            });
        }

        // 2. IP Host Check (e.g., http://192.168.1.1/login)
        const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^\[[a-fA-F0-9:]+\]$/;
        if (ipRegex.test(hostname)) {
            riskScore += 30;
            heuristics.push({
                title: 'Raw IP Hostname Detected',
                desc: 'URL uses a raw IP address instead of a domain name. Legitimate services almost never present raw IP login pages.',
                type: 'danger',
                icon: 'fa-skull'
            });
        }

        // 3. Top Level Domain (TLD) Risk Check
        const parts = hostname.split('.');
        const tld = parts.length > 1 ? parts[parts.length - 1] : '';
        if (SUSPICIOUS_TLDS.includes(tld)) {
            riskScore += 25;
            heuristics.push({
                title: `High-Risk TLD (.${tld})`,
                desc: `The top-level domain .${tld} is frequently associated with disposable phishing sites and low-trust registrar domains.`,
                type: 'danger',
                icon: 'fa-triangle-exclamation'
            });
        } else if (tld) {
            heuristics.push({
                title: `Standard TLD (.${tld})`,
                desc: `Top-level domain .${tld} is standard.`,
                type: 'safe',
                icon: 'fa-circle-check'
            });
        }

        // 4. Excessive Subdomain Depth Check
        if (parts.length > 3) {
            riskScore += 20;
            heuristics.push({
                title: 'Excessive Subdomain Stacking',
                desc: `Found ${parts.length - 2} subdomain levels. Attackers stack subdomains (e.g. paypal.com.evil-site.org) to fool victims into seeing trusted brand names.`,
                type: 'danger',
                icon: 'fa-layer-group'
            });
        }

        // 5. Brand Impersonation / Typosquatting Detection
        let brandMatchFound = false;
        POPULAR_BRANDS.forEach(brand => {
            const rootDomain = parts.slice(-2).join('.');
            const containsKeyword = brand.keywords.some(kw => hostname.includes(kw));

            if (containsKeyword) {
                // If it contains brand keyword but root domain is NOT official domain
                if (rootDomain !== brand.domain && !hostname.endsWith('.' + brand.domain)) {
                    riskScore += 35;
                    brandMatchFound = true;
                    heuristics.push({
                        title: `Brand Impersonation Alert: Target (${brand.name})`,
                        desc: `URL contains references to '${brand.name}' but the root host domain is '${rootDomain}', NOT '${brand.domain}'. This is a classic phishing indicator.`,
                        type: 'danger',
                        icon: 'fa-user-ninja'
                    });
                }
            }
        });

        if (!brandMatchFound) {
            heuristics.push({
                title: 'No Known Brand Impersonation Detected',
                desc: 'Domain structure does not match known typosquatting patterns.',
                type: 'safe',
                icon: 'fa-circle-check'
            });
        }

        // 6. Sensitive Path & Keyword Target Check
        const matchedKeywords = SENSITIVE_KEYWORDS.filter(kw => pathname.includes(kw) || search.includes(kw));
        if (matchedKeywords.length > 0) {
            riskScore += 15;
            heuristics.push({
                title: 'Credential / Sensitive Keywords in Path',
                desc: `Path targets sensitive endpoints (${matchedKeywords.join(', ')}). Always verify domain ownership before typing credentials.`,
                type: 'warning',
                icon: 'fa-key'
            });
        }

        // 7. Suspicious URL Characters & Encoded Symbols
        if (fullUrl.includes('@')) {
            riskScore += 25;
            heuristics.push({
                title: 'Deceptive "@" Userinfo Symbol',
                desc: 'URL contains the "@" character. Browsers treat text before "@" as username, hiding the true destination domain.',
                type: 'danger',
                icon: 'fa-ghost'
            });
        }

        if (fullUrl.includes('//', 8)) {
            riskScore += 15;
            heuristics.push({
                title: 'Double Slash Redirection in Path',
                desc: 'Contains embedded double slashes "//", which can be used to bypass security filters.',
                type: 'warning',
                icon: 'fa-share'
            });
        }

        // 8. URL Length & Entropy Analysis
        const entropy = calculateStringEntropy(hostname);
        if (fullUrl.length > 80) {
            riskScore += 10;
            heuristics.push({
                title: 'Abnormally Long URL Length',
                desc: `URL length is ${fullUrl.length} characters. Phishing links often embed long obfuscated tracking strings.`,
                type: 'warning',
                icon: 'fa-ruler-horizontal'
            });
        }

        if (entropy > 3.8 && parts.length > 2) {
            riskScore += 15;
            heuristics.push({
                title: 'High Hostname Entropy / Random Generation',
                desc: `Hostname entropy is ${entropy.toFixed(2)}. Suggests algorithmically generated domain name (DGA).`,
                type: 'warning',
                icon: 'fa-dice'
            });
        }

        // Cap risk score between 0 and 100
        riskScore = Math.min(Math.max(riskScore, 0), 100);

        // Determine Verdict
        let verdict = 'SAFE';
        let summary = 'This URL exhibits no major suspicious indicators.';
        let recommendation = 'The domain structure appears standard. However, always ensure you opened links from trusted sources.';

        if (riskScore >= 75) {
            verdict = 'CRITICAL PHISH';
            summary = 'EXTREME RISK: Strong indicators of a phishing or brand impersonation scam.';
            recommendation = 'DO NOT open this website or enter any personal credentials! Close the tab immediately.';
        } else if (riskScore >= 45) {
            verdict = 'HIGH RISK';
            summary = 'SUSPICIOUS: Multiple security anomalies and high-risk indicators detected.';
            recommendation = 'Proceed with extreme caution. Double check official domain bookmarks before entering sensitive data.';
        } else if (riskScore >= 20) {
            verdict = 'CAUTION';
            summary = 'MODERATE RISK: Contains minor potential security warnings.';
            recommendation = 'Verify the authenticity of the page owner before interacting with inputs.';
        }

        return {
            url: fullUrl,
            protocol,
            hostname,
            tld: tld ? `.${tld}` : 'N/A',
            riskScore,
            verdict,
            summary,
            recommendation,
            heuristics
        };
    }

    /**
     * Email & Text Phishing Analyzer
     */
    function analyzeEmail(text) {
        if (!text || text.trim().length === 0) {
            return { error: 'Please enter or paste email text to analyze.' };
        }

        let score = 0;
        const indicators = [];
        const lowerText = text.toLowerCase();

        // 1. Urgency & High-Pressure Phrasing
        const urgencyTerms = [
            '24 hours', 'immediate action', 'account suspended', 'account blocked',
            'legal action', 'terminate your account', 'unauthorized attempt', 'urgent notice',
            'act now', 'within 12 hours', 'final warning'
        ];
        const matchedUrgency = urgencyTerms.filter(t => lowerText.includes(t));
        if (matchedUrgency.length > 0) {
            score += 30;
            indicators.push({
                title: 'High Urgency & Threat Phrasing',
                desc: `Found urgent pressure terms: "${matchedUrgency.join('", "')}". Scammers create panic so victims act without thinking.`,
                type: 'danger'
            });
        }

        // 2. Financial / Credential Actions
        const financialTerms = [
            'update billing', 'confirm credit card', 'verify ssn', 'gift card',
            'wire transfer', 'claim prize', 'winner', 'payment declined', 'crypto wallet',
            'verify password', 'click here to restore'
        ];
        const matchedFinancial = financialTerms.filter(t => lowerText.includes(t));
        if (matchedFinancial.length > 0) {
            score += 30;
            indicators.push({
                title: 'Credential / Financial Solicitation',
                desc: `Requests sensitive actions: "${matchedFinancial.join('", "')}". Legitimate institutions rarely request credential verification via raw message links.`,
                type: 'danger'
            });
        }

        // 3. Generic Greeting Check
        const genericGreetings = ['dear customer', 'dear user', 'dear account holder', 'dear client', 'attention user'];
        if (genericGreetings.some(g => lowerText.includes(g))) {
            score += 15;
            indicators.push({
                title: 'Generic Impersonal Salutation',
                desc: 'Message uses generic greetings like "Dear Customer" instead of your actual name.',
                type: 'warning'
            });
        }

        // 4. Embedded URL Extraction
        const urlMatches = text.match(/https?:\/\/[^\s]+/g);
        if (urlMatches && urlMatches.length > 0) {
            score += 15;
            indicators.push({
                title: `Contains ${urlMatches.length} Embedded Link(s)`,
                desc: `Found embedded links (e.g. ${urlMatches[0].substring(0, 45)}...). Always hover links to inspect the destination domain.`,
                type: 'warning'
            });
        }

        score = Math.min(Math.max(score, 0), 100);

        let verdict = 'SAFE';
        let summary = 'No high-risk phishing phrasing detected in the text.';
        if (score >= 60) {
            verdict = 'HIGH RISK PHISH';
            summary = 'Strong indicators of a deceptive phishing email or SMS scam.';
        } else if (score >= 30) {
            verdict = 'SUSPICIOUS';
            summary = 'Contains suspicious high-urgency or financial keywords.';
        }

        return {
            riskScore: score,
            verdict,
            summary,
            indicators
        };
    }

    // Interactive Quiz Scenarios
    const QUIZ_SCENARIOS = [
        {
            id: 1,
            category: 'EMAIL SCENARIO',
            title: 'Urgent Security Alert from PayPal',
            sender: 'service-update@paypa1-security-center.com',
            subject: 'URGENT: Your account has been temporarily restricted!',
            body: 'Dear Customer, We detected an unauthorized login from an unknown device in Russia. Please click the link below within 24 hours to verify your identity and restore account access, or your funds will be frozen.',
            isPhishing: true,
            explanation: 'This is PHISHING! Notice the sender domain uses "paypa1" (with a number 1 instead of l), creates artificial urgency ("24 hours"), and uses a generic "Dear Customer" greeting.'
        },
        {
            id: 2,
            category: 'SECURITY NOTIFICATION',
            title: 'Google Account Sign-In Alert',
            sender: 'no-reply@accounts.google.com',
            subject: 'Security alert: New sign-in on Windows PC',
            body: 'Your Google Account was just signed in to on a Windows device. If this was you, you don\'t need to do anything. If you don\'t recognize this activity, review your account security settings.',
            isPhishing: false,
            explanation: 'This is LEGITIMATE. The email comes from the official domain (@accounts.google.com), contains no pressure tactics, and does not demand you click a suspicious link to avoid penalties.'
        },
        {
            id: 3,
            category: 'SMS / TEXT MESSAGE',
            title: 'Package Delivery Notice',
            sender: '+1 (800) 555-0199',
            subject: 'USPS Delivery Failure',
            body: 'USPS: Your package #940011029 cannot be delivered due to incomplete address. Update your address now at: http://usps-redelivery-notice.top/update',
            isPhishing: true,
            explanation: 'This is a SMISHING (SMS Phishing) SCAM! USPS will never send package update links pointing to high-risk TLDs like ".top".'
        },
        {
            id: 4,
            category: 'WORKPLACE EMAIL',
            title: 'Internal IT Maintenance Notice',
            sender: 'helpdesk@company-internal.com',
            subject: 'Scheduled System Maintenance Notice',
            body: 'Team, please be aware that internal servers will undergo scheduled routine maintenance this Saturday from 2:00 AM to 4:00 AM EST. No user action is required.',
            isPhishing: false,
            explanation: 'This is LEGITIMATE. It is an informational internal announcement that asks for no passwords, credentials, or urgent actions.'
        },
        {
            id: 5,
            category: 'FINANCIAL SCAM',
            title: 'CEO Wire Transfer Request',
            sender: 'ceo.johnson.exec@gmail.com',
            subject: 'URGENT Confidential Task',
            body: 'I am currently in an urgent board meeting and cannot take calls. I need you to immediately buy $500 in Apple Gift Cards for an urgent client gift and email me the redemption codes right now.',
            isPhishing: true,
            explanation: 'This is EXECUTIVE IMPERSONATION (SPEAR PHISHING)! CEOs will not ask employees via personal Gmail accounts to buy gift cards or make urgent unverified payments.'
        }
    ];

    return {
        analyzeUrl,
        analyzeEmail,
        QUIZ_SCENARIOS
    };
})();
