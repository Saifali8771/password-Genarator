/**
 * CYBERGUARD PASSWORD STRENGTH & GENERATOR ENGINE
 */

const PasswordEngine = (function() {

    // Common Breached Passwords List for Instant Offline Lookup
    const COMMON_BREACHED_PASSWORDS = [
        '123456', 'password', '123456789', '12345678', '12345', '1234567', 'qwerty', '1234567890',
        '111111', '123123', 'dragon', 'admin', 'welcome', 'password1', 'monkey', 'letmein',
        'p@ssword', 'p@ssw0rd', 'sunshine', 'princess', 'charlie', 'football', 'superman', 'iloveyou',
        'trustno1', '123321', '000000', '654321', 'master', 'shadow', 'ashley', 'jordan', 'matrix'
    ];

    // Word dictionary for Memorable Passphrase Generator
    const PASSPHRASE_WORDS = [
        'correct', 'horse', 'battery', 'staple', 'cyber', 'shield', 'quantum', 'phoenix',
        'falcon', 'thunder', 'galaxy', 'shadow', 'matrix', 'crystal', 'anchor', 'orbit',
        'dragon', 'velocity', 'horizon', 'nebula', 'titan', 'stellar', 'vector', 'vortex',
        'compass', 'beacon', 'summit', 'glacier', 'beacon', 'safari', 'cascade', 'zenith'
    ];

    /**
     * Calculates Shannon Entropy & Character Diversity
     */
    function evaluatePassword(pwd) {
        if (!pwd) {
            return {
                length: 0,
                entropy: 0,
                score: 0,
                rating: 'NO PASSWORD',
                varietyCount: 0,
                isBreached: false,
                crackTimes: {
                    online: 'Instant',
                    fastOnline: 'Instant',
                    offlineGpu: 'Instant',
                    quantum: 'Instant'
                },
                checklist: []
            };
        }

        const len = pwd.length;
        const lower = /[a-z]/.test(pwd);
        const upper = /[A-Z]/.test(pwd);
        const number = /[0-9]/.test(pwd);
        const symbol = /[^a-zA-Z0-9]/.test(pwd);

        let poolSize = 0;
        if (lower) poolSize += 26;
        if (upper) poolSize += 26;
        if (number) poolSize += 10;
        if (symbol) poolSize += 33;

        let varietyCount = [lower, upper, number, symbol].filter(Boolean).length;

        // Base entropy calculation: bits = len * log2(poolSize)
        let entropy = poolSize > 0 ? len * Math.log2(poolSize) : 0;

        // Penalties for sequential and repetitive patterns
        let penalty = 0;

        // Repetitive characters penalty (e.g., 'aaaaa')
        const repeatedCharMatch = pwd.match(/(.)\1{2,}/g);
        if (repeatedCharMatch) {
            penalty += repeatedCharMatch.length * 8;
        }

        // Sequential numbers or letters penalty (e.g. '1234', 'abcd')
        const sequentialRegex = /(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|qwe|wer|ert|rty|tyu|yui|iop)/i;
        if (sequentialRegex.test(pwd)) {
            penalty += 12;
        }

        // Deduct penalty
        const adjustedEntropy = Math.max(Math.round(entropy - penalty), 0);

        // Breached Check
        const cleanPwd = pwd.toLowerCase().trim();
        const isBreached = COMMON_BREACHED_PASSWORDS.includes(cleanPwd);

        // Rating & Score Determination
        let rating = 'WEAK';
        let score = 0; // 0 to 100

        if (isBreached) {
            rating = 'KNOWN BREACHED!';
            score = 5;
        } else if (adjustedEntropy < 28) {
            rating = 'VERY WEAK';
            score = 15;
        } else if (adjustedEntropy < 45) {
            rating = 'WEAK';
            score = 35;
        } else if (adjustedEntropy < 60) {
            rating = 'FAIR';
            score = 55;
        } else if (adjustedEntropy < 80) {
            rating = 'STRONG';
            score = 80;
        } else {
            rating = 'EXTREME / NIST COMPLIANT';
            score = 100;
        }

        // Calculate Crack Times
        const crackTimes = calculateCrackTimes(poolSize, len, isBreached);

        // Build Checklist
        const checklist = [
            { text: 'At least 12 characters long', pass: len >= 12 },
            { text: 'Contains uppercase letters (A-Z)', pass: upper },
            { text: 'Contains lowercase letters (a-z)', pass: lower },
            { text: 'Contains numbers (0-9)', pass: number },
            { text: 'Contains special symbols (!@#$)', pass: symbol },
            { text: 'Not found in common password breach database', pass: !isBreached }
        ];

        return {
            length: len,
            entropy: adjustedEntropy,
            score,
            rating,
            varietyCount,
            isBreached,
            crackTimes,
            checklist
        };
    }

    /**
     * Multi-Vector Crack Time Estimator
     */
    function calculateCrackTimes(poolSize, len, isBreached) {
        if (isBreached || len === 0 || poolSize === 0) {
            return {
                online: 'Instant (Breached)',
                fastOnline: 'Instant (Breached)',
                offlineGpu: 'Instant (Breached)',
                quantum: 'Instant (Breached)'
            };
        }

        // Total possible combinations = poolSize ^ len
        // Average combinations needed to crack = total / 2
        const totalCombinations = Math.pow(poolSize, len);
        const avgAttempts = totalCombinations / 2;

        return {
            online: formatSeconds(avgAttempts / 100),            // 100 attempts / sec
            fastOnline: formatSeconds(avgAttempts / 10000),       // 10,000 attempts / sec
            offlineGpu: formatSeconds(avgAttempts / 100000000000), // 100 Billion / sec
            quantum: formatSeconds(avgAttempts / 10000000000000)  // 10 Trillion / sec
        };
    }

    /**
     * Formats seconds into human readable time duration
     */
    function formatSeconds(seconds) {
        if (!isFinite(seconds) || seconds > 3.15e16) {
            return 'Trillions of Years';
        }
        if (seconds < 0.001) return 'Instant (< 1ms)';
        if (seconds < 1) return `${(seconds * 1000).toFixed(0)} ms`;
        if (seconds < 60) return `${seconds.toFixed(1)} seconds`;
        
        const minutes = seconds / 60;
        if (minutes < 60) return `${minutes.toFixed(0)} minutes`;

        const hours = minutes / 60;
        if (hours < 24) return `${hours.toFixed(0)} hours`;

        const days = hours / 24;
        if (days < 365) return `${days.toFixed(0)} days`;

        const years = days / 365;
        if (years < 1000) return `${years.toFixed(0)} years`;
        if (years < 1000000) return `${(years / 1000).toFixed(1)} thousand years`;
        if (years < 1000000000) return `${(years / 1000000).toFixed(1)} Million years`;
        return `${(years / 1000000000).toFixed(1)} Billion years`;
    }

    /**
     * Cryptographically Secure Random Password Generator
     */
    function generateRandomPassword(options) {
        const {
            length = 16,
            useUpper = true,
            useLower = true,
            useNumbers = true,
            useSymbols = true,
            avoidAmbiguous = false
        } = options;

        let charPool = '';
        if (useLower) charPool += 'abcdefghijklmnopqrstuvwxyz';
        if (useUpper) charPool += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (useNumbers) charPool += '0123456789';
        if (useSymbols) charPool += '!@#$%^&*()_+-=[]{}|;:,.<>?';

        if (avoidAmbiguous) {
            charPool = charPool.replace(/[l1IO0]/g, '');
        }

        if (!charPool) charPool = 'abcdefghijklmnopqrstuvwxyz';

        const randomArray = new Uint32Array(length);
        window.crypto.getRandomValues(randomArray);

        let result = '';
        for (let i = 0; i < length; i++) {
            result += charPool[randomArray[i] % charPool.length];
        }

        return result;
    }

    /**
     * Memorable Passphrase Generator
     */
    function generatePassphrase(options) {
        const {
            wordCount = 4,
            separator = '-',
            capitalize = true,
            includeNumber = true
        } = options;

        const randomArray = new Uint32Array(wordCount);
        window.crypto.getRandomValues(randomArray);

        const chosenWords = [];
        for (let i = 0; i < wordCount; i++) {
            let word = PASSPHRASE_WORDS[randomArray[i] % PASSPHRASE_WORDS.length];
            if (capitalize) {
                word = word.charAt(0).toUpperCase() + word.slice(1);
            }
            chosenWords.push(word);
        }

        if (includeNumber) {
            const numArray = new Uint32Array(1);
            window.crypto.getRandomValues(numArray);
            const num = (numArray[0] % 90) + 10; // 10 to 99
            chosenWords.push(num.toString());
        }

        return chosenWords.join(separator);
    }

    return {
        evaluatePassword,
        generateRandomPassword,
        generatePassphrase
    };
})();
