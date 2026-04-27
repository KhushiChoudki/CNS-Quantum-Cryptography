const { createUser, findUserByName, storeQuantumData, updateUserAuth } = require("../models/userModel");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const SECRET = "supersecretkey"; // store in .env for production
const BRIDGE = "http://127.0.0.1:5001"; // force IPv4 - Windows localhost can resolve to ::1

// â”€â”€ helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async function callBridge(path, body) {
    const res = await fetch(`${BRIDGE}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
    });
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `Bridge error ${res.status}`);
    }
    return res.json();
}

// â”€â”€ Signup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async function signup(req, res) {
    try {
        const { name, password } = req.body;

        const existing = await findUserByName(name);
        if (existing) return res.status(400).json({ message: "User already exists âŒ" });

        // 1. Create user in MongoDB (with null quantum fields)
        await createUser({ name, password });

        // 2. Register with quantum security engine â†’ get token + PQC public key
        const quantum = await callBridge("/register", { user_id: name });

        // 3. Store quantum data alongside the user document
        await storeQuantumData(name, {
            quantum_token: quantum.token,
            pqc_public_key: quantum.public_key
        });

        res.json({
            message: "Signup successful",
            pqc_public_key: quantum.public_key
            // NOTE: token intentionally NOT returned to client - kept server-side
        });
    } catch (err) {
        console.error("Signup error:", err.message);
        res.status(500).json({ error: err.message });
    }
}

// â”€â”€ Login â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async function login(req, res) {
    try {
        const { name, password } = req.body;

        // 1. Find user in MongoDB
        const user = await findUserByName(name);
        if (!user) return res.status(400).json({ message: "User not found âŒ" });

        // 2. Verify password
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ message: "Incorrect password âŒ" });

        // 3. Make sure a quantum token exists in MongoDB
        if (!user.quantum_token) {
            return res.status(400).json({ message: "Quantum token missing - please re-register âŒ" });
        }

        // 4. Try to authenticate via quantum bridge
        let authResult = await callBridge("/authenticate", {
            user_id: name,
            token: user.quantum_token
        });

        // 5. AUTO-RECOVERY: if the bridge lost this user's state (e.g. bridge restarted),
        //    silently re-register them in the bridge and retry with the fresh token.
        if (authResult.error === "User not found") {
            console.log(`[Auto-recovery] Bridge lost state for "${name}" - re-registering...`);

            const quantum = await callBridge("/register", { user_id: name });

            // Persist the new token to MongoDB
            await storeQuantumData(name, {
                quantum_token: quantum.token,
                pqc_public_key: quantum.public_key
            });

            // Retry authentication with the freshly generated token
            authResult = await callBridge("/authenticate", {
                user_id: name,
                token: quantum.token
            });
        }

        // 6. Handle auth failure
        if (authResult.status !== "authenticated") {
            if (authResult.next_token) {
                await storeQuantumData(name, {
                    quantum_token: authResult.next_token,
                    pqc_public_key: user.pqc_public_key
                });
            }
            return res.status(401).json({
                message: "Quantum authentication denied âŒ",
                status: authResult.status,
                confidence: authResult.confidence,
                error: authResult.error || null
            });
        }

        // 7. Persist refreshed token + mark authorized
        await storeQuantumData(name, {
            quantum_token: authResult.next_token || user.quantum_token,
            pqc_public_key: user.pqc_public_key
        });
        await updateUserAuth(name, { session_key: authResult.session_key });

        // 8. Issue JWT
        const jwtToken = jwt.sign({ name }, SECRET, { expiresIn: "1h" });

        res.json({
            message: "Login successful - Quantum authentication passed",
            status: authResult.status,
            confidence: authResult.confidence,
            session_key: authResult.session_key,
            token: jwtToken
        });
    } catch (err) {
        console.error("Login error:", err.message);
        res.status(500).json({ error: err.message });
    }
}

// â”€â”€ VPN Config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async function vpnConfig(req, res) {
    try {
        const name = req.query.name || req.body?.name;
        if (!name) return res.status(400).json({ message: "name is required" });

        const user = await findUserByName(name);
        if (!user) {
            try { await fetch(`${BRIDGE}/log-intrusion`, { method: "POST" }); } catch(e){}
            return res.status(404).json({ message: "User not found" });
        }

        if (!user.authorized) {
            try { await fetch(`${BRIDGE}/log-intrusion`, { method: "POST" }); } catch(e){}
            return res.status(403).json({
                message: "Access denied âŒ - authenticate first",
                authorized: false
            });
        }

        // â”€â”€ VPN config pointing at the Azure VM (azure_user@40.81.244.230)
        //    WireGuard default port 51820. Client fills in their own PrivateKey.
        const config = `[Interface]
PrivateKey = <your-client-private-key>
Address    = 10.0.0.2/32
DNS        = 1.1.1.1

[Peer]
PublicKey  = <server-public-key>
Endpoint   = 40.81.244.230:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
# Quantum Session Key (one-time, rotates each login)
# SessionKey = ${user.session_key || "N/A"}
`;
        res.setHeader("Content-Type", "text/plain");
        res.send(config);
    } catch (err) {
        console.error("VPN config error:", err.message);
        res.status(500).json({ error: err.message });
    }
}

// â”€â”€ Metrics â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async function getMetrics(req, res) {
    try {
        const response = await fetch(`${BRIDGE}/metrics`);
        const data = await response.json();
        res.json(data);
    } catch (err) {
        res.status(503).json({ error: "Quantum bridge unreachable - " + err.message });
    }
}

// â”€â”€ Attack Simulation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async function simulateAttack(req, res) {
    try {
        const { name } = req.body;
        if (!name) return res.status(400).json({ message: "name is required" });

        const user = await findUserByName(name);
        if (!user) return res.status(404).json({ message: "User not found âŒ - register first" });

        const response = await fetch(`${BRIDGE}/simulate-attack`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ user_id: name })
        });
        const data = await response.json();
        res.json(data);
    } catch (err) {
        res.status(503).json({ error: "Quantum bridge unreachable - " + err.message });
    }
}

async function attackVisual(req, res) {
    try {
        const { name, attack_type, rounds } = req.body;
        if (!name) return res.status(400).json({ message: 'name is required' });
        const user = await findUserByName(name);
        if (!user) return res.status(404).json({ message: 'User not found' });
        const response = await fetch(`${BRIDGE}/attack-visual`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user_id: name, attack_type, rounds }) });
        const data = await response.json();
        res.json(data);
    } catch (err) {
        res.status(503).json({ error: 'Quantum bridge unreachable - ' + err.message });
    }
}

module.exports = { signup, login, vpnConfig, getMetrics, simulateAttack, attackVisual, SECRET };
