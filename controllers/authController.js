const {
    createUser, findUserByName,
    storeQuantumData, updateUserAuth,
    revokeUserSession, appendAuditEvent,
} = require("../models/userModel");
const bcrypt = require("bcrypt");
const jwt    = require("jsonwebtoken");

const SECRET = process.env.JWT_SECRET || "supersecretkey-pqc-vpn-system";
const BRIDGE = process.env.BRIDGE_URL  || "http://40.81.244.230:5001";
const SESSION_TTL_MS = 60 * 60 * 1000; // 1 hour

// ── Bridge helper ──────────────────────────────────────────────────────────────
async function callBridge(path, body, method = "POST") {
    const opts = {
        method,
        headers: { "Content-Type": "application/json" },
    };
    if (body) opts.body = JSON.stringify(body);

    const res = await fetch(`${BRIDGE}${path}`, opts);
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `Bridge error ${res.status}`);
    }
    return res.json();
}

// ── Signup ─────────────────────────────────────────────────────────────────────
async function signup(req, res) {
    try {
        const { name, password } = req.body;
        if (!name || !password)
            return res.status(400).json({ message: "name and password required" });

        const existing = await findUserByName(name);
        if (existing) return res.status(400).json({ message: "User already exists ❌" });

        // 1. Create user in MongoDB
        await createUser({ name, password });

        // 2. Register with PQC bridge → get Wiesner token + Kyber-512 keypair
        const quantum = await callBridge("/register", { user_id: name });

        // 3. Persist quantum data
        await storeQuantumData(name, {
            quantum_token: quantum.token,
            pqc_public_key: quantum.public_key,
            token_display:  quantum.token_display || null,
            kyber_meta:     quantum.kyber_meta    || null,
        });

        await appendAuditEvent(name, {
            event: "registered",
            details: { kyber_algo: quantum.kyber_meta?.algorithm || "Kyber-512" }
        });

        // 4. Return PQC key info + token display (NOT the raw token — server-held)
        res.json({
            message:        "✅ Registration successful",
            pqc_public_key: quantum.public_key,
            kyber_meta:     quantum.kyber_meta,
            token_display:  quantum.token_display,  // basis/bit table for UI
            wiesner_desc:   quantum.wiesner_desc,
            token_length:   quantum.token_length,
        });
    } catch (err) {
        console.error("Signup error:", err.message);
        res.status(500).json({ error: err.message });
    }
}

// ── Login ──────────────────────────────────────────────────────────────────────
async function login(req, res) {
    try {
        const { name, password, quantum_token_upload } = req.body;
        if (!name || !password)
            return res.status(400).json({ message: "name and password required" });

        // 1. Find user
        const user = await findUserByName(name);
        if (!user) return res.status(400).json({ message: "User not found ❌" });

        // 2. Verify password
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ message: "Incorrect password ❌" });

        // 3. Ensure quantum token exists
        if (!user.quantum_token) {
            return res.status(400).json({ message: "Quantum token missing — please re-register ❌" });
        }

        // 4. Determine which token to use (Prefer uploaded token for True MFA)
        let tokenToVerify;

        if (user.has_logged_in) {
            // Must upload a token
            if (!quantum_token_upload) {
                return res.status(400).json({ message: "Missing credential file. Returning users MUST upload their quantum credential file. ❌" });
            }
            try {
                if (Array.isArray(quantum_token_upload)) {
                    tokenToVerify = quantum_token_upload.map(t => [t.basis, t.bit]);
                } else if (quantum_token_upload.token_display) {
                    tokenToVerify = quantum_token_upload.token_display.map(t => [t.basis, t.bit]);
                } else {
                    return res.status(400).json({ message: "Invalid credential file structure. ❌" });
                }
            } catch (e) {
                return res.status(400).json({ message: "Invalid quantum token format ❌" });
            }
        } else {
            // First time login - server provides the token
            tokenToVerify = user.quantum_token;
            // Optionally, if they DID upload one anyway, we can use it
            if (quantum_token_upload) {
                try {
                    if (Array.isArray(quantum_token_upload)) {
                        tokenToVerify = quantum_token_upload.map(t => [t.basis, t.bit]);
                    } else if (quantum_token_upload.token_display) {
                        tokenToVerify = quantum_token_upload.token_display.map(t => [t.basis, t.bit]);
                    }
                } catch (e) { }
            }
        }

        // 5. Authenticate via PQC bridge (Layer 1: Wiesner + Layer 2: Kyber KEM)
        let authResult = await callBridge("/authenticate", {
            user_id: name,
            token:   tokenToVerify,
        });

        // 5. Auto-recovery if bridge lost state (e.g. restarted)
        if (authResult.error === "User not found") {
            console.log(`[Auto-recovery] Re-registering "${name}" in bridge...`);
            const quantum = await callBridge("/register", { user_id: name });
            await storeQuantumData(name, {
                quantum_token: quantum.token,
                pqc_public_key: quantum.public_key,
                token_display:  quantum.token_display || null,
                kyber_meta:     quantum.kyber_meta    || null,
            });
            authResult = await callBridge("/authenticate", {
                user_id: name,
                token:   quantum.token,
            });
        }

        // 6. Handle auth failure
        if (authResult.status !== "authenticated") {
            // Persist rotated token
            if (authResult.next_token) {
                await storeQuantumData(name, {
                    quantum_token:  authResult.next_token,
                    pqc_public_key: user.pqc_public_key,
                });
            }
            await appendAuditEvent(name, {
                event: "auth_failed",
                details: { reason: authResult.error, confidence: authResult.confidence }
            });
            return res.status(401).json({
                message:      "Quantum authentication denied ❌",
                status:       authResult.status,
                confidence:   authResult.confidence,
                layers_passed: authResult.layers_passed || 0,
                error:        authResult.error || null,
            });
        }

        // 7. Auth succeeded → add WireGuard peer dynamically
        const sessionExpiry = new Date(Date.now() + SESSION_TTL_MS);
        let vpnData = { allocated_ip: null, vpn_config: null, client_pubkey: null };
        try {
            const vpnResult = await callBridge("/vpn-peer-add", {
                user_id:     name,
                session_key: authResult.session_key,
                session_ttl: SESSION_TTL_MS / 1000,
            });
            vpnData = {
                allocated_ip:  vpnResult.allocated_ip,
                vpn_config:    vpnResult.vpn_config,
                client_pubkey: vpnResult.client_pubkey,
            };
        } catch (vpnErr) {
            console.warn("VPN peer add failed (non-fatal):", vpnErr.message);
        }

        // 8. Persist session state + rotated token
        await storeQuantumData(name, {
            quantum_token:  authResult.next_token || user.quantum_token,
            pqc_public_key: user.pqc_public_key,
            token_display:  authResult.next_token_display || null,
        });
        await updateUserAuth(name, {
            session_key:        authResult.session_key,
            session_expires_at: sessionExpiry,
            vpn_peer_ip:        vpnData.allocated_ip,
            vpn_config:         vpnData.vpn_config,
        });
        await appendAuditEvent(name, {
            event: "auth_success",
            details: {
                confidence:  authResult.confidence,
                kyber_algo:  authResult.kyber_algorithm,
                vpn_ip:      vpnData.allocated_ip,
                session_ttl: "1 hour",
            }
        });

        // 9. Issue JWT
        const jwtToken = jwt.sign({ name }, SECRET, { expiresIn: "1h" });

        res.json({
            message:           "✅ Login successful — PQC authentication passed",
            status:            authResult.status,
            confidence:        authResult.confidence,
            layers_passed:     authResult.layers_passed,
            session_key:       authResult.session_key,
            kyber_algorithm:   authResult.kyber_algorithm,
            kyber_standard:    authResult.kyber_standard,
            security_bits:     authResult.security_bits,
            vpn_peer_ip:       vpnData.allocated_ip,
            session_expires_at: sessionExpiry.toISOString(),
            next_token_display: authResult.next_token_display || null,
            token:             jwtToken,
            // WireGuard config available via /auth/vpn-config
        });
    } catch (err) {
        console.error("Login error:", err.message);
        res.status(500).json({ error: err.message });
    }
}

// ── Logout ─────────────────────────────────────────────────────────────────────
async function logout(req, res) {
    try {
        const { name } = req.body;
        if (!name) return res.status(400).json({ message: "name required" });

        const user = await findUserByName(name);
        if (!user) return res.status(404).json({ message: "User not found" });

        // Remove WireGuard peer
        try {
            await callBridge("/vpn-peer-remove", { user_id: name });
        } catch (e) { /* non-fatal */ }

        await revokeUserSession(name);
        await appendAuditEvent(name, { event: "logout", details: {} });

        res.json({ message: "✅ Logged out — WireGuard peer removed" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}

// ── VPN Config ─────────────────────────────────────────────────────────────────
async function vpnConfig(req, res) {
    try {
        const name = req.query.name || req.body?.name;
        if (!name) return res.status(400).json({ message: "name required" });

        const user = await findUserByName(name);
        if (!user) {
            await callBridge("/log-intrusion", {}).catch(() => {});
            return res.status(404).json({ message: "User not found" });
        }

        if (!user.authorized) {
            await callBridge("/log-intrusion", {}).catch(() => {});
            return res.status(403).json({
                message:    "Access denied ❌ — PQC authentication required first",
                authorized: false,
            });
        }

        // Session expiry check
        if (user.session_expires_at && new Date() > new Date(user.session_expires_at)) {
            await revokeUserSession(name);
            return res.status(403).json({
                message:    "Session expired ❌ — please re-authenticate",
                authorized: false,
            });
        }

        // Return stored config (generated at login time)
        if (user.vpn_config) {
            res.setHeader("Content-Type", "text/plain");
            res.setHeader("Content-Disposition", `attachment; filename="${name}-pqc-vpn.conf"`);
            return res.send(user.vpn_config);
        }

        // Fallback static config
        const config = `[Interface]
# PQC-Gated WireGuard — ${name}
PrivateKey = <run: wg genkey>
Address    = ${user.vpn_peer_ip || "10.0.0.X"}/32
DNS        = 1.1.1.1

[Peer]
PublicKey  = <SERVER-PUBLIC-KEY>
Endpoint   = 40.81.244.230:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
# Kyber-512 Session Key: ${user.session_key?.substring(0, 32) || "N/A"}...
`;
        res.setHeader("Content-Type", "text/plain");
        res.send(config);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}

// ── Session Status ─────────────────────────────────────────────────────────────
async function sessionStatus(req, res) {
    try {
        const { name } = req.query;
        if (!name) return res.status(400).json({ message: "name required" });

        const user = await findUserByName(name);
        if (!user) return res.status(404).json({ message: "User not found" });

        const now      = new Date();
        const expiry   = user.session_expires_at ? new Date(user.session_expires_at) : null;
        const active   = user.authorized && expiry && now < expiry;
        const remaining = expiry ? Math.max(0, Math.floor((expiry - now) / 1000)) : 0;

        // Also query bridge for real-time peer info
        let peerInfo = null;
        try {
            peerInfo = await callBridge(`/vpn-session?user_id=${name}`, null, "GET");
        } catch (e) { /* non-fatal */ }

        res.json({
            authorized:        active,
            session_expires_at: expiry?.toISOString() || null,
            ttl_remaining_s:   remaining,
            vpn_peer_ip:       user.vpn_peer_ip,
            kyber_session_key: user.session_key?.substring(0, 16) + "...",
            peer_info:         peerInfo,
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
}

// ── Metrics ────────────────────────────────────────────────────────────────────
async function getMetrics(req, res) {
    try {
        const response = await fetch(`${BRIDGE}/metrics`);
        const data     = await response.json();
        res.json(data);
    } catch (err) {
        res.status(503).json({ error: "Quantum bridge unreachable — " + err.message });
    }
}

// ── Audit Log ──────────────────────────────────────────────────────────────────
async function getAuditLog(req, res) {
    try {
        // System-wide from bridge
        const response = await fetch(`${BRIDGE}/audit-log?limit=50`);
        const data     = await response.json();
        res.json(data);
    } catch (err) {
        res.status(503).json({ error: "Bridge unreachable — " + err.message });
    }
}

// ── Attack Simulation ──────────────────────────────────────────────────────────
async function simulateAttack(req, res) {
    try {
        const { name } = req.body;
        if (!name) return res.status(400).json({ message: "name required" });

        const user = await findUserByName(name);
        if (!user) return res.status(404).json({ message: "User not found ❌ — register first" });

        const response = await fetch(`${BRIDGE}/simulate-attack`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ user_id: name }),
        });
        const data = await response.json();
        res.json(data);
    } catch (err) {
        res.status(503).json({ error: "Quantum bridge unreachable — " + err.message });
    }
}

async function attackVisual(req, res) {
    try {
        const { name, attack_type, rounds } = req.body;
        if (!name) return res.status(400).json({ message: "name required" });

        const user = await findUserByName(name);
        if (!user) return res.status(404).json({ message: "User not found" });

        const response = await fetch(`${BRIDGE}/attack-visual`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ user_id: name, attack_type, rounds }),
        });
        const data = await response.json();
        res.json(data);
    } catch (err) {
        res.status(503).json({ error: "Quantum bridge unreachable — " + err.message });
    }
}

// ── VPN Peers ─────────────────────────────────────────────────────────────────
async function vpnPeers(req, res) {
    try {
        const response = await fetch(`${BRIDGE}/vpn-peers`);
        const data     = await response.json();
        res.json(data);
    } catch (err) {
        res.status(503).json({ error: "Bridge unreachable" });
    }
}

async function getBenchmark(req, res) {
    try {
        const runs = req.query.runs || 20;
        const r = await fetch(`${BRIDGE}/benchmark?runs=${runs}`);
        res.json(await r.json());
    } catch (err) { res.status(503).json({ error: "Bridge unreachable" }); }
}

async function getSecurityAnalysis(req, res) {
    try {
        const samples = req.query.samples || 300;
        const r = await fetch(`${BRIDGE}/security-analysis?samples=${samples}`);
        res.json(await r.json());
    } catch (err) { res.status(503).json({ error: "Bridge unreachable" }); }
}

async function getHndlDemo(req, res) {
    try {
        const r = await fetch(`${BRIDGE}/hndl-demo`);
        res.json(await r.json());
    } catch (err) { res.status(503).json({ error: "Bridge unreachable" }); }
}

module.exports = {
    signup, login, logout,
    vpnConfig, sessionStatus,
    getMetrics, getAuditLog,
    simulateAttack, attackVisual,
    vpnPeers,
    getBenchmark, getSecurityAnalysis, getHndlDemo,
    SECRET,
};
