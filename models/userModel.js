const { getDB } = require("../db");
const bcrypt = require("bcrypt");

const collectionName = "users";

async function createUser({ name, password }) {
    const db = getDB();
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await db.collection(collectionName).insertOne({
        name,
        password:           hashedPassword,
        // Quantum fields — populated after bridge call
        pqc_public_key:     null,
        quantum_token:      null,
        token_display:      null,   // [{index, basis, bit, basis_name}]
        kyber_meta:         null,   // Kyber-512 parameter metadata
        // Session fields
        authorized:         false,
        session_key:        null,
        session_expires_at: null,
        vpn_peer_ip:        null,
        vpn_config:         null,
        // Audit trail
        audit_log:          [],
        created_at:         new Date(),
    });
    return result.insertedId;
}

async function findUserByName(name) {
    const db = getDB();
    return await db.collection(collectionName).findOne({ name });
}

async function storeQuantumData(name, { quantum_token, pqc_public_key, token_display, kyber_meta }) {
    const db = getDB();
    const update = { quantum_token, pqc_public_key };
    if (token_display !== undefined) update.token_display  = token_display;
    if (kyber_meta    !== undefined) update.kyber_meta     = kyber_meta;
    await db.collection(collectionName).updateOne({ name }, { $set: update });
}

async function updateUserAuth(name, { session_key, session_expires_at, vpn_peer_ip, vpn_config }) {
    const db = getDB();
    await db.collection(collectionName).updateOne(
        { name },
        {
            $set: {
                authorized:         true,
                has_logged_in:      true,
                session_key,
                session_expires_at: session_expires_at || null,
                vpn_peer_ip:        vpn_peer_ip        || null,
                vpn_config:         vpn_config         || null,
            }
        }
    );
}

async function revokeUserSession(name) {
    const db = getDB();
    await db.collection(collectionName).updateOne(
        { name },
        { $set: { authorized: false, session_key: null, session_expires_at: null, vpn_peer_ip: null } }
    );
}

async function appendAuditEvent(name, event) {
    const db = getDB();
    await db.collection(collectionName).updateOne(
        { name },
        {
            $push: {
                audit_log: {
                    $each: [{ ...event, timestamp: new Date() }],
                    $slice: -100,   // keep last 100 events per user
                }
            }
        }
    );
}

module.exports = {
    createUser,
    findUserByName,
    storeQuantumData,
    updateUserAuth,
    revokeUserSession,
    appendAuditEvent,
};