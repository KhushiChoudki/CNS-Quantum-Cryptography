const { getDB } = require("../db");
const bcrypt = require("bcrypt");

const collectionName = "users";

async function createUser({ name, password }) {
    const db = getDB();
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await db.collection(collectionName).insertOne({
        name,
        password: hashedPassword,
        // Quantum fields – populated after bridge call in authController
        pqc_public_key: null,
        quantum_token: null,
        authorized: false,
        session_key: null
    });
    return result.insertedId;
}

async function findUserByName(name) {
    const db = getDB();
    return await db.collection(collectionName).findOne({ name });
}

/**
 * Stores the quantum-generated token + public key received from the bridge
 * immediately after registration.
 */
async function storeQuantumData(name, { quantum_token, pqc_public_key }) {
    const db = getDB();
    await db.collection(collectionName).updateOne(
        { name },
        { $set: { quantum_token, pqc_public_key } }
    );
}

/**
 * Marks the user as authenticated and stores the session key.
 */
async function updateUserAuth(name, { session_key }) {
    const db = getDB();
    await db.collection(collectionName).updateOne(
        { name },
        { $set: { authorized: true, session_key } }
    );
}

module.exports = { createUser, findUserByName, storeQuantumData, updateUserAuth };