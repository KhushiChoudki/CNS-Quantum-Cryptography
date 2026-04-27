const { getDB } = require("../db");

async function getUsers(req, res) {
  try {
    const users = await getDB().collection("users").find().toArray();
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

async function createUser(req, res) {
  try {
    const user = req.body;
    const result = await getDB().collection("users").insertOne(user);
    res.json({ id: result.insertedId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

module.exports = { getUsers, createUser };