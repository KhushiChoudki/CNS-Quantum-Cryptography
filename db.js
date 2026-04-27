const { MongoClient } = require("mongodb");

const url = "mongodb://127.0.0.1:27017";
const client = new MongoClient(url);
let db;

async function connectDB() {
  await client.connect();
  db = client.db("myFirstDB");
  console.log("MongoDB Connected 💚");
}

function getDB() {
  if (!db) throw new Error("Database not connected yet!");
  return db;
}

module.exports = { connectDB, getDB };