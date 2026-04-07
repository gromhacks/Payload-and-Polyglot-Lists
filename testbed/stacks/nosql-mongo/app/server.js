const express = require("express");
const { MongoClient } = require("mongodb");

const app = express();
app.use(express.urlencoded({ extended: true }));

const MONGO_URL = process.env.MONGO_URL || "mongodb://mongo:27017/testbed";
let db;

const seedData = [
  { name: "admin", email: "admin@test.com", password: "secret123", role: "admin" },
  { name: "user", email: "user@test.com", password: "password", role: "user" },
  { name: "guest", email: "guest@test.com", password: "guest", role: "guest" },
];

async function initDb() {
  const maxRetries = 30;
  for (let i = 0; i < maxRetries; i++) {
    try {
      const client = await MongoClient.connect(MONGO_URL);
      db = client.db();
      const count = await db.collection("users").countDocuments();
      if (count === 0) {
        await db.collection("users").insertMany(seedData);
      }
      console.log("Database initialized successfully.");
      return;
    } catch (e) {
      console.log(`Attempt ${i + 1}/${maxRetries} - waiting for MongoDB: ${e.message}`);
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  throw new Error("Could not connect to MongoDB after 30 attempts");
}

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.post("/find", async (req, res) => {
  const start = performance.now();
  const input = req.body.input || "{}";
  try {
    const query = JSON.parse(input);
    const rows = await db.collection("users").find(query).toArray();
    const elapsed = performance.now() - start;
    res.json({ output: JSON.stringify(rows), error: null, time_ms: Math.round(elapsed * 100) / 100 });
  } catch (e) {
    const elapsed = performance.now() - start;
    res.json({ output: "", error: e.message, time_ms: Math.round(elapsed * 100) / 100 });
  }
});

app.post("/where", async (req, res) => {
  const start = performance.now();
  const input = req.body.input || "";
  try {
    const rows = await db.collection("users").find({ $where: input }).toArray();
    const elapsed = performance.now() - start;
    res.json({ output: JSON.stringify(rows), error: null, time_ms: Math.round(elapsed * 100) / 100 });
  } catch (e) {
    const elapsed = performance.now() - start;
    res.json({ output: "", error: e.message, time_ms: Math.round(elapsed * 100) / 100 });
  }
});

app.post("/aggregate", async (req, res) => {
  const start = performance.now();
  const input = req.body.input || "[]";
  try {
    const pipeline = JSON.parse(input);
    const rows = await db.collection("users").aggregate(pipeline).toArray();
    const elapsed = performance.now() - start;
    res.json({ output: JSON.stringify(rows), error: null, time_ms: Math.round(elapsed * 100) / 100 });
  } catch (e) {
    const elapsed = performance.now() - start;
    res.json({ output: "", error: e.message, time_ms: Math.round(elapsed * 100) / 100 });
  }
});

initDb().then(() => {
  app.listen(8080, "0.0.0.0", () => {
    console.log("Server listening on port 8080");
  });
});
