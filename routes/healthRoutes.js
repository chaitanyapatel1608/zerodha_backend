const express = require("express");
const mongoose = require("mongoose");

const router = express.Router();

function getHealthStatus() {
  const dbReady = mongoose.connection.readyState === 1;
  const memory = process.memoryUsage();
  return {
    status: dbReady ? "ok" : "degraded",
    uptimeSeconds: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    database: {
      status: dbReady ? "connected" : "disconnected",
      readyState: mongoose.connection.readyState,
    },
    system: {
      heapUsedMb: Math.round(memory.heapUsed / 1024 / 1024),
      heapTotalMb: Math.round(memory.heapTotal / 1024 / 1024),
      rssMb: Math.round(memory.rss / 1024 / 1024),
    },
    version: "2.0.0",
  };
}

router.get(["/health", "/healthz"], (req, res) => {
  res.status(200).json(getHealthStatus());
});

router.get("/ready", (req, res) => {
  const dbReady = mongoose.connection.readyState === 1;
  const health = getHealthStatus();
  res.status(dbReady ? 200 : 503).json(health);
});

module.exports = router;
