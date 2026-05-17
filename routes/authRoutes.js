const express  = require("express");
const router   = express.Router();
const { signup, login, logout, vpnConfig, sessionStatus, getMetrics, getAuditLog, simulateAttack, attackVisual, vpnPeers, getBenchmark, getSecurityAnalysis, getHndlDemo } = require("../controllers/authController");

router.post("/signup",           signup);
router.post("/login",            login);
router.post("/logout",           logout);
router.get ("/vpn-config",       vpnConfig);
router.get ("/session-status",   sessionStatus);
router.get ("/metrics",          getMetrics);
router.get ("/audit-log",        getAuditLog);
router.post("/simulate-attack",  simulateAttack);
router.post("/attack-visual",    attackVisual);
router.get ("/vpn-peers",        vpnPeers);
router.get ("/benchmark",        getBenchmark);
router.get ("/security-analysis",getSecurityAnalysis);
router.get ("/hndl-demo",        getHndlDemo);

module.exports = router;