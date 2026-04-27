const jwt = require("jsonwebtoken");
const { SECRET } = require("../controllers/authController");

function verifyToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.status(401).json({ message: "No token provided ❌" });

    const token = authHeader.split(" ")[1]; // Bearer <token>
    jwt.verify(token, SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ message: "Invalid token ❌" });
        req.user = decoded;
        next();
    });
}

module.exports = { verifyToken };