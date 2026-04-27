const fs = require('fs');
let content = fs.readFileSync('c:\\Users\\Keert\\my-app\\controllers\\authController.js', 'utf8');

content = content.replace(/if \(\!user\) return res\.status\(404\)\.json\(\{ message\: "User not found.*?" \}\);([\s\S]*?)if \(\!user\.authorized\) \{([\s\S]*?)return res\.status\(403\)\.json\(/, 
`if (!user) {
            try { await fetch(\`\${BRIDGE}/log-intrusion\`, { method: "POST" }); } catch(e){}
            return res.status(404).json({ message: "User not found" });
        }

        if (!user.authorized) {
            try { await fetch(\`\${BRIDGE}/log-intrusion\`, { method: "POST" }); } catch(e){}
            return res.status(403).json(`);

fs.writeFileSync('c:\\Users\\Keert\\my-app\\controllers\\authController.js', content, 'utf8');
console.log("Updated authController.js");
