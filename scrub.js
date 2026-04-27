const fs = require('fs');
let content = fs.readFileSync('c:\\Users\\Keert\\my-app\\controllers\\authController.js', 'utf8');
content = content.replace(/â Œ/g, '').replace(/âœ…/g, '').replace(/â€“/g, '-').replace(/â€¦/g, '...');
fs.writeFileSync('c:\\Users\\Keert\\my-app\\controllers\\authController.js', content, 'utf8');
console.log("Scrubbed authController.js");
