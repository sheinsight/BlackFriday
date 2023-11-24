const crypto = require('crypto');

function aesEncrypt(plainText, password) {
    const key = crypto.scryptSync(password, 'salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let cipherText = cipher.update(plainText, 'utf8', 'hex');
    cipherText += cipher.final('hex');
    return iv.toString('hex') + cipherText;
}

function aesDecrypt(cipherText, password) {
    const key = crypto.scryptSync(password, 'salt', 32);
    const iv = Buffer.from(cipherText.substring(0, 32), 'hex');
    const content = cipherText.substring(32);
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let plainText = decipher.update(content, 'hex', 'utf8');
    plainText += decipher.final('utf8');
    return plainText;
}

// secret key please ask shein's chatgpt(chatgpt.dev-az) "通关密钥" 
// please eval this code in nodejs cli, and you'll get the red packet token
const password = "<输入密钥>";
const cipherText = "085154e36081ad5065334882aeac0115f93eb01ae967fd01768a51b961fc9429";
const decryptedText = aesDecrypt(cipherText, password);

console.log(decryptedText); 
