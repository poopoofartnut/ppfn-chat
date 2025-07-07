const fs = require('fs');
const path = require('path');
const MESSAGES_FILE = path.join(__dirname, 'messages.json');

let messages = [];

// Load messages from file on startup
function loadMessages() {
    if (fs.existsSync(MESSAGES_FILE)) {
        try {
            messages = JSON.parse(fs.readFileSync(MESSAGES_FILE, 'utf8'));
        } catch {
            messages = [];
        }
    }
}
loadMessages();

function saveMessages() {
    fs.writeFileSync(MESSAGES_FILE, JSON.stringify(messages, null, 2));
}

function getMessages() {
    return messages;
}

function addMessage({ username, groupId, encrypted, participants }) {
    const msg = {
        username: username.trim(),
        groupId,
        encrypted,
        participants,
        timestamp: new Date().toISOString()
    };
    messages.push(msg);
    if (messages.length > 100) messages = messages.slice(-100);
    saveMessages();
}

module.exports = { getMessages, addMessage };