const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { getMessages, addMessage } = require('./messages');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const USERS_FILE = path.join(__dirname, 'users.json');
const INVITES_FILE = path.join(__dirname, 'invites.json');
const READS_FILE = path.join(__dirname, 'reads.json');
let users = [], invites = [], reads = {};
if (fs.existsSync(USERS_FILE)) {
    try {
        users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    } catch {
        users = [];
    }
}
if (fs.existsSync(INVITES_FILE)) {
    try {
        invites = JSON.parse(fs.readFileSync(INVITES_FILE, 'utf8'));
    } catch {
        invites = [];
    }
}
if (fs.existsSync(READS_FILE)) {
    try {
        reads = JSON.parse(fs.readFileSync(READS_FILE, 'utf8'));
    } catch {
        reads = {};
    }
}

function saveUsers() {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function saveInvites() {
    fs.writeFileSync(INVITES_FILE, JSON.stringify(invites, null, 2));
}

function saveReads() {
    fs.writeFileSync(READS_FILE, JSON.stringify(reads, null, 2));
}

function hashPassword(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
}

function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

function generateAccountId() {
    return crypto.randomBytes(16).toString('hex');
}

function generatePassphrase() {
    return crypto.randomBytes(32).toString('hex');
}

function findUserByToken(token) {
    return users.find(u => u.token === token);
}

function getUserByAccountId(accountId) {
    return users.find(u => u.accountId === accountId);
}

function getPassphrasesForAccounts(accountIds) {
    return accountIds.map(id => {
        const u = getUserByAccountId(id);
        return u ? u.passphrase : '';
    });
}

function getGroupId(accountIds) {
    // Deterministic group id: hash of sorted account IDs
    const sorted = [...accountIds].sort().join(':');
    return crypto.createHash('sha256').update(sorted).digest('hex');
}

// Sign up
app.post('/api/auth/signup', (req, res) => {
    const { username, password } = req.body;
    if (typeof username !== 'string' || !username.trim() ||
        typeof password !== 'string' || password.length < 4) {
        return res.status(400).json({ error: 'Username and password required (min 4 chars).' });
    }
    if (users.find(u => u.username === username.trim())) {
        return res.status(400).json({ error: 'Username already exists.' });
    }
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(password, salt);
    const token = generateToken();
    const accountId = generateAccountId();
    const passphrase = generatePassphrase();
    users.push({ username: username.trim(), salt, hash, token, accountId, passphrase });
    saveUsers();
    res.json({ token, username: username.trim(), accountId, passphrase });
});

// Sign in
app.post('/api/auth/signin', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) return res.status(400).json({ error: 'Invalid credentials.' });
    const hash = hashPassword(password, user.salt);
    if (hash !== user.hash) return res.status(400).json({ error: 'Invalid credentials.' });
    // Issue new token
    user.token = generateToken();
    saveUsers();
    res.json({ token: user.token, username: user.username });
});

// Get account info (after login)
app.post('/api/auth/accountinfo', (req, res) => {
    const { token } = req.body;
    const user = findUserByToken(token);
    if (!user) return res.status(401).json({ error: 'Unauthorized.' });
    res.json({ accountId: user.accountId, passphrase: user.passphrase, username: user.username });
});

// Handshake endpoint: given usernames, return accountIds and passphrases for all (except requestor's passphrase)
app.post('/api/chat/handshake', (req, res) => {
    const { token, usernames } = req.body;
    const user = findUserByToken(token);
    if (!user || !Array.isArray(usernames) || usernames.length < 2) {
        return res.status(400).json({ error: 'Invalid handshake.' });
    }
    // Get user objects for all usernames
    const usersInChat = usernames.map(u => users.find(x => x.username === u)).filter(Boolean);
    if (usersInChat.length !== usernames.length) {
        return res.status(400).json({ error: 'One or more usernames not found.' });
    }
    // Build handshake info: for each user, send {username, accountId, passphrase (null for requestor)}
    const handshake = usersInChat.map(u => ({
        username: u.username,
        accountId: u.accountId,
        passphrase: u.username === user.username ? null : u.passphrase
    }));
    res.json({ handshake });
});

// --- GLOBAL CHATROOM SUPPORT ---
function getAllAccountIds() {
    return users.map(u => u.accountId);
}
function getGlobalGroupId() {
    return 'global';
}

// Get all messages for a group
app.post('/api/chat/messages', (req, res) => {
    const { token, chatWithUsernames, chatWith, groupId } = req.body;
    const user = findUserByToken(token);
    if (!user) return res.status(401).json({ error: 'Unauthorized.' });

    let participants = chatWith;
    let gid = groupId;
    if (groupId === 'global') {
        gid = 'global';
        participants = getAllAccountIds();
    } else if (Array.isArray(chatWithUsernames)) {
        participants = chatWithUsernames.map(u => {
            const found = users.find(x => x.username === u);
            return found ? found.accountId : null;
        }).filter(Boolean);
        gid = getGroupId(participants);
    } else if (Array.isArray(chatWith)) {
        gid = getGroupId(chatWith);
    }
    if (!Array.isArray(participants) || participants.length < 2) {
        return res.status(400).json({ error: 'chatWith must be an array of account IDs or usernames (including your own).' });
    }
    const allMessages = getMessages();
    const groupMessages = allMessages.filter(m => m.groupId === gid);

    // Mark as read
    if (!reads[user.accountId]) reads[user.accountId] = {};
    reads[user.accountId][gid] = Date.now();
    saveReads();

    res.json({ messages: groupMessages });
});

// Start chat: send invites to all users except initiator
app.post('/api/chat/start', (req, res) => {
    const { token, usernames } = req.body;
    const user = findUserByToken(token);
    if (!user || !Array.isArray(usernames) || usernames.length < 2) {
        return res.status(400).json({ error: 'Invalid chat start.' });
    }
    const usersInChat = usernames.map(u => users.find(x => x.username === u)).filter(Boolean);
    if (usersInChat.length !== usernames.length) {
        return res.status(400).json({ error: 'One or more usernames not found.' });
    }
    const accountIds = usersInChat.map(u => u.accountId);
    const groupId = getGroupId(accountIds);

    let invite = invites.find(i => i.groupId === groupId);
    if (!invite) {
        invite = {
            groupId,
            initiator: user.accountId,
            participants: accountIds,
            accepted: [user.accountId],
            rejected: [],
            timestamp: new Date().toISOString()
        };
        invites.push(invite);
    } else {
        invite.timestamp = new Date().toISOString();
        if (!invite.accepted.includes(user.accountId)) invite.accepted.push(user.accountId);
    }
    saveInvites();
    res.json({ groupId, participants: accountIds });
});

// --- OPEN CHATS ENDPOINT ---
app.post('/api/chat/open', (req, res) => {
    const { token } = req.body;
    const user = findUserByToken(token);
    if (!user) return res.status(401).json({ error: 'Unauthorized.' });
    const allMessages = getMessages();

    // --- GLOBAL CHATROOM ---
    const globalGroupId = getGlobalGroupId();
    const globalParticipants = getAllAccountIds();
    const globalMsgs = allMessages.filter(m => m.groupId === globalGroupId);
    const globalLastMsg = globalMsgs.length > 0
        ? globalMsgs.reduce((a, b) => new Date(a.timestamp) > new Date(b.timestamp) ? a : b)
        : null;

    // --- USER CHATS ---
    const openChats = {};
    for (const invite of invites) {
        if (
            invite.accepted.includes(user.accountId) &&
            invite.accepted.length >= 2 &&
            invite.accepted.includes(user.accountId)
        ) {
            const groupId = invite.groupId;
            // Find last message for this group
            const groupMsgs = allMessages.filter(m => m.groupId === groupId);
            const lastMessage = groupMsgs.length > 0
                ? groupMsgs.reduce((a, b) => new Date(a.timestamp) > new Date(b.timestamp) ? a : b)
                : null;
            openChats[groupId] = {
                groupId,
                participants: invite.accepted,
                lastMessage
            };
        }
    }
    // Add global chatroom
    openChats[globalGroupId] = {
        groupId: globalGroupId,
        participants: globalParticipants,
        lastMessage: globalLastMsg,
        isGlobal: true
    };

    // --- UNREAD COUNTS ---
    const userReads = reads[user.accountId] || {};
    for (const chat of Object.values(openChats)) {
        const groupId = chat.groupId;
        const lastRead = userReads[groupId] || 0;
        const groupMsgs = allMessages.filter(m => m.groupId === groupId);
        chat.unread = groupMsgs.filter(m => new Date(m.timestamp).getTime() > lastRead && m.username !== user.username).length;
    }

    // Only show chats where user is a participant (or global)
    const chatList = Object.values(openChats)
        .filter(chat => chat.isGlobal || chat.participants.includes(user.accountId))
        .sort((a, b) =>
            new Date((b.lastMessage && b.lastMessage.timestamp) || 0) -
            new Date((a.lastMessage && a.lastMessage.timestamp) || 0)
        );
    res.json({ chats: chatList });
});

// Create or update a chat invite
app.post('/api/chat/invite', (req, res) => {
    const { token, chatWith } = req.body;
    const user = findUserByToken(token);
    if (!user || !Array.isArray(chatWith) || chatWith.length < 2) {
        return res.status(400).json({ error: 'Invalid invite.' });
    }
    const groupId = getGroupId(chatWith);
    let invite = invites.find(i => i.groupId === groupId);
    if (!invite) {
        invite = {
            groupId,
            initiator: user.accountId,
            participants: chatWith,
            accepted: [user.accountId],
            rejected: [],
            timestamp: new Date().toISOString()
        };
        invites.push(invite);
    } else {
        // If already exists, update timestamp and add initiator to accepted
        invite.timestamp = new Date().toISOString();
        if (!invite.accepted.includes(user.accountId)) invite.accepted.push(user.accountId);
    }
    saveInvites();
    res.json({ success: true });
});

// Get pending invites for a user
app.post('/api/chat/invites', (req, res) => {
    const { token } = req.body;
    const user = findUserByToken(token);
    if (!user) return res.status(401).json({ error: 'Unauthorized.' });
    const pending = invites.filter(i =>
        i.participants.includes(user.accountId) &&
        !i.accepted.includes(user.accountId) &&
        !i.rejected.includes(user.accountId)
    );
    res.json({ invites: pending });
});

// Accept or reject an invite
app.post('/api/chat/invite/respond', (req, res) => {
    const { token, groupId, accept } = req.body;
    const user = findUserByToken(token);
    if (!user) return res.status(401).json({ error: 'Unauthorized.' });
    const invite = invites.find(i => i.groupId === groupId);
    if (!invite || !invite.participants.includes(user.accountId)) {
        return res.status(400).json({ error: 'Invite not found.' });
    }
    if (accept) {
        if (!invite.accepted.includes(user.accountId)) invite.accepted.push(user.accountId);
        // Remove from rejected if previously rejected
        invite.rejected = invite.rejected.filter(id => id !== user.accountId);
    } else {
        if (!invite.rejected.includes(user.accountId)) invite.rejected.push(user.accountId);
        // Remove from accepted if previously accepted
        invite.accepted = invite.accepted.filter(id => id !== user.accountId);
    }
    saveInvites();
    res.json({ success: true });
});

// --- GLOBAL CHAT SEND SUPPORT ---
app.post('/api/chat/send', (req, res) => {
    const { token, username, chatWithUsernames, chatWith, encrypted, groupId } = req.body;
    const user = findUserByToken(token);
    if (!user || user.username !== username) {
        return res.status(401).json({ error: 'Unauthorized.' });
    }
    let participants = chatWith;
    let gid = groupId;
    if (groupId === 'global') {
        gid = 'global';
        participants = getAllAccountIds();
    } else if (Array.isArray(chatWithUsernames)) {
        participants = chatWithUsernames.map(u => {
            const found = users.find(x => x.username === u);
            return found ? found.accountId : null;
        }).filter(Boolean);
        gid = getGroupId(participants);
    } else if (Array.isArray(chatWith)) {
        gid = getGroupId(chatWith);
    }
    if (!Array.isArray(participants) || participants.length < 2) {
        return res.status(400).json({ error: 'chatWith must be an array of account IDs or usernames (including your own).' });
    }
    if (typeof encrypted !== 'object' || !encrypted.iv || !encrypted.data) {
        return res.status(400).json({ error: 'Encrypted message is required.' });
    }
    // For global, allow all
    if (gid === 'global') {
        addMessage({ username: username.trim(), groupId: gid, encrypted, participants });
        return res.json({ success: true });
    }
    const invite = invites.find(i => i.groupId === gid);
    if (
        !invite ||
        !invite.accepted.includes(user.accountId) ||
        invite.accepted.length < 2
    ) {
        return res.status(403).json({ error: 'Not enough participants have accepted the chat.' });
    }
    addMessage({ username: username.trim(), groupId: gid, encrypted, participants: invite.accepted });
    res.json({ success: true });
});

// Add endpoint to resolve accountIds to usernames
app.post('/api/auth/usernames', (req, res) => {
    const { accountIds } = req.body;
    if (!Array.isArray(accountIds)) return res.json({ usernames: {} });
    const usernames = {};
    for (const id of accountIds) {
        const user = users.find(u => u.accountId === id);
        if (user) usernames[id] = user.username;
    }
    res.json({ usernames });
});

// Read receipts endpoint
app.post('/api/chat/readreceipts', (req, res) => {
    const { token, groupId, messageTimestamps } = req.body;
    const user = findUserByToken(token);
    if (!user || !groupId || !Array.isArray(messageTimestamps)) {
        return res.json({ readReceipts: {} });
    }
    // For each message timestamp, return which users have read it (based on their last read timestamp for this group)
    const receipts = {};
    for (const ts of messageTimestamps) {
        receipts[ts] = [];
        for (const u of users) {
            const userReads = reads[u.accountId] || {};
            const lastRead = userReads[groupId] || 0;
            if (new Date(ts).getTime() <= lastRead) {
                receipts[ts].push(u.accountId);
            }
        }
    }
    res.json({ readReceipts: receipts });
});

app.listen(PORT, () => {
    console.log(`Chat backend running at http://localhost:${PORT}`);
});