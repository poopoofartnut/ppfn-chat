const API_URL = 'http://localhost:3000/api/chat';

const messagesDiv = document.getElementById('messages');
const form = document.getElementById('chat-form');
const input = document.getElementById('message-input');
const usernameInput = document.getElementById('username-input');
const sendBtn = document.getElementById('send-btn');
const groupInput = document.getElementById('group-input');
const passphraseInput = document.getElementById('passphrase-input');
const signupForm = document.getElementById('signup-form');
const signinForm = document.getElementById('signin-form');
const chatContainer = document.getElementById('chat-container');
const authContainer = document.getElementById('auth-container');
const chatWithInput = document.getElementById('chatwith-input');
const accountInfoDiv = document.getElementById('account-info');
const openChatsUl = document.getElementById('open-chats');
const chatTitleDiv = document.getElementById('chat-title');
const chatParticipantsDiv = document.getElementById('chat-participants');

let username = localStorage.getItem('chat-username') || '';
let group = localStorage.getItem('chat-group') || '';
let passphrase = '';
let token = localStorage.getItem('chat-token') || '';
let accountId = '';
let chatWith = []; // Array of account IDs for the current chat
let groupKey = null;
let openChats = [];
let activeGroupId = null;
let pollInterval = null;
let accountIdToUsername = {}; // accountId -> username
let lastReadTimestamps = {}; // groupId -> timestamp

function setUsername(name) {
    username = name.trim();
    localStorage.setItem('chat-username', username);
    usernameInput.value = username;
    usernameInput.readOnly = true; // Make username input read-only after login
}

function setGroup(name) {
    group = name.trim();
    localStorage.setItem('chat-group', group);
}

function showChatUI(show) {
    chatContainer.style.display = show ? '' : 'none';
    authContainer.style.display = show ? 'none' : '';
    if (show) {
        startPolling();
    } else {
        stopPolling();
    }
}

function setToken(t) {
    token = t;
    localStorage.setItem('chat-token', t);
}

function logout() {
    setToken('');
    username = '';
    localStorage.removeItem('chat-username');
    usernameInput.value = '';
    usernameInput.readOnly = false;
    showChatUI(false);
    openChatsUl.innerHTML = '';
    openChats = [];
    activeGroupId = null;
    stopPolling();
}

function showAccountInfo(id, pass) {
    accountInfoDiv.innerHTML = `
        <div>
            <b>Your Account ID:</b> <code>${id}</code><br>
            <b>Your Passphrase:</b> <code>${pass}</code>
        </div>
        <small>Share your Account ID with others to chat. Keep your passphrase secret.</small>
    `;
    accountInfoDiv.style.display = '';
}

async function fetchAccountInfo() {
    const res = await fetch(`${API_URL.replace('/chat', '')}/auth/accountinfo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
    });
    const data = await res.json();
    if (data.accountId && data.passphrase) {
        accountId = data.accountId;
        passphrase = data.passphrase;
        showAccountInfo(accountId, passphrase);
    }
}

async function performHandshake(usernames) {
    const res = await fetch(`${API_URL.replace('/chat', '')}/chat/handshake`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, usernames })
    });
    const data = await res.json();
    if (!data.handshake) {
        alert(data.error || 'Handshake failed');
        return null;
    }
    // Update accountIdToUsername map
    data.handshake.forEach(u => {
        if (u.accountId && u.username) accountIdToUsername[u.accountId] = u.username;
    });
    return data.handshake;
}

async function deriveGroupKeyFromHandshake(handshake) {
    // Sort by accountId for deterministic key
    const sorted = [...handshake].sort((a, b) => a.accountId.localeCompare(b.accountId));
    const passphrases = sorted.map(u => u.username === username ? passphrase : u.passphrase);
    const combined = passphrases.join(':');
    const enc = new TextEncoder();
    const baseKey = await window.crypto.subtle.importKey(
        'raw',
        enc.encode(combined),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
    return window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: enc.encode('ppfn-chat-salt'),
            iterations: 100000,
            hash: 'SHA-256'
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

function formatTime(iso) {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// --- Chat header rendering ---
function renderChatHeader() {
    if (!chatWith || chatWith.length === 0) {
        chatTitleDiv.textContent = '';
        chatParticipantsDiv.innerHTML = '';
        return;
    }
    const isGlobal = activeGroupId === 'global';
    if (isGlobal) {
        chatTitleDiv.textContent = '🌐 Global Chat';
    } else {
        const names = chatWith
            .map(id => id === accountId ? username : (accountIdToUsername[id] || id))
            .filter(u => u !== username);
        chatTitleDiv.textContent = names.join(', ');
    }
    chatParticipantsDiv.innerHTML = '';
    chatWith.forEach(id => {
        const uname = id === accountId ? username : (accountIdToUsername[id] || id);
        const avatar = document.createElement('span');
        avatar.className = 'avatar';
        avatar.title = uname;
        avatar.textContent = uname[0] ? uname[0].toUpperCase() : '?';
        chatParticipantsDiv.appendChild(avatar);
    });
}

async function appendMessage(msg, readReceiptsMap) {
    const div = document.createElement('div');
    div.className = 'message';
    const text = await decryptMessage(msg.encrypted);
    div.innerHTML = `<span class="meta">${msg.username || 'Anonymous'} @ ${formatTime(msg.timestamp)}</span><br>
        <span class="text">${text}</span>`;
    // Read receipts
    if (readReceiptsMap && readReceiptsMap[msg.timestamp]) {
        const rrDiv = document.createElement('div');
        rrDiv.className = 'read-receipts';
        readReceiptsMap[msg.timestamp].forEach(id => {
            if (id === accountId) return;
            const uname = accountIdToUsername[id] || id;
            const avatar = document.createElement('span');
            avatar.className = 'avatar';
            avatar.title = uname;
            avatar.textContent = uname[0] ? uname[0].toUpperCase() : '?';
            rrDiv.appendChild(avatar);
        });
        if (rrDiv.childNodes.length > 0) {
            div.appendChild(rrDiv);
        }
    }
    messagesDiv.appendChild(div);
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

// --- Read receipts support ---
async function fetchReadReceipts(groupId, messages) {
    // Returns: { [msgTimestamp]: [accountId, ...] }
    const res = await fetch(`${API_URL.replace('/chat', '')}/chat/readreceipts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, groupId, messageTimestamps: messages.map(m => m.timestamp) })
    });
    return await res.json();
}

async function fetchMessages() {
    if (!chatWith || chatWith.length < 2) return;
    let groupId = activeGroupId;
    const res = await fetch(`${API_URL}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, chatWith, groupId })
    });
    const data = await res.json();
    messagesDiv.innerHTML = '';
    // Find unread boundary
    let unreadLineDrawn = false;
    let lastRead = 0;
    if (groupId && lastReadTimestamps[groupId]) {
        lastRead = lastReadTimestamps[groupId];
    }
    // Mark last read timestamp now
    lastReadTimestamps[groupId] = Date.now();
    // Fetch read receipts for all messages
    let readReceiptsMap = {};
    if (data.messages && data.messages.length > 0) {
        readReceiptsMap = (await fetchReadReceipts(groupId, data.messages)).readReceipts || {};
    }
    for (const msg of data.messages) {
        const msgTime = new Date(msg.timestamp).getTime();
        if (!unreadLineDrawn && lastRead && msgTime > lastRead && msg.username !== username) {
            // Draw unread line
            const line = document.createElement('div');
            line.className = 'unread-line';
            line.textContent = 'Unread messages';
            messagesDiv.appendChild(line);
            unreadLineDrawn = true;
        }
        await appendMessage(msg, readReceiptsMap);
    }
    // Set activeGroupId for highlighting
    if (data.messages && data.messages.length > 0) {
        activeGroupId = data.messages[0].groupId;
        renderOpenChats();
    }
    renderChatHeader();
}

// --- Remove requirement to include your own username when starting a chat ---
document.getElementById('start-chat-btn').addEventListener('click', async () => {
    // User enters comma-separated usernames (do NOT require own username)
    let usernames = chatWithInput.value.split(',').map(x => x.trim()).filter(Boolean);
    if (usernames.length < 1) {
        alert('Enter at least one username.');
        return;
    }
    // Always add own username if not present for handshake and chatWith
    if (!usernames.includes(username)) {
        usernames = [username, ...usernames];
    }
    const chatData = await startChatWithUsernames(usernames);
    if (!chatData) return;
    // Handshake for key derivation
    const handshake = await performHandshake(usernames);
    if (!handshake) return;
    handshake.forEach(u => {
        if (u.accountId && u.username) accountIdToUsername[u.accountId] = u.username;
    });
    groupKey = await deriveGroupKeyFromHandshake(handshake);
    chatWith = chatData.participants;
    await fetchMessages();
    await fetchOpenChats();
    renderChatHeader();
});

signupForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = signupForm.elements['signup-username'].value.trim();
    const password = signupForm.elements['signup-password'].value;
    if (!username || !password) return;
    const res = await fetch(`${API_URL.replace('/chat', '')}/auth/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    if (data.token) {
        setToken(data.token);
        setUsername(username);
        showChatUI(true);
        await fetchAccountInfo();
        await fetchOpenChats();
        startPolling();
    } else {
        alert(data.error || 'Sign up failed');
    }
});

signinForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = signinForm.elements['signin-username'].value.trim();
    const password = signinForm.elements['signin-password'].value;
    if (!username || !password) return;
    const res = await fetch(`${API_URL.replace('/chat', '')}/auth/signin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    });
    const data = await res.json();
    if (data.token) {
        setToken(data.token);
        setUsername(username);
        showChatUI(true);
        await fetchAccountInfo();
        await fetchOpenChats();
        startPolling();
    } else {
        alert(data.error || 'Sign in failed');
    }
});

document.getElementById('logout-btn').addEventListener('click', logout);

const invitePopupContainer = document.createElement('div');
invitePopupContainer.style.position = 'fixed';
invitePopupContainer.style.bottom = '20px';
invitePopupContainer.style.right = '20px';
invitePopupContainer.style.zIndex = '9999';
document.body.appendChild(invitePopupContainer);

async function sendInvite(ids) {
    await fetch(`${API_URL.replace('/chat', '')}/chat/invite`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, chatWith: ids })
    });
}

async function fetchInvites() {
    if (!token) return;
    const res = await fetch(`${API_URL.replace('/chat', '')}/chat/invites`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
    });
    const data = await res.json();
    showInvitePopups(data.invites || []);
}

function showInvitePopups(invites) {
    invitePopupContainer.innerHTML = '';
    invites.forEach(invite => {
        const div = document.createElement('div');
        div.style.background = '#fff';
        div.style.border = '1px solid #007bff';
        div.style.borderRadius = '8px';
        div.style.padding = '12px 16px';
        div.style.marginTop = '10px';
        div.style.boxShadow = '0 2px 8px rgba(0,0,0,0.12)';
        div.style.minWidth = '260px';
        div.innerHTML = `
            <b>Chat Invite</b><br>
            From: <code>${invite.initiator}</code><br>
            Participants: <code>${invite.participants.join(', ')}</code><br>
            <button class="accept-btn">Accept</button>
            <button class="reject-btn">Reject</button>
        `;
        div.querySelector('.accept-btn').onclick = async () => {
            await respondToInvite(invite.groupId, true);
            div.remove();
            await fetchOpenChats();
            await fetchMessages();
        };
        div.querySelector('.reject-btn').onclick = async () => {
            await respondToInvite(invite.groupId, false);
            div.remove();
            await fetchOpenChats();
        };
        invitePopupContainer.appendChild(div);
    });
}

// Only allow sending messages if chat is in openChats (user accepted and at least one other accepted)
function isChatOpen() {
    return openChats.some(chat =>
        chat.groupId === activeGroupId &&
        chat.participants.includes(accountId) &&
        chat.participants.length >= 2
    );
}

async function startChatWithUsernames(usernames) {
    const res = await fetch(`${API_URL.replace('/chat', '')}/chat/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, usernames })
    });
    const data = await res.json();
    if (!data.groupId || !data.participants) {
        alert(data.error || 'Failed to start chat');
        return null;
    }
    return data;
}

form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const message = input.value.trim();
    const name = username;
    if (!token) {
        alert('You must be signed in.');
        return;
    }
    if (!name) {
        alert('Please sign in.');
        return;
    }
    if (!chatWith || chatWith.length < 2) {
        alert('Start a chat first.');
        return;
    }
    if (!groupKey) {
        alert('No group key.');
        return;
    }
    if (!isChatOpen()) {
        alert('You must accept the chat invite and at least one other participant must accept.');
        return;
    }
    if (!message) return;
    sendBtn.disabled = true;
    const resp = await fetch(`${API_URL}/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            token,
            username: name,
            chatWith,
            encrypted: await encryptMessage(message)
        })
    });
    input.value = '';
    sendBtn.disabled = false;
    input.focus();
    await fetchMessages();
    await fetchOpenChats();
});

input.addEventListener('input', () => {
    sendBtn.disabled = !input.value.trim();
});

function startPolling() {
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(() => {
        if (token) {
            fetchMessages();
            fetchOpenChats();
            fetchInvites();
        }
    }, 2000);
}

function stopPolling() {
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = null;
}

// Only start polling after login/signup is successful
if (token) {
    startPolling();
}

async function encryptMessage(plain) {
    if (!groupKey) throw new Error('No group key');
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const ciphertext = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        groupKey,
        enc.encode(plain)
    );
    return {
        iv: Array.from(iv),
        data: Array.from(new Uint8Array(ciphertext))
    };
}

async function decryptMessage(encMsg) {
    try {
        if (!groupKey) return '[No group key]';
        const iv = new Uint8Array(encMsg.iv);
        const data = new Uint8Array(encMsg.data);
        const plain = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            groupKey,
            data
        );
        return new TextDecoder().decode(plain);
    } catch {
        return '[Unable to decrypt]';
    }
}

// Add the missing respondToInvite function
async function respondToInvite(groupId, accept) {
    await fetch(`${API_URL.replace('/chat', '')}/chat/invite/respond`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, groupId, accept })
    });
    await fetchOpenChats();
}

// Automatically fetch usernames for all participants from the server (no prompt)
async function ensureUsernamesForChat(chat) {
    const missingIds = chat.participants.filter(
        id => !accountIdToUsername[id] && id !== accountId
    );
    if (missingIds.length === 0) return;
    const res = await fetch(`${API_URL.replace('/chat', '')}/auth/usernames`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ accountIds: missingIds })
    });
    const data = await res.json();
    if (data && data.usernames) {
        Object.entries(data.usernames).forEach(([id, uname]) => {
            if (id && uname) accountIdToUsername[id] = uname;
        });
    }
}

// Add CSS for unread badge and unread line (append to style.css if not present)
/*
.unread-badge {
    display: inline-block;
    background: #ef4444;
    color: #fff;
    border-radius: 50%;
    padding: 2px 8px;
    font-size: 0.9em;
    margin-left: 8px;
    font-weight: bold;
    vertical-align: middle;
}
.unread-line {
    width: 100%;
    text-align: center;
    color: #ef4444;
    font-weight: bold;
    margin: 18px 0 8px 0;
    border-bottom: 2px solid #ef4444;
    line-height: 1.6;
}
*/

function renderOpenChats() {
    openChatsUl.innerHTML = '';
    openChats.forEach(chat => {
        // Use accountIdToUsername mapping for all participants
        const usernames = chat.participants.map(id =>
            id === accountId ? username : (accountIdToUsername[id] || id)
        );
        const li = document.createElement('li');
        li.textContent = chat.isGlobal ? '🌐 Global Chat' : usernames.filter(u => u !== username).join(', ');
        if (chat.groupId === activeGroupId) li.classList.add('active');
        // Unread badge
        if (chat.unread && chat.unread > 0) {
            const badge = document.createElement('span');
            badge.textContent = chat.unread;
            badge.className = 'unread-badge';
            li.appendChild(badge);
        }
        li.onclick = async () => {
            await ensureUsernamesForChat(chat);
            const resolvedUsernames = chat.participants.map(id =>
                id === accountId ? username : (accountIdToUsername[id] || id)
            );
            chatWithInput.value = chat.isGlobal ? '' : resolvedUsernames.filter(u => u !== username).join(', ');
            let handshake = null;
            if (!chat.isGlobal) {
                handshake = await performHandshake(resolvedUsernames);
                if (!handshake) return;
                groupKey = await deriveGroupKeyFromHandshake(handshake);
                chatWith = chat.participants;
            } else {
                groupKey = await deriveGroupKeyFromHandshake(
                    chat.participants.map(id => ({
                        username: accountIdToUsername[id] || id,
                        accountId: id,
                        passphrase: id === accountId ? passphrase : null
                    }))
                );
                chatWith = chat.participants;
            }
            activeGroupId = chat.groupId;
            await fetchMessages();
            renderOpenChats();
            renderChatHeader();
        };
        openChatsUl.appendChild(li);
    });
    renderChatHeader();
}

async function fetchOpenChats() {
    if (!token) return;
    const res = await fetch(`${API_URL.replace('/chat', '')}/chat/open`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
    });
    const data = await res.json();
    openChats = data.chats || [];
    renderOpenChats();
}