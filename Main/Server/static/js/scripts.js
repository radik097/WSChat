function generateKey() {
    return forge.random.getBytesSync(16);  // AES-128 key
}
async function fetchJSON(url) {
    const response = await fetch(url);
    if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
    }
    return await response.json();
}
function encryptMessage(key, message) {
    const iv = forge.random.getBytesSync(16);
    const cipher = forge.cipher.createCipher('AES-CBC', key);
    cipher.start({ iv: iv });
    cipher.update(forge.util.createBuffer(message, 'utf8'));
    cipher.finish();
    return {
        iv: iv,
        encrypted: cipher.output.getBytes()
    };
}

function decryptMessage(key, iv, encrypted) {
    const decipher = forge.cipher.createDecipher('AES-CBC', key);
    decipher.start({ iv: iv });
    decipher.update(forge.util.createBuffer(encrypted));
    const result = decipher.finish();
    return result ? decipher.output.toString('utf8') : null;
}

async function sendMessage() {
    const key = sessionStorage.getItem('encryptionKey');
    const message = document.getElementById('messageInput').value;
    const username = document.getElementById('usernameInput').value;
    const encryptedData = encryptMessage(key, message);

    const payload = {
        SenderId: sessionStorage.getItem('username'),
        ReceiverId: username,
        EncryptedData: forge.util.encode64(encryptedData.encrypted),
        Iv: forge.util.encode64(encryptedData.iv)
    };

    try {
        const response = await fetch('/api/message/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            document.getElementById('messageInput').value = '';
            receiveMessages();
        }
    } catch (error) {
        console.error("Error sending message:", error);
    }
}

let lastMessageTimestamp = null;  // Глобальная переменная для отслеживания времени последнего сообщения

async function receiveMessages() {
    const username = sessionStorage.getItem('username');
    if (!username) {
        console.error("Username is not stored in session!");
        return;
    }

    try {
        const messages = await fetchJSON(`/api/message/receive?userId=${username}`);
        const key = sessionStorage.getItem('encryptionKey');
        if (!key) {
            console.error("Encryption key is missing!");
            return;
        }

        const messagesList = document.getElementById('chat');
        const currentMessages = messages.filter(msg => new Date(msg.timestamp) > new Date(lastMessageTimestamp));

        for (const msg of currentMessages) {
            if (!msg.iv || !msg.encryptedData || !msg.senderUsername) {
                console.error("Missing Iv, EncryptedData, or senderUsername in the message:", msg);
                continue;
            }

            try {
                const iv = forge.util.decode64(msg.iv);
                const encrypted = forge.util.decode64(msg.encryptedData);
                const decryptedMessage = decryptMessage(key, iv, encrypted);

                const listItem = document.createElement('li');
                listItem.className = (msg.senderUsername === username) ? 'message right' : 'message left';

                loadUserAvatar(msg.senderUsername, function(avatar) {
                    if (!avatar) {
                        console.error("Failed to load user avatar!");
                        return;
                    }
                    listItem.innerHTML = `<img class="logo" src="${avatar}" alt=""><p>${decryptedMessage}</p>`;
                    messagesList.appendChild(listItem);
                });
            } catch (error) {
                console.error("Error during decryption:", error);
            }
        }

        if (currentMessages.length > 0) {
            lastMessageTimestamp = currentMessages[currentMessages.length - 1].timestamp;
        }
    } catch (error) {
        console.error("Error receiving messages:", error);
    }
}


window.onload = function() {
    let encryptionKey = sessionStorage.getItem('encryptionKey');
    if (!encryptionKey) {
        const key = generateKey();
        sessionStorage.setItem('encryptionKey', key);
    }

    loadUsers();
    if (window.location.pathname === '/') {
        receiveMessages();
        setInterval(receiveMessages, 15000);
    }
};


function loadUsers() {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/users', true);
    xhr.onload = function() {
        if (xhr.status === 200) {
            const users = JSON.parse(xhr.responseText);
            const select = document.getElementById('usernameInput');
            select.innerHTML = ''; // Очистить перед добавлением новых пользователей

            users.forEach(function(user) {
                const option = document.createElement('option');
                option.value = user.username;
                option.textContent = user.username;
                select.appendChild(option);
            });

            // Инициализировать sessionStorage текущим значением
            if (select.options.length > 0) {
                select.value = users[0].username;
                sessionStorage.setItem('username', select.value);
            }
        }
    };
    xhr.send();
}
function loadUserAvatar(username, callback) {
    const cachedAvatar = localStorage.getItem(`avatar_${username}`);
    if (cachedAvatar) {
        callback(cachedAvatar);
        return;
    }

    var xhr = new XMLHttpRequest();
    xhr.open('GET', `/api/user/avatar?username=${encodeURIComponent(username)}`, true);
    xhr.onload = function() {
        if (xhr.status === 200) {
            const data = JSON.parse(xhr.responseText);
            const avatar = data.ProfilePhoto ? `data:image/png;base64,${data.ProfilePhoto}` : 'https://randomuser.me/api/portraits/men/67.jpg';
            localStorage.setItem(`avatar_${username}`, avatar);  // Сохранение в кэш
            callback(avatar);
        } else {
            callback('https://randomuser.me/api/portraits/men/67.jpg');
        }
    };
    xhr.onerror = function() {
        callback('https://randomuser.me/api/portraits/men/67.jpg');
    };
    xhr.send();
}

function loadChatForUser() {
    const select = document.getElementById('usernameInput');
    const selectedUsername = select.value;
    sessionStorage.setItem('username', selectedUsername);
    
    loadUserAvatar(selectedUsername, function(avatar) {
        document.getElementById('userAvatar').src = avatar;
        receiveMessages();
    });
}

window.onload = function() {
    const encryptionKey = sessionStorage.getItem('encryptionKey');
    if (!encryptionKey) {
        const key = generateKey();
        sessionStorage.setItem('encryptionKey', key);
    }

    loadUsers();
    if (window.location.pathname === '/') {
        receiveMessages();
        setInterval(receiveMessages, 15000); // обновляем сообщения каждые 5 секунд
    }
};
