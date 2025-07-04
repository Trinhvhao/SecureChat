// Chat data
const chatData = {
    1: {
        name: 'Vi Hiếu',
        avatar: 'https://i.pravatar.cc/50?img=2',
        messages: [
            { type: 'received', content: 'Hiii 🔥', time: 'May 31, 2025, 9:26 AM' }
        ]
    },
    2: {
        name: 'Nguyen Khoa',
        avatar: 'https://i.pravatar.cc/50?img=3',
        messages: [
            { type: 'received', content: 'Hey, làm sao để code React hooks?', time: 'April 12, 2025, 2:15 PM' },
            { type: 'sent', content: 'Bạn có thể bắt đầu với useState và useEffect', time: 'April 12, 2025, 2:18 PM' },
            { type: 'received', content: 'Cảm ơn bạn! 👍', time: 'April 12, 2025, 2:20 PM' }
        ]
    },
    3: {
        name: 'Nguyễn Tài',
        avatar: 'https://i.pravatar.cc/50?img=4',
        messages: [
            { type: 'sent', content: 'Chào bạn, dự án thế nào rồi?', time: 'March 28, 2025, 10:30 AM' },
            { type: 'received', content: 'Đang làm phần authentication', time: 'March 28, 2025, 10:45 AM' },
            { type: 'sent', content: 'OK, cần giúp gì không?', time: 'March 28, 2025, 10:46 AM' }
        ]
    },
    4: {
        name: 'Văn Chi',
        avatar: 'https://i.pravatar.cc/50?img=5',
        messages: [
            { type: 'received', content: 'Meeting lúc 3h chiều nha', time: 'March 25, 2025, 9:00 AM' },
            { type: 'sent', content: 'OK bạn, mình sẽ chuẩn bị slide', time: 'March 25, 2025, 9:05 AM' }
        ]
    },
    5: {
        name: 'Đỗ Tài',
        avatar: 'https://i.pravatar.cc/50?img=6',
        messages: [
            { type: 'received', content: 'Source code mình gửi qua email rồi nhé', time: 'March 5, 2025, 4:20 PM' },
            { type: 'sent', content: 'Cảm ơn bạn nhiều!', time: 'March 5, 2025, 4:25 PM' }
        ]
    },
    6: {
        name: 'Tuan Le Anh',
        avatar: 'https://i.pravatar.cc/50?img=7',
        messages: [
            { type: 'sent', content: 'Cuối tuần đi cafe không?', time: 'March 1, 2025, 11:00 AM' },
            { type: 'received', content: 'OK, mình rảnh cả ngày', time: 'March 1, 2025, 11:15 AM' },
            { type: 'sent', content: 'Vậy 10h sáng nhé', time: 'March 1, 2025, 11:16 AM' }
        ]
    },
    7: {
        name: 'Wong Ji Kim',
        avatar: 'https://i.pravatar.cc/50?img=8',
        messages: [
            { type: 'received', content: 'Hello, can we discuss about the project?', time: 'February 20, 2025, 3:00 PM' }
        ]
    }
};

// DOM elements
const chatItems = document.querySelectorAll('.chat-item');
const chatMessages = document.getElementById('chatMessages');
const chatHeaderInfo = document.querySelector('.chat-header-info');
const profileSection = document.querySelector('.profile-section');

// Function to render messages
function renderMessages(chatId) {
    const chat = chatData[chatId];
    if (!chat) return;

    // Clear current messages
    chatMessages.innerHTML = '';

    // Add date if first message has time
    if (chat.messages.length > 0 && chat.messages[0].time) {
        const dateDiv = document.createElement('div');
        dateDiv.className = 'message-date';
        dateDiv.textContent = chat.messages[0].time.split(',')[0] + ',' + chat.messages[0].time.split(',')[1];
        chatMessages.appendChild(dateDiv);
    }

    // Render each message
    chat.messages.forEach((msg, index) => {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${msg.type}`;

        if (msg.type === 'received') {
            messageDiv.innerHTML = `
                <img src="${chat.avatar}" alt="${chat.name}">
                <div class="message-content">
                    <p>${msg.content}</p>
                </div>
            `;
        } else {
            const isThumbsUp = msg.content === '👍';
            messageDiv.innerHTML = `
                <div class="message-content${isThumbsUp ? ' thumbs-up' : ''}">
                    <p>${msg.content}</p>
                </div>
            `;
        }

        chatMessages.appendChild(messageDiv);
    });

    // Add encryption notice after first message
    if (chat.messages.length > 0) {
        const encryptionNotice = document.createElement('div');
        encryptionNotice.className = 'encryption-notice';
        encryptionNotice.innerHTML = `
            <i class="fas fa-lock"></i>
            <p>New messages and calls are secured with end-to-end encryption. Only people in this chat can read, listen to, or share them. <a href="#">Learn more</a></p>
        `;
        chatMessages.appendChild(encryptionNotice);
    }

    // Add missing messages notice
    const missingNotice = document.createElement('div');
    missingNotice.className = 'messages-missing';
    missingNotice.innerHTML = 'Messages are missing. <a href="#">Restore now</a>';
    chatMessages.appendChild(missingNotice);

    // Scroll to bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Function to update chat header
function updateChatHeader(chatId) {
    const chat = chatData[chatId];
    if (!chat) return;

    chatHeaderInfo.innerHTML = `
        <img src="${chat.avatar}" alt="${chat.name}">
        <h3>${chat.name}</h3>
    `;
}

// Function to update profile info
function updateProfileInfo(chatId) {
    const chat = chatData[chatId];
    if (!chat) return;

    profileSection.innerHTML = `
        <img src="${chat.avatar.replace('50', '80')}" alt="${chat.name}">
        <h3>${chat.name}</h3>
        <div class="encryption-status">
            <i class="fas fa-lock"></i>
            <span>End-to-end encrypted</span>
        </div>
        <div class="profile-actions">
            <button>
                <i class="fas fa-user-circle"></i>
                <span>Profile</span>
            </button>
            <button>
                <i class="fas fa-bell-slash"></i>
                <span>Mute</span>
            </button>
            <button>
                <i class="fas fa-search"></i>
                <span>Search</span>
            </button>
        </div>
    `;
}

// Add click event to chat items
chatItems.forEach(item => {
    item.addEventListener('click', function() {
        // Remove active class from all items
        chatItems.forEach(chat => chat.classList.remove('active'));

        // Add active class to clicked item
        this.classList.add('active');

        // Get chat ID
        const chatId = this.getAttribute('data-chat-id');

        // Update chat window
        renderMessages(chatId);
        updateChatHeader(chatId);
        updateProfileInfo(chatId);
    });
});

// Initialize with first chat
renderMessages(1);
updateChatHeader(1);
updateProfileInfo(1);

// Function to send message
function sendMessage(content, isThumbsUp) {
    const activeChat = document.querySelector('.chat-item.active');
    const chatId = activeChat.getAttribute('data-chat-id');

    // Create message element
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message sent';

    if (isThumbsUp) {
        messageDiv.innerHTML = `
            <div class="message-content thumbs-up">
                <p>${content}</p>
            </div>
        `;
    } else {
        messageDiv.innerHTML = `
            <div class="message-content">
                <p>${content}</p>
            </div>
        `;
    }

    // Add message before missing messages notice
    const missingNotice = chatMessages.querySelector('.messages-missing');
    if (missingNotice) {
        chatMessages.insertBefore(messageDiv, missingNotice);
    } else {
        chatMessages.appendChild(messageDiv);
    }

    // Update chat data
    const currentTime = new Date().toLocaleString('en-US', {
        month: 'long',
        day: 'numeric',
        year: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        hour12: true
    });

    chatData[chatId].messages.push({
        type: 'sent',
        content: content,
        time: currentTime
    });

    // Scroll to bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Update UI based on input
const messageInput = document.querySelector('#messageInput');
const sendButton = document.querySelector('#sendButton');
const inputActions = document.querySelector('.input-actions');

messageInput.addEventListener('input', function() {
    if (this.value.trim() !== '') {
        // Has text - show paper plane and hide extra icons
        sendButton.innerHTML = '<i class="fas fa-paper-plane"></i>';
        inputActions.classList.add('typing');
    } else {
        // No text - show thumbs up and show all icons
        sendButton.innerHTML = '<i class="fas fa-thumbs-up"></i>';
        inputActions.classList.remove('typing');
    }
});

// Add click event for send button
sendButton.addEventListener('click', function() {
    const messageText = messageInput.value.trim();

    if (messageText === '') {
        // Send thumbs up if no text
        sendMessage('👍', true);
    } else {
        // Send text message
        sendMessage(messageText, false);
        messageInput.value = '';
        // Reset UI after sending
        sendButton.innerHTML = '<i class="fas fa-thumbs-up"></i>';
        inputActions.classList.remove('typing');
    }
});

// Add enter key event for sending messages
messageInput.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        const messageText = this.value.trim();
        if (messageText !== '') {
            sendMessage(messageText, false);
            this.value = '';
            // Reset UI after sending
            sendButton.innerHTML = '<i class="fas fa-thumbs-up"></i>';
            inputActions.classList.remove('typing');
        }
    }
});

// Dark mode toggle
const themeToggle = document.getElementById('themeToggle');
const body = document.body;

// Check for saved theme preference
const currentTheme = localStorage.getItem('theme') || 'light';
if (currentTheme === 'dark') {
    body.classList.add('dark-mode');
    themeToggle.innerHTML = '<i class="fas fa-sun"></i>';
}

themeToggle.addEventListener('click', function() {
    // Add animation class
    this.classList.add('switching');

    // Wait a bit before changing theme for smooth transition
    setTimeout(() => {
        body.classList.toggle('dark-mode');

        if (body.classList.contains('dark-mode')) {
            localStorage.setItem('theme', 'dark');
            this.innerHTML = '<i class="fas fa-sun"></i>';
        } else {
            localStorage.setItem('theme', 'light');
            this.innerHTML = '<i class="fas fa-moon"></i>';
        }

        // Remove animation class after completion
        setTimeout(() => {
            this.classList.remove('switching');
        }, 500);
    }, 200);
});

// Profile dropdown
const profileDropdown = document.getElementById('profileDropdown');
profileDropdown.addEventListener('click', function(e) {
    e.stopPropagation();
    this.classList.toggle('active');
});

// Close dropdown when clicking outside
document.addEventListener('click', function() {
    profileDropdown.classList.remove('active');
});

// Status dot toggle (online/offline)
let isOnline = true;
const statusDot = document.querySelector('.status-dot');

document.querySelector('.dropdown-item:first-child').addEventListener('click', function() {
    isOnline = !isOnline;
    statusDot.style.backgroundColor = isOnline ? '#31a24c' : '#f02849';
});

// Add click events for section headers
document.addEventListener('click', function(e) {
    if (e.target.closest('.section-header')) {
        const header = e.target.closest('.section-header');
        header.classList.toggle('expanded');
    }
});

// Add hover effect for input buttons
const inputButtons = document.querySelectorAll('.input-actions i, .input-field i');
inputButtons.forEach(btn => {
    btn.addEventListener('mouseenter', function() {
        this.style.transform = 'scale(1.1)';
    });
    btn.addEventListener('mouseleave', function() {
        this.style.transform = 'scale(1)';
    });
});
