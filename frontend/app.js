let socket;
let currentUser;
let currentChatroom;

// DOM Elements
const authSection = document.getElementById('auth-section');
const chatroomSection = document.getElementById('chatroom-section');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const loginBtn = document.getElementById('login-btn');
const registerBtn = document.getElementById('register-btn');
const chatroomNameInput = document.getElementById('chatroom-name');
const createJoinBtn = document.getElementById('create-join-btn');
const messageInput = document.getElementById('message-input');
const sendBtn = document.getElementById('send-btn');
const messagesDiv = document.getElementById('messages');
const authErrorDiv = document.getElementById('auth-error');
const chatroomErrorDiv = document.getElementById('chatroom-error');

// Initialize WebSocket connection
function initializeWebSocket() {
  socket = new WebSocket('wss://chatinsocket.onrender.com/');

  socket.onopen = () => {
    console.log('WebSocket connection established');
  };

  socket.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log('Received message:', data);

    if (data.type === 'login_successfull') {
      currentUser = data.username;
      authSection.style.display = 'none';
      chatroomSection.style.display = 'block';
      authErrorDiv.textContent = '';
    } else if (data.type === 'login_failed') {
      authErrorDiv.textContent = data.message;
    } else if (data.type === 'registration_successfull') {
      alert('Registration successful. Please login.');
      authErrorDiv.textContent = '';
    } else if (data.type === 'registration_failed') {
      authErrorDiv.textContent = data.error;
    } else if (data.type === 'chatroom_joined') {
      currentChatroom = data.chatroomName;
      chatroomErrorDiv.textContent = '';
      alert(`Joined chatroom: ${data.chatroomName}`);
    } else if (data.type === 'message') {
      const messageElement = document.createElement('div');
      messageElement.textContent = `${data.from}: ${data.message}`;
      messagesDiv.appendChild(messageElement);
    } else if (data.type === 'system_message') {
      const messageElement = document.createElement('div');
      messageElement.textContent = data.message;
      messagesDiv.appendChild(messageElement);
    } else if (data.type === 'error') {
      chatroomErrorDiv.textContent = data.message;
    } else if (data.type === 'rate_limit_exceeded') {
      alert('Rate limit exceeded. Please wait before sending more messages.');
    } else if (data.type === 'heartbeat') {
      // Respond to heartbeat
      socket.send(JSON.stringify({ type: 'heartbeat_ack' }));
    }
  };

  socket.onclose = () => {
    console.log('WebSocket connection closed');
    alert('Connection lost. Please refresh the page.');
  };
}

// Send message
sendBtn.addEventListener('click', () => {
  const message = messageInput.value;
  if (message && socket && currentChatroom) {
    socket.send(
      JSON.stringify({
        type: 'message',
        username: currentUser,
        chatroomName: currentChatroom,
        message,
      })
    );
    messageInput.value = '';
  } else {
    alert('Please join a chatroom and enter a message.');
  }
});

// Create/Join Chatroom
createJoinBtn.addEventListener('click', () => {
  const chatroomName = chatroomNameInput.value;
  if (chatroomName && socket && currentUser) {
    socket.send(
      JSON.stringify({
        type: 'join_chatroom',
        chatroomName,
        username: currentUser,
      })
    );
  } else {
    chatroomErrorDiv.textContent = 'Please log in and enter a chatroom name.';
  }
});

// Login
loginBtn.addEventListener('click', () => {
  const username = usernameInput.value;
  const password = passwordInput.value;
  if (username && password && socket) {
    socket.send(JSON.stringify({ type: 'login', username, password }));
  } else {
    authErrorDiv.textContent = 'Please enter a username and password.';
  }
});

// Register
registerBtn.addEventListener('click', () => {
  const username = usernameInput.value;
  const password = passwordInput.value;
  if (username && password && socket) {
    socket.send(JSON.stringify({ type: 'register', username, password }));
  } else {
    authErrorDiv.textContent = 'Please enter a username and password.';
  }
});

// Initialize WebSocket on page load
initializeWebSocket();
