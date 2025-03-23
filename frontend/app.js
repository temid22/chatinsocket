// import { Picker } from 'https://cdn.skypack.dev/emoji-mart';
// import data from 'https://cdn.skypack.dev/@emoji-mart/data';
// import { marked } from 'https://cdn.skypack.dev/marked';
// import DOMPurify from 'https://cdn.skypack.dev/dompurify';

let socket;
let currentUser;
let currentRecipient;
const chatHistory = new Map();

// DOM Elements
const authSection = document.getElementById('auth-section');
const chatroomSection = document.getElementById('chat-section');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const loginBtn = document.getElementById('login-btn');
const registerBtn = document.getElementById('register-btn');
const messageBox = document.getElementById('message-box');
const sendBtn = document.getElementById('send-btn');
const messagesDiv = document.getElementById('messages');
const authErrorDiv = document.getElementById('auth-error');
const userListDiv = document.getElementById('user-list');
const fileInput = document.getElementById('file-input');
// DOM Elements for emoji picker and formatting buttons
const emojiPicker = document.getElementById('emoji-picker');
const emojiBtn = document.getElementById('emoji-btn');
const boldBtn = document.getElementById('bold-btn');
const italicBtn = document.getElementById('italic-btn');
const linkBtn = document.getElementById('link-btn');

const pickerOptions = {
  onEmojiSelect: (emoji) => {
    messageBox.value += emoji.native; // Insert the selected emoji into the message box
    emojiPicker.style.display = 'none'; // Hide the picker after selection
  },
  dynamicWidth: true, // Allow the picker to adjust its width
};
const picker = new EmojiMart.Picker(pickerOptions);

// Append the picker to the emoji-picker container
emojiPicker.appendChild(picker);

// Toggle emoji picker visibility
emojiBtn.addEventListener('click', () => {
  emojiPicker.style.display =
    emojiPicker.style.display === 'none' ? 'block' : 'none';
});

// Bold formatting
boldBtn.addEventListener('click', () => {
  const selectedText = messageBox.value.substring(
    messageBox.selectionStart,
    messageBox.selectionEnd
  );
  if (selectedText) {
    const newText = `**${selectedText}**`;
    messageBox.setRangeText(
      newText,
      messageBox.selectionStart,
      messageBox.selectionEnd,
      'end'
    );
  }
});

// Italic formatting
italicBtn.addEventListener('click', () => {
  const selectedText = messageBox.value.substring(
    messageBox.selectionStart,
    messageBox.selectionEnd
  );
  if (selectedText) {
    const newText = `*${selectedText}*`;
    messageBox.setRangeText(
      newText,
      messageBox.selectionStart,
      messageBox.selectionEnd,
      'end'
    );
  }
});

// Function to parse and sanitize formatted text
function formatMessage(text) {
  // Convert markdown to HTML
  const html = marked.parse(text);
  // Sanitize the HTML to prevent XSS attacks
  return DOMPurify.sanitize(html);
}
// Secret key for encryption (must match the backend)
const secretKey = new Uint8Array(32); // Replace with the actual shared key

// Function to generate a unique chatroom name
function getChatroomName(user1, user2) {
  const users = [user1, user2].sort(); // Sort usernames alphabetically
  return users.join('-'); // Join with a hyphen
}

// Encrypt Message with AES
async function encryptMessage(message, key) {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const encodedMessage = new TextEncoder().encode(message);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv },
    key,
    encodedMessage
  );
  return { iv, encryptedData: new Uint8Array(encrypted) };
}

// Decrypt Message with AES
async function decryptMessage(encryptedData, iv, key) {
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv },
    key,
    encryptedData
  );
  return new TextDecoder().decode(decrypted);
}

// Encrypt AES Key with RSA
async function encryptAESKey(key, publicKey) {
  const exportedKey = await crypto.subtle.exportKey('raw', key);
  const encryptedKey = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    publicKey,
    exportedKey
  );
  return new Uint8Array(encryptedKey);
}

// Decrypt AES Key with RSA
async function decryptAESKey(encryptedKey, privateKey) {
  const decryptedKey = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    privateKey,
    encryptedKey
  );
  return await crypto.subtle.importKey(
    'raw',
    decryptedKey,
    { name: 'AES-CBC', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}
// Encrypt file
async function encryptFile(file, secretKey) {
  const iv = crypto.getRandomValues(new Uint8Array(16)); // Initialization vector
  const algorithm = { name: 'AES-CBC', iv };
  const key = await crypto.subtle.importKey(
    'raw',
    secretKey,
    algorithm,
    false,
    ['encrypt']
  );
  const encrypted = await crypto.subtle.encrypt(algorithm, key, file);
  return { iv, encryptedData: new Uint8Array(encrypted) };
}

// Decrypt file
async function decryptFile(encryptedData, iv, secretKey) {
  const algorithm = { name: 'AES-CBC', iv };
  const key = await crypto.subtle.importKey(
    'raw',
    secretKey,
    algorithm,
    false,
    ['decrypt']
  );
  const decrypted = await crypto.subtle.decrypt(algorithm, key, encryptedData);
  return new Uint8Array(decrypted);
}

// Display a file (e.g., image) in the chat window
function displayFile(fileData, from, mimeType = 'application/octet-stream') {
  const fileBlob = new Blob([fileData], { type: mimeType });
  const fileUrl = URL.createObjectURL(fileBlob);

  const fileElement = document.createElement('div');
  fileElement.className = 'message';

  console.log('blob', fileBlob.type);

  if (fileBlob.type.startsWith('image/')) {
    // Display image
    const img = document.createElement('img');
    img.src = fileUrl;
    img.style.maxWidth = '200px';
    img.style.maxHeight = '200px';
    img.onload = () => URL.revokeObjectURL(fileUrl); // Clean up the object URL after the image loads
    fileElement.appendChild(img);
  } else {
    // Display a download link for non-image files
    const link = document.createElement('a');
    link.href = fileUrl;
    link.download = `file_${Date.now()}`;
    link.textContent = 'Download File';
    link.onclick = () => URL.revokeObjectURL(fileUrl); // Clean up the object URL after the link is clicked
    fileElement.appendChild(link);
  }

  const senderElement = document.createElement('div');
  senderElement.textContent = `${from}:`;
  fileElement.prepend(senderElement);

  messagesDiv.appendChild(fileElement);
  messagesDiv.scrollTop = messagesDiv.scrollHeight; // Auto-scroll to the bottom
}

//Display messages and files in the chat window
function displayMessages(messages) {
  messagesDiv.innerHTML = ''; // Clear the chat window
  messages.forEach((msg) => {
    if (msg.file) {
      // Display file
      displayFile(msg.file, msg.from, msg.mimeType);
    } else {
      // Display text message with formatting
      const messageElement = document.createElement('div');
      messageElement.className = 'message';
      messageElement.innerHTML = `<strong>${msg.from}:</strong> 
      ${formatMessage(msg.message)}`;
      messagesDiv.appendChild(messageElement);
    }
  });
  messagesDiv.scrollTop = messagesDiv.scrollHeight; // Auto-scroll to the bottom
}

// Initialize WebSocket connection
function initializeWebSocket() {
  socket = new WebSocket('wss://localhost:5000'); // Replace with your backend URL

  socket.onopen = () => {
    console.log('WebSocket connection established');
  };

  socket.onmessage = async (event) => {
    const data = JSON.parse(event.data);
    console.log('Received message:', data);

    if (data.type === 'login_successfull') {
      currentUser = data.username;
      authSection.style.display = 'none';
      chatroomSection.classList.add('visible'); // Add the 'visible' class
      authErrorDiv.textContent = '';
    } else if (data.type === 'login_failed') {
      authErrorDiv.textContent = data.message;
    } else if (data.type === 'registration_successfull') {
      alert('Registration successful. Please login.');
      authErrorDiv.textContent = '';
    } else if (data.type === 'registration_failed') {
      authErrorDiv.textContent = data.error;
    } else if (data.type === 'chat_history') {
      // Load chat history for the selected recipient
      // Decrypt each file message in the chat history
      const decryptedMessages = await Promise.all(
        data.messages.map(async (msg) => {
          if (msg.file) {
            try {
              const decryptedFile = await decryptFile(
                new Uint8Array(msg.file),
                new Uint8Array(msg.iv),
                secretKey
              );
              return {
                ...msg,
                file: decryptedFile,
                mimeType: msg.mimeType,
              };
            } catch (error) {
              console.error('Decryption error:', error);
              return msg; // Return original message if decryption fails
            }
          } else {
            return msg;
          }
        })
      );
      chatHistory.set(data.chatroomName, decryptedMessages);
      displayMessages(decryptedMessages);
      // chatHistory.set(data.chatroomName, data.messages);
      // displayMessages(data.messages);
    } else if (data.type === 'message') {
      // Add the message to the chat history
      const chatroomName = getChatroomName(currentUser, data.from);
      const history = chatHistory.get(chatroomName) || [];
      history.push({
        from: data.from,
        message: data.message,
        file: null,
        mimeType: null,
      });
      chatHistory.set(chatroomName, history);

      // Display the message if the recipient is currently selected
      if (currentRecipient === data.from) {
        displayMessages(history);
      }
    } else if (data.type === 'file') {
      // Decrypt the file
      const decryptedFile = await decryptFile(
        new Uint8Array(data.file),
        new Uint8Array(data.iv),
        secretKey
      );

      // Add the file to the chat history
      const chatroomName = getChatroomName(currentUser, data.from);
      const history = chatHistory.get(chatroomName) || [];
      history.push({
        from: data.from,
        message: null,
        file: decryptedFile,
        mimeType: data.mimeType,
      });
      chatHistory.set(chatroomName, history);

      // Display the file if the recipient is currently selected
      if (currentRecipient === data.from) {
        // displayMessages(history);
        displayFile(decryptedFile, data.from, data.mimeType);
      }
    } else if (data.type === 'user_list') {
      updateUserList(data.users); // Update the user list
    } else if (data.type === 'error') {
      chatroomErrorDiv.textContent = data.message;
      alert(data.message);
    } else if (data.type === 'rate_limit_exceeded') {
      alert('Rate limit exceeded. Please wait before sending more messages.');
    } else if (data.type === 'heartbeat') {
      // Respond to heartbeat
      socket.send(JSON.stringify({ type: 'heartbeat_ack' }));
    }
  };

  socket.onerror = (error) => {
    console.error('WebSocket error:', error);
  };
  socket.onclose = () => {
    console.log('WebSocket connection closed');
    alert('Connection lost. Please refresh the page.');
  };
}

// Update the user list in the sidebar
function updateUserList(users) {
  userListDiv.innerHTML = ''; // Clear the current list
  users.forEach((user) => {
    if (user !== currentUser) {
      // Don't show the current user in the list
      const userElement = document.createElement('div');
      userElement.textContent = user;
      userElement.style.cursor = 'pointer';
      userElement.style.padding = '5px';
      userElement.addEventListener('click', () => switchUser(user));
      userListDiv.appendChild(userElement);
    }
  });
}

// Switch to a different user's chat
function switchUser(user) {
  currentRecipient = user; // Set the recipient
  messagesDiv.innerHTML = ''; // Clear the chat window

  // Request chat history from the backend
  socket.send(
    JSON.stringify({
      type: 'switch_chat',
      username: currentUser,
      recipient: user,
    })
  );
}

// Send message
sendBtn.addEventListener('click', () => {
  const message = messageBox.value; // Ensure 'messageBox' is correctly defined
  if (message && socket && currentRecipient) {
    // Add the message to the chat history for the sender
    const chatroomName = getChatroomName(currentUser, currentRecipient);
    const history = chatHistory.get(chatroomName) || [];
    history.push({ from: currentUser, message, file: null, mimeType: null });
    chatHistory.set(chatroomName, history);

    // Display the updated messages
    displayMessages(history);

    // Send the message to the backend
    socket.send(
      JSON.stringify({
        type: 'message',
        username: currentUser,
        recipient: currentRecipient,
        message,
      })
    );

    // Clear the message input
    messageBox.value = '';
  } else {
    alert('Please select a user and enter a message.');
  }
});

// Send file
fileInput.addEventListener('change', async (event) => {
  const file = event.target.files[0];
  if (file && socket && currentRecipient) {
    const fileBuffer = await file.arrayBuffer();
    const { iv, encryptedData } = await encryptFile(fileBuffer, secretKey);

    // Immediately display the original file to sender
    displayFile(new Uint8Array(fileBuffer), currentUser, file.type);

    // Store original file in local history for immediate display
    const chatroomName = getChatroomName(currentUser, currentRecipient);
    const history = chatHistory.get(chatroomName) || [];
    history.push({
      from: currentUser,
      message: null,
      file: new Uint8Array(fileBuffer), // Store original bytes
      mimeType: file.type,
    });
    chatHistory.set(chatroomName, history);

    // Display the updated messages
    // displayMessages(history);

    // Send the encrypted file to the backend
    socket.send(
      JSON.stringify({
        type: 'file',
        username: currentUser,
        recipient: currentRecipient,
        iv: Array.from(iv),
        file: Array.from(encryptedData),
        mimeType: file.type, // Include the MIME type
      })
    );
  } else {
    alert('Please select a user and a file.');
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
