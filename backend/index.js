import { WebSocketServer } from 'ws';
import bcrypt from 'bcrypt';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import User from './model/User.js';

dotenv.config();

const PORT = 5000;

// WebSocket server setup
const wss = new WebSocketServer({ port: PORT });

// Stored connected clients and chatrooms
const connectedClients = new Map(); // Map<username, WebSocket>
const chatrooms = new Map(); // Map<chatroomName, Set<username>>

// Rate limit
const RATE_LIMIT = 5; // Max messages per seco`nd
const userMessageCounts = new Map();

// Heartbeat interval (in milliseconds)
const HEARTBEAT_INTERVAL = 30000; // 30 seconds

// Connect to MongoDB
mongoose
  .connect(process.env.dbURI)
  .then(() => console.log('DB Connected! and server running'))
  .catch((e) => console.log(e));

// Authenticate/Login user
async function authenticate(username, password) {
  const user = await User.findOne({ username });
  if (user && (await bcrypt.compare(password, user.password))) {
    return true;
  }
  return false;
}

// Register user
async function registerUser(username, password) {
  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ username, password: hashedPassword });
  await newUser.save();
  console.log('New user:', newUser);
}

// Create/Join chatroom
function handleChatroom(ws, chatroomName, username) {
  if (!chatrooms.has(chatroomName)) {
    chatrooms.set(chatroomName, new Set());
  }
  chatrooms.get(chatroomName).add(username);
  ws.send(JSON.stringify({ type: 'chatroom_joined', chatroomName }));
  broadcastMessage(chatroomName, {
    type: 'system_message',
    message: `${username} joined the chatroom.`,
  });
  console.log(`${username} joined chatroom: ${chatroomName}`);
}

// Broadcast message to all users in the chatroom
function broadcastMessage(chatroomName, message) {
  const usersInChatroom = chatrooms.get(chatroomName);
  if (usersInChatroom) {
    usersInChatroom.forEach((username) => {
      const clientWs = connectedClients.get(username);
      if (clientWs) {
        clientWs.send(JSON.stringify(message));
      }
    });
  }
}

// Handle WebSocket connections
wss.on('connection', (ws) => {
  console.log('New client connected');

  // Set up heartbeat
  let heartbeatInterval;
  const setupHeartbeat = () => {
    heartbeatInterval = setInterval(() => {
      if (ws.readyState === ws.OPEN) {
        ws.send(JSON.stringify({ type: 'heartbeat' }));
      }
    }, HEARTBEAT_INTERVAL);
  };

  // Start heartbeat
  setupHeartbeat();

  ws.on('message', async (message) => {
    let data;
    // Convert Buffer to string if necessary
    if (message instanceof Buffer) {
      data = JSON.parse(message.toString('utf8'));
    } else {
      data = JSON.parse(message);
    }
    console.log('Received data:', data);

    if (data.type === 'login') {
      if (await authenticate(data.username, data.password)) {
        connectedClients.set(data.username, ws);
        ws.send(
          JSON.stringify({ type: 'login_successfull', username: data.username })
        );
      } else {
        ws.send(
          JSON.stringify({
            type: 'login_failed',
            message: 'Incorrect password/user does not exist',
          })
        );
      }
    } else if (data.type === 'register') {
      try {
        await registerUser(data.username, data.password);
        ws.send(JSON.stringify({ type: 'registration_successfull' }));
      } catch (error) {
        ws.send(
          JSON.stringify({
            type: 'registration_failed',
            error: 'Username already exists',
          })
        );
      }
    } else if (data.type === 'join_chatroom') {
      if (!connectedClients.has(data.username)) {
        ws.send(
          JSON.stringify({ type: 'error', message: 'User not logged in' })
        );
        return;
      }
      handleChatroom(ws, data.chatroomName, data.username);
    } else if (data.type === 'message') {
      if (!connectedClients.has(data.username)) {
        ws.send(
          JSON.stringify({ type: 'error', message: 'User not logged in' })
        );
        return;
      }

      // Rate limiting
      const count = userMessageCounts.get(data.username) || 0;
      if (count >= RATE_LIMIT) {
        ws.send(
          JSON.stringify({
            type: 'rate_limit_exceeded',
            message: 'Wait for 1 min',
          })
        );
      } else {
        userMessageCounts.set(data.username, count + 1);
        broadcastMessage(data.chatroomName, {
          type: 'message',
          from: data.username,
          chatroomName: data.chatroomName,
          message: data.message,
        });
      }
    }
  });

  ws.on('close', () => {
    // Handle disconnection
    connectedClients.forEach((value, key) => {
      if (value === ws) {
        connectedClients.delete(key);
        console.log(`${key} disconnected!`);

        // Notify chatroom members
        chatrooms.forEach((users, chatroomName) => {
          if (users.has(key)) {
            users.delete(key);
            broadcastMessage(chatroomName, {
              type: 'system_message',
              message: `${key} left the chatroom.`,
            });
          }
        });
      }
    });

    // Clear heartbeat interval
    clearInterval(heartbeatInterval);
  });
});
