import { WebSocketServer } from 'ws';
import bcrypt from 'bcrypt';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import User from './model/User.js';

dotenv.config();

const PORT = 5000;

// WebSocket server setup
const wss = new WebSocketServer({ host: '0.0.0.0', port: PORT });

// Stored connected clients
const connectedClients = new Map(); // Map<username, WebSocket>
const activeUsers = new Set(); // Set of active users
const chatHistory = new Map(); // Map<chatroomName, Array<{ from: string, message: string }>>

// Rate limit
const RATE_LIMIT = 5; // Max messages per second
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
  // const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ username, password });
  await newUser.save();
  console.log('New user:', newUser);
}

// Broadcast active users to all clients
function broadcastActiveUsers() {
  const userList = Array.from(activeUsers);
  wss.clients.forEach((client) => {
    if (client.readyState === client.OPEN) {
      client.send(JSON.stringify({ type: 'user_list', users: userList }));
    }
  });
}

// Function to generate a unique chatroom name
function getChatroomName(user1, user2) {
  const users = [user1, user2].sort(); // Sort usernames alphabetically
  return users.join('-'); // Join with a hyphen
}

// Handle WebSocket connections
wss.on('connection', (ws, req) => {
  console.log('New client connected');
  const clientIp = req.socket.remoteAddress;
  console.log(`New client connected from IP: ${clientIp}`);

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
    if (message instanceof Buffer) {
      data = JSON.parse(message.toString('utf8'));
    } else {
      data = JSON.parse(message);
    }
    console.log(`Received message from ${clientIp}:`, data);

    if (data.type === 'login') {
      if (await authenticate(data.username, data.password)) {
        connectedClients.set(data.username, ws);
        activeUsers.add(data.username);
        ws.username = data.username;
        ws.send(
          JSON.stringify({ type: 'login_successfull', username: data.username })
        );
        broadcastActiveUsers(); // Broadcast updated user list
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
    } else if (data.type === 'switch_chat') {
      if (!connectedClients.has(data.username)) {
        ws.send(
          JSON.stringify({ type: 'error', message: 'User not logged in' })
        );
        return;
      }

      const chatroomName = getChatroomName(data.username, data.recipient);
      const history = chatHistory.get(chatroomName) || [];
      ws.send(
        JSON.stringify({
          type: 'chat_history',
          chatroomName,
          messages: history,
        })
      );
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

        // Store the message in chat history
        const chatroomName = getChatroomName(data.username, data.recipient);
        const history = chatHistory.get(chatroomName) || [];
        history.push({ from: data.username, message: data.message });
        chatHistory.set(chatroomName, history);

        // Send the message to the recipient
        const recipientWs = connectedClients.get(data.recipient);
        if (recipientWs) {
          recipientWs.send(
            JSON.stringify({
              type: 'message',
              from: data.username,
              message: data.message,
            })
          );
        }

        // Send the message back to the sender
        ws.send(
          JSON.stringify({
            type: 'message',
            from: data.username,
            message: data.message,
          })
        );
      }
    }
  });

  ws.on('close', () => {
    if (ws.username) {
      connectedClients.delete(ws.username);
      activeUsers.delete(ws.username);
      broadcastActiveUsers(); // Broadcast updated user list
    }

    // Clear heartbeat interval
    clearInterval(heartbeatInterval);
    console.log('Client disconnected');
  });
});
