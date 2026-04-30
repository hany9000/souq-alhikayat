require('dotenv').config();
require('node:dns/promises').setServers(['1.1.1.1', '8.8.8.8']);
const mongoose = require('mongoose');
const User = require('./models/User');
const WebSocket = require('ws');
const http = require('http');
const fs = require('fs');
const path = require('path');

// ✅ دعم المنفذ الديناميكي للسحابة
const PORT = process.env.PORT || 3000;

const logStream = fs.createWriteStream(path.join(__dirname, 'server.log'), { flags: 'a' });

function log(...args) {
    const msg = args.map(a => typeof a === 'object' ? JSON.stringify(a) : String(a)).join(' ');
    logStream.write(`[${new Date().toISOString()}] ${msg}\n`);
    console.log(...args);
}
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());

const requiredEnvVars = ['MONGODB_URI', 'JWT_SECRET'];
const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
    console.error(`❌ متغيرات البيئة المفقودة: ${missingVars.join(', ')}`);
    process.exit(1);
}
console.log('✅ جميع متغيرات البيئة موجودة وآمنة');

const TURN_SERVER_URL = process.env.TURN_SERVER_URL || "";
const TURN_USERNAME = process.env.TURN_USERNAME || "";
const TURN_CREDENTIAL = process.env.TURN_CREDENTIAL || "";

if (TURN_SERVER_URL) {
    console.log('📡 TURN Server configured: ' + TURN_SERVER_URL);
} else {
    console.log('⚠️ No TURN server configured (TURN_SERVER_URL not set)');
}

app.use(helmet());
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));
console.log('✅ CORS enabled with permissive settings');

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 50,
    message: { success: false, message: "محاولات كثيرة جداً، يرجى الانتظار قليلاً." },
    standardHeaders: true,
    legacyHeaders: false,
});

const rateLimitStore = new Map();

function checkRateLimit(key) {
    const now = Date.now();
    const windowMs = 15 * 60 * 1000;
    const max = 50;
    
    if (!rateLimitStore.has(key)) {
        rateLimitStore.set(key, { count: 1, resetTime: now + windowMs });
        return true;
    }
    
    const record = rateLimitStore.get(key);
    if (now > record.resetTime) {
        rateLimitStore.set(key, { count: 1, resetTime: now + windowMs });
        return true;
    }
    
    if (record.count >= max) {
        return false;
    }
    
    record.count += 1;
    return true;
}

function validateInput(email, password) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
        return 'بريد إلكتروني غير صالح';
    }
    if (!password || password.length < 6) {
        return 'كلمة المرور يجب أن تكون 6 أحرف على الأقل';
    }
    return null;
}

const SALT_ROUNDS = 10;
const JWT_SECRET = process.env.JWT_SECRET || "word-market-secret-key-2024";
const JWT_EXPIRY = "24h";

mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/souq_al_hikayat')
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB connection error:', err));

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, message: "مطلوب توكن للمصادقة" }));
        return;
    }
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, message: "التوكن غير صالح أو منتهي" }));
            return;
        }
        req.user = decoded;
        next();
    });
}

const wss = new WebSocket.Server({ port: 3000 });

// HTTP Server للمصادقة
const httpServer = http.createServer((req, res) => {
  // CORS Headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }
  
  // Parse URL
  const url = new URL(req.url, `http://localhost:3000`);
  
  // API Routes
  if (url.pathname === '/api/register' && req.method === 'POST') {
    const clientIp = req.socket.remoteAddress || 'unknown';
    if (!checkRateLimit('register:' + clientIp)) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, message: 'محاولات كثيرة جداً، يرجى الانتظار قليلاً.' }));
        return;
    }
    
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const data = JSON.parse(body);
        const { email, password } = data;
        
        const validationError = validateInput(email, password);
        if (validationError) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, message: validationError }));
          return;
        }
        
        const existingUser = await User.findOne({ email });
        if (existingUser) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, message: 'البريد مسجل مسبقاً' }));
          return;
        }
        
        const newUser = new User({ email, password });
        await newUser.save();
        
        console.log(`📝 New user registered: ${email}`);
        
        const token = jwt.sign(
            { userId: newUser._id.toString(), email: newUser.email },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRY }
        );
        
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          userId: newUser._id.toString(),
          email: newUser.email,
          token: token,
          trialStart: newUser.trialStart,
          isPremium: false
        }));
      } catch (e) {
        console.error("❌ Register error:", e);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, message: 'خطأ في الخادم' }));
      }
    });
  }
  else if (url.pathname === '/api/login' && req.method === 'POST') {
    const clientIp = req.socket.remoteAddress || 'unknown';
    if (!checkRateLimit('login:' + clientIp)) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, message: 'محاولات كثيرة جداً، يرجى الانتظار قليلاً.' }));
        return;
    }
    
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const data = JSON.parse(body);
        const { email, password } = data;
        
        const validationError = validateInput(email, password);
        if (validationError) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, message: validationError }));
          return;
        }
        
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
          console.log(`❌ Login failed: user not found for email: ${email}`);
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, message: 'بيانات الدخول غير صحيحة' }));
          return;
        }
        
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
          console.log(`❌ Login failed: wrong password for: ${email}`);
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, message: 'بيانات الدخول غير صحيحة' }));
          return;
        }
        
        const TRIAL_DURATION_MS = 24 * 60 * 60 * 1000;
        const elapsed = Date.now() - new Date(user.trialStart).getTime();
        // Give test account premium/open access
        var isPremium = user.isPremium;
        if (email === 'testnew@gmail.com') {
            isPremium = true;
            console.log('⭐ Test account granted premium access');
        }
        const isTrialExpired = !isPremium && elapsed > TRIAL_DURATION_MS;
        
        const token = jwt.sign(
            { userId: user._id.toString(), email: user.email },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRY }
        );
        
        console.log(`🔐 Login: ${email}, trial expired: ${isTrialExpired}, premium: ${isPremium}`);
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          userId: user._id.toString(),
          email: user.email,
          isPremium: isPremium,
          isTrialExpired: false, // Always false for test account
          trialStart: user.trialStart,
          token: token
        }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, message: 'خطأ في الخادم' }));
      }
    });
  }
  else if (url.pathname === '/api/upgrade' && req.method === 'POST') {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, message: "مطلوب توكن للمصادقة" }));
      return;
    }
    
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const data = JSON.parse(body);
        const { userId } = data;
        
        if (decoded.userId !== userId) {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, message: "غير مصرح لك بترقية هذا الحساب" }));
          return;
        }
        
        const user = await User.findById(userId);
        if (!user) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, message: 'المستخدم غير موجود' }));
          return;
        }
        
        user.isPremium = true;
        await user.save();
        
        console.log(`⭐ User upgraded to premium: ${user.email}`);
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, isPremium: true }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, message: 'خطأ في الخادم' }));
      }
    });
  }
  else {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ message: 'Not Found' }));
  }
});

// Start HTTP server on port 3001
httpServer.listen(3001, () => {
  console.log('🌐 HTTP Server running on http://localhost:3001');
  console.log('📝 Auth Routes: POST /api/register, POST /api/login, POST /api/upgrade');
});

// ✅ نقطة صحة الخادم (لـ Render Uptime Monitor)
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

console.log('🏥 Health check endpoint: GET /health');

// 🎁 API مسارات المكافآت والتقدم

// 1️⃣ جلب تقدم اللاعب
app.get('/api/progress/:player_id', async (req, res) => {
  try {
    const user = await User.findById(req.params.player_id).select('progress rewards trialStart isPremium');
    if (!user) return res.status(404).json({ error: "Player not found" });
    res.json({
      progress: user.progress || {},
      rewards: user.rewards || [],
      trialStart: user.trialStart,
      isPremium: user.isPremium
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2️⃣ تحديث تقدم اللاعب
app.patch('/api/progress/:player_id', async (req, res) => {
  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', async () => {
    try {
      const { points, achievement, room_activity } = JSON.parse(body);
      const user = await User.findById(req.params.player_id);
      if (!user) return res.status(404).json({ error: "Player not found" });

      if (points) {
        user.progress = user.progress || {};
        user.progress.total_points = (user.progress.total_points || 0) + points;
        user.progress.last_updated = new Date();
      }

      if (achievement && !user.rewards?.includes(achievement)) {
        user.rewards = user.rewards || [];
        user.rewards.push(achievement);
      }

      if (room_activity) {
        user.progress.room_sessions = user.progress.room_sessions || [];
        user.progress.room_sessions.push({
          room_id: room_activity.room_id,
          duration: room_activity.duration,
          timestamp: new Date()
        });
      }

      await user.save();
      res.json({ success: true, progress: user.progress, rewards: user.rewards });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
});

// 3️⃣ استبدال مكافأة
app.post('/api/rewards/redeem', async (req, res) => {
  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', async () => {
    try {
      const { player_id, reward_code, points_cost } = JSON.parse(body);
      const user = await User.findById(player_id);
      if (!user) return res.status(404).json({ error: "Player not found" });

      const currentPoints = user.progress?.total_points || 0;
      if (currentPoints < points_cost) {
        return res.status(400).json({ error: "نقاط غير كافية" });
      }

      user.progress.total_points -= points_cost;
      user.rewards = user.rewards || [];
      user.rewards.push({ code: reward_code, redeemed_at: new Date() });

      await user.save();
      res.json({ success: true, remaining_points: user.progress.total_points });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
});

console.log('🎁 Progress & Rewards API endpoints added');

// API endpoint لتكوين TURN
app.get('/api/config', (req, res) => {
  console.log('📡 GET /api/config reached');
  const config = {
    signaling_url: "ws://localhost:3002",
    turn_server: TURN_SERVER_URL || null,
    turn_username: TURN_USERNAME || null,
    turn_credential: TURN_CREDENTIAL ? "***" : null
  };
  res.json(config);
});

console.log('📡 TURN config endpoint: GET /api/config');

// API endpoint لإعادة تعيين كلمة المرور (للاختبار)
app.post('/api/reset-password', async (req, res) => {
  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', async () => {
    try {
      const { email, newPassword } = JSON.parse(body);
      console.log(`🔑 Password reset requested for: ${email}`);
      
      const user = await User.findOne({ email: email.toLowerCase() });
      if (!user) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, message: 'User not found' }));
        return;
      }
      
      user.password = newPassword;
      await user.save();
      console.log(`✅ Password reset successful for: ${email}`);
      
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, message: 'Password reset successful' }));
    } catch (e) {
      console.error('❌ Password reset error:', e);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, message: 'Error resetting password' }));
    }
  });
});

console.log('🔑 Password reset endpoint: POST /api/reset-password');

// إدارة اللاعبين - نستخدم player_id كمفتاح رئيسي
let players = {};
let nextId = 1;

// إدارة الغرف العامة (مثل السوق الرئيسي)
let publicRooms = {
  "main": { name: "الشات العام", players: [] }
};

// الغرف الخاصة (Private Rooms)
let privateRooms = {};

// نظام الأصدقاء
let friendships = {};      // { playerId: [friendId1, friendId2, ...] }
let friendRequests = [];  // [{ from: playerId, to: playerId, name: "playerName" }]

// الرسائل الخاصة (Private Messages) - تخزين مؤقت
let privateMessages = {};  // { playerId: [{ from: "name", message: "text", time: timestamp }] }

const REQUIRED_REPUTATION = 1000;
const MAX_ROOM_PLAYERS = 30;

wss.on('connection', (ws) => {
  const playerId = nextId++;
  ws.playerId = playerId;
  console.log(`🔗 لاعب جديد متصل: ID=${playerId}`);

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message.toString());
      handleMessage(ws, playerId, data);
    } catch (e) {
      console.error('خطأ في قراءة الرسالة:', e.message);
      sendTo(ws, { type: 'error', data: { message: 'خطأ في قراءة البيانات' } });
    }
  });

  ws.on('close', () => {
    handleDisconnect(playerId);
  });

  ws.on('error', (err) => {
    console.error(`خطأ من اللاعب ${playerId}:`, err.message);
  });
});

function handleMessage(ws, playerId, data) {
  const type = data.type;
  const playerIdKey = ws.playerId || playerId;
  const player = players[playerIdKey];

  // تسجيل اسم اللاعب والسمعة من العميل
  let playerName = player ? player.name : '';
  let playerReputation = player ? player.reputation || 0 : 0;

  if (type === 'join') {
    const room = data.data.room || 'main';
    const roomName = data.data.room_name || room;
    const createRoom = data.data.create_room || false;
    
    // ✅ الحصول على player_id من العميل أو إنشاء واحد
    const clientPlayerId = data.data.player_id || String(playerId);
    ws.playerId = clientPlayerId;
    
    // ✅ التحقق من التكرار - إذا كان اللاعب موجوداً، نستخدم الاتصال الجديد
    const existingPlayer = Object.values(players).find(p => p.id === clientPlayerId);
    
    if (existingPlayer && existingPlayer.ws) {
      console.log(`🔄 player_id موجود ${clientPlayerId} - تحديث الاتصال`);
      // تحديث بيانات الاتصال القديمة
      const oldRoom = existingPlayer.room;
      if (oldRoom && publicRooms[oldRoom]) {
        publicRooms[oldRoom].players = publicRooms[oldRoom].players.filter(id => id !== existingPlayer.id);
        broadcastToRoom(oldRoom, { type: 'player_left', data: { name: existingPlayer.name } }, existingPlayer.id);
      }
    }

    if (createRoom && !publicRooms[room]) {
      publicRooms[room] = { name: roomName, players: [] };
    }

    players[clientPlayerId] = {
      id: clientPlayerId,
      name: data.data.name || 'مجهول',
      reputation: data.data.reputation || 0,
      room: room,
      roomName: roomName,
      joinedAt: Date.now(),
      ws: ws,
      privateRoomId: null
    };

    if (!publicRooms[room]) {
      publicRooms[room] = { name: roomName, players: [] };
    }
    publicRooms[room].players.push(clientPlayerId);

    console.log(`👤 ${players[clientPlayerId].name} دخل غرفة ${publicRooms[room].name} (player_id: ${clientPlayerId})`);

    const roomPlayers = getRoomPlayers(room);
    sendTo(ws, { type: 'player_list', data: roomPlayers, room: room, player_id: clientPlayerId });
    sendTo(ws, { type: 'room_info', data: { room: room, room_name: publicRooms[room].name } });

    // ✅ إرسال player_list المحدث لجميع اللاعبين الآخرين (عدا اللاعب الجديد)
    broadcastToRoom(room, { type: 'player_list', data: roomPlayers, room: room }, clientPlayerId);
    console.log(`📋 📤 Broadcasting updated player_list to all players (except new player)`);

    broadcastToRoom(room, { type: 'player_joined', data: { id: clientPlayerId, name: players[clientPlayerId].name } }, clientPlayerId);
    
    // إرسال قائمة الأصدقاء المتصلين
    sendFriendsOnlineStatus(clientPlayerId);
  }

  else if (type === 'chat_message') {
    console.log('💬 رسالة شات من اللاعب:', player?.name, 'privateRoomId:', player?.privateRoomId);
    
    if (player) {
      // ✅ تحديد الغرفة الصحيحة (خاصة أو عامة)
      let targetRoom = null;
      
      if (player.privateRoomId && privateRooms[player.privateRoomId]) {
        // اللاعب في غرفة خاصة
        targetRoom = player.privateRoomId;
      } else {
        // اللاعب في الشات العام
        targetRoom = player.room;
      }
      
      const msg = {
        type: 'chat_message',
        data: {
          player: player.name,
          message: data.data.message,
          room: targetRoom,  // ✅ إرسال معرف الغرفة الصحيح
          timestamp: Date.now()
        }
      };

      // إرسال الرسالة حسب نوع الغرفة
      if (player.privateRoomId && privateRooms[player.privateRoomId]) {
        console.log('📤 إرسال للغرفة الخاصة:', player.privateRoomId);
        broadcastToPrivateRoom(player.privateRoomId, msg, playerIdKey);
        console.log(`💬 [غرفة خاصة] ${player.name}: ${data.data.message}`);
      } else {
        // الشات العام
        console.log('📤 إرسال للشات العام');
        broadcastToRoomAll(player.room, msg);
        console.log(`💬 [${publicRooms[player.room]?.name || player.room}] ${player.name}: ${data.data.message}`);
      }
    }
  }

  else if (type === 'change_room') {
    if (player && publicRooms[data.data.room]) {
      const oldRoom = player.room;
      publicRooms[oldRoom].players = publicRooms[oldRoom].players.filter(id => id !== playerIdKey);
      broadcastToRoom(oldRoom, { type: 'player_left', data: { name: player.name } }, playerIdKey);
      
      // ✅ إرسال player_list المحدث للغرفة القديمة
      const oldRoomPlayers = getRoomPlayers(oldRoom);
      broadcastToRoom(oldRoom, { type: 'player_list', data: oldRoomPlayers, room: oldRoom }, playerIdKey);

      player.room = data.data.room;
      publicRooms[data.data.room].players.push(playerIdKey);

      const roomPlayers = getRoomPlayers(data.data.room);
      sendTo(ws, { type: 'player_list', data: roomPlayers, room: data.data.room });
      broadcastToRoom(data.data.room, { type: 'player_joined', data: { id: playerIdKey, name: player.name } }, playerIdKey);
      
      // ✅ إرسال player_list المحدث للغرفة الجديدة
      broadcastToRoom(data.data.room, { type: 'player_list', data: roomPlayers, room: data.data.room }, playerIdKey);
    }
  }

  // ===== الغرف الخاصة =====

  else if (type === 'get_rooms') {
    // إرسال قائمة الغرف الخاصة المتاحة
    const roomList = getAvailablePrivateRooms();
    sendTo(ws, { type: 'room_list', data: roomList });
    console.log(`📋 إرسال ${roomList.length} غرفة خاصة`);
  }

  else if (type === 'create_private_room') {
    const roomName = data.data.name || 'غرفة جديدة';
    const description = data.data.description || '';
    const maxPlayers = data.data.max_players || MAX_ROOM_PLAYERS;
    const reputation = data.data.reputation || 0;

    if (reputation < REQUIRED_REPUTATION) {
      sendTo(ws, { 
        type: 'error', 
        data: { message: `لا يمكن إنشاء غرفة - سمعة غير كافية (مطلوب: ${REQUIRED_REPUTATION})` } 
      });
      console.log(`❌ ${player?.name || playerId} حاول إنشاء غرفة بسمعة ${reputation}`);
      return;
    }

    const roomId = 'room_' + Date.now() + '_' + playerId;
    privateRooms[roomId] = {
      id: roomId,
      name: roomName,
      description: description,
      ownerId: playerId,
      ownerName: player?.name || 'مجهول',
      maxPlayers: maxPlayers,
      players: [playerId],
      createdAt: Date.now()
    };

    if (player) {
      player.privateRoomId = roomId;
    }

    sendTo(ws, { type: 'private_room_created', data: privateRooms[roomId] });
    console.log(`🏠 غرفة خاصة جديدة: "${roomName}" by ${player?.name}`);
  }

  else if (type === 'join_private_room') {
    const roomIdOrName = data.data.room_id;
    console.log(`🚪 [DEBUG] join_private_room request from ${player?.name} (${playerId}) for: ${roomIdOrName}`);
    
    // البحث عن الغرفة بالاسم أو بالمعرف
    let targetRoom = null;
    let targetRoomId = null;
    
    for (const [rid, room] of Object.entries(privateRooms)) {
      if (rid === roomIdOrName || room.name === roomIdOrName) {
        targetRoom = room;
        targetRoomId = rid;
        break;
      }
    }
    
    if (!targetRoom) {
      sendTo(ws, { type: 'error', data: { message: 'الغرفة غير موجودة: ' + roomIdOrName } });
      console.log(`❌ محاولة دخول غرفة غير موجودة: ${roomIdOrName}`);
      return;
    }

    if (targetRoom.players.length >= targetRoom.maxPlayers) {
      sendTo(ws, { type: 'error', data: { message: 'الغرفة ممتلئة' } });
      return;
    }
    
    // إضافة اللاعب للغرفة
    targetRoom.players.push(playerId);
    
    if (player) {
      player.privateRoomId = targetRoomId;
      console.log(`✅ [DEBUG] Set player.privateRoomId = ${targetRoomId} for ${player.name}`);
    }

    // إرسال معلومات الغرفة للاعب
    sendTo(ws, { type: 'private_room_joined', data: targetRoom });

    // ✅ إرسال player_list للاعب الجديد مباشرة مع room الصحيح
    const roomPlayersList = getPrivateRoomPlayers(targetRoomId);
    console.log(`📋 [DEBUG] Sending player_list to new player ${player?.name}: ${JSON.stringify(roomPlayersList)}`);
    sendTo(ws, { 
        type: 'player_list', 
        data: roomPlayersList, 
        room: targetRoomId 
    });

    // ✅ إرسال القائمة المحدثة لجميع الأعضاء مع room الصحيح
    console.log(`📋 [DEBUG] Broadcasting player_list to room ${targetRoomId}: ${JSON.stringify(roomPlayersList)}`);
    broadcastToPrivateRoom(targetRoomId, { 
        type: 'player_list', 
        data: roomPlayersList, 
        room: targetRoomId 
    }, playerId);  // exclude the new player

    console.log(`🚪 ${player?.name} انضم للغرفة: ${targetRoom.name} (players in room: ${targetRoom.players.length})`);
  }

  else if (type === 'leave_private_room') {
    if (player && player.privateRoomId) {
      const roomId = player.privateRoomId;
      
      if (privateRooms[roomId]) {
        privateRooms[roomId].players = privateRooms[roomId].players.filter(id => id !== playerId);
        
        // إرسال تحديث للقائمة
        const roomPlayersList = getPrivateRoomPlayers(roomId);
        broadcastToPrivateRoom(roomId, { type: 'player_list', data: roomPlayersList, room: roomId });

        // إذا كانت الغرفة فارغة - حذفها
        if (privateRooms[roomId].players.length === 0) {
          delete privateRooms[roomId];
          console.log(`🗑️ تم حذف غرفة فارغة: ${roomId}`);
        }
      }

      player.privateRoomId = null;
      sendTo(ws, { type: 'private_room_left', data: {} });
      console.log(`👋 ${player.name} غادر الغرفة الخاصة`);
    }
  }

  // ===== نظام الأصدقاء =====

  else if (type === 'add_friend') {
    const targetName = data.data.player_name;
    const targetPlayer = findPlayerByName(targetName);
    
    if (!targetPlayer) {
      sendTo(ws, { type: 'error', data: { message: 'اللاعب غير موجود' } });
      return;
    }

    if (targetPlayer.id === playerId) {
      sendTo(ws, { type: 'error', data: { message: 'لا يمكنك إضافة نفسك كصديق' } });
      return;
    }

    // التحقق من الصداقة الحالية
    if (!friendships[playerId]) friendships[playerId] = [];
    if (friendships[playerId].includes(targetPlayer.id)) {
      sendTo(ws, { type: 'error', data: { message: 'هذا اللاعب صديقك بالفعل' } });
      return;
    }

    // إضافة طلب صداقة
    const request = { from: playerId, to: targetPlayer.id, name: player?.name || 'مجهول', time: Date.now() };
    friendRequests.push(request);

    // إرسال طلب الصداقة للهدف
    if (targetPlayer.ws && targetPlayer.ws.readyState === WebSocket.OPEN) {
      sendTo(targetPlayer.ws, { 
        type: 'friend_request', 
        data: { id: playerId, name: player?.name || 'مجهول' } 
      });
    }

    sendTo(ws, { type: 'friends_list', data: getFriendsList(playerId) });
    console.log(`👤 طلب صداقة من ${player?.name} إلى ${targetName}`);
  }

  else if (type === 'accept_friend') {
    const fromId = data.data.from_id;
    const fromPlayer = players[fromId];

    // إضافة الصداقة للطرفين
    if (!friendships[playerId]) friendships[playerId] = [];
    if (!friendships[fromId]) friendships[fromId] = [];

    if (!friendships[playerId].includes(fromId)) {
      friendships[playerId].push(fromId);
    }
    if (!friendships[fromId].includes(playerId)) {
      friendships[fromId].push(playerId);
    }

    // حذف طلب الصداقة
    friendRequests = friendRequests.filter(r => !(r.from === fromId && r.to === playerId));

    // إرسال قائمة محدثة لكلا اللاعبين
    sendTo(ws, { type: 'friends_list', data: getFriendsList(playerId) });
    if (fromPlayer && fromPlayer.ws) {
      sendTo(fromPlayer.ws, { type: 'friends_list', data: getFriendsList(fromId) });
    }

    console.log(`✅ ${player?.name} و ${fromPlayer?.name} أصبحا أصدقاء`);
  }

  else if (type === 'reject_friend') {
    const fromId = data.data.from_id;
    
    // حذف طلب الصداقة فقط
    friendRequests = friendRequests.filter(r => !(r.from === fromId && r.to === playerId));
    
    console.log(`❌ ${player?.name} رفض طلب الصداقة من ${fromId}`);
  }

  else if (type === 'get_friends') {
    sendTo(ws, { type: 'friends_list', data: getFriendsList(playerId) });
  }

  else if (type === 'get_friend_requests') {
    const requests = friendRequests.filter(r => r.to === playerId).map(r => ({
      id: r.from,
      name: r.name,
      time: r.time
    }));
    sendTo(ws, { type: 'friend_requests', data: requests });
  }

  // ===== الرسائل الخاصة =====

  else if (type === 'private_message') {
    const targetId = data.data.target_id;
    const message = data.data.message;
    const targetPlayer = players[targetId];

    if (!targetPlayer) {
      sendTo(ws, { type: 'error', data: { message: 'اللاعب غير موجود' } });
      return;
    }

    // التحقق من الصداقة
    if (!friendships[playerId] || !friendships[playerId].includes(targetId)) {
      sendTo(ws, { type: 'error', data: { message: 'يجب أن تكون صديقاً لهذا اللاعب' } });
      return;
    }

    // حفظ الرسالة
    if (!privateMessages[targetId]) privateMessages[targetId] = [];
    privateMessages[targetId].push({
      from: playerId,
      fromName: player?.name || 'مجهول',
      message: message,
      time: Date.now()
    });

    if (!privateMessages[playerId]) privateMessages[playerId] = [];
    privateMessages[playerId].push({
      from: playerId,
      fromName: player?.name || 'مجهول',
      message: message,
      time: Date.now(),
      isSent: true
    });

    // إرسال الرسالة للهدف
    if (targetPlayer.ws && targetPlayer.ws.readyState === WebSocket.OPEN) {
      sendTo(targetPlayer.ws, { 
        type: 'private_message', 
        data: { player: player?.name || 'مجهول', message: message, from_id: playerId } 
      });
    }

    console.log(`💬 رسالة خاصة: ${player?.name} → ${targetPlayer.name}: ${message}`);
  }

  // ===== إشارات WebRTC (Signaling) =====
  else if (type === 'webrtc_signal' || type === 'sdp' || type === 'ice') {
    const targetId = data.data.target_id;
    const signalData = data.data;
    
    if (!targetId || !players[targetId]) {
      console.log(`❌ هدف الإشارة غير موجود: ${targetId}`);
      return;
    }

    const targetPlayer = players[targetId];
    if (targetPlayer.ws && targetPlayer.ws.readyState === WebSocket.OPEN) {
      sendTo(targetPlayer.ws, { 
        type: 'webrtc_signal', 
        data: {
          from_id: playerId,
          from_name: player?.name || 'مجهول',
          signal_type: signalData.signal_type,
          sdp: signalData.sdp,
          sdp_type: signalData.sdp_type,
          mid: signalData.mid,
          index: signalData.index
        } 
      });
      console.log(`📡 إعادة إرسال إشارة WebRTC من ${player?.name} إلى ${targetPlayer.name}`);
    }
  }

  // ===== طلب بدء مكالمة صوتية =====
  else if (type === 'voice_call_invite') {
    const targetId = data.data.target_id;
    console.log(`[DEBUG] voice_call_invite - targetId: ${targetId}, type: ${typeof targetId}`);
    console.log(`[DEBUG] All players: ${Object.keys(players)}`);
    
    const targetPlayer = players[targetId];

    if (!targetPlayer) {
      console.log(`[DEBUG] Target player NOT FOUND: ${targetId}`);
      sendTo(ws, { type: 'error', data: { message: 'اللاعب غير موجود' } });
      return;
    }

    console.log(`[DEBUG] Target player found: ${targetPlayer.name}`);
    
    // إرسال الدعوة للهدف
    if (targetPlayer.ws && targetPlayer.ws.readyState === WebSocket.OPEN) {
      sendTo(targetPlayer.ws, { 
        type: 'voice_call_invite', 
        data: { from_id: playerId, from_name: player?.name || 'مجهول' } 
      });
      console.log(`📞 [DEBUG] Invite sent to ${targetPlayer.name} (ID: ${targetId})`);
    } else {
      console.log(`[DEBUG] Target WS not open: ${targetPlayer.ws?.readyState}`);
    }
  }

  // ===== قبول أو رفض المكالمة =====
  else if (type === 'voice_call_response') {
    const targetId = data.data.target_id;
    const accept = data.data.accept;
    const targetPlayer = players[targetId];
    console.log(`[DEBUG] voice_call_response - targetId: ${targetId}, accept: ${accept}`);

    if (!targetPlayer) {
      console.log(`[DEBUG] Response target NOT FOUND: ${targetId}`);
      return;
    }

    if (targetPlayer.ws && targetPlayer.ws.readyState === WebSocket.OPEN) {
      sendTo(targetPlayer.ws, { 
        type: 'voice_call_response', 
        data: { from_id: playerId, from_name: player?.name || 'مجهول', accept: accept } 
      });
      console.log(`📞 [DEBUG] Response sent: ${accept ? 'accept' : 'reject'}`);
    }
  }
}

function handleDisconnect(playerId) {
  const player = players[playerId];
  
  if (player) {
    // مغادرة الغرفة الخاصة إن وجدت
    if (player.privateRoomId && privateRooms[player.privateRoomId]) {
      privateRooms[player.privateRoomId].players = privateRooms[player.privateRoomId].players.filter(id => id !== playerId);
      
      const roomPlayersList = getPrivateRoomPlayers(player.privateRoomId);
      broadcastToPrivateRoom(player.privateRoomId, { type: 'player_list', data: roomPlayersList, room: player.privateRoomId });

      if (privateRooms[player.privateRoomId].players.length === 0) {
        delete privateRooms[player.privateRoomId];
      }
    }

    // مغادرة الشات العام
    if (publicRooms[player.room]) {
      publicRooms[player.room].players = publicRooms[player.room].players.filter(id => id !== playerId);
      broadcastToRoom(player.room, { type: 'player_left', data: { name: player.name } });
      
      // ✅ إرسال player_list المحدث للجميع بعد المغادرة
      const updatedPlayers = getRoomPlayers(player.room);
      broadcastToRoom(player.room, { type: 'player_list', data: updatedPlayers, room: player.room });
    }

    // إرسال статус غير متصل للأصدقاء
    notifyFriendsOffline(playerId);

    console.log(`👋 ${player.name} غادر اللعبة`);
    delete players[playerId];
  }
}

// ===== دوال مساعدة =====

function getRoomPlayers(room) {
  return publicRooms[room]?.players
    .filter(id => players[id])
    .map(id => ({
      id: id,
      name: players[id].name,
      reputation: players[id].reputation || 0,
      joinedAt: players[id].joinedAt
    })) || [];
}

function getAvailablePrivateRooms() {
  return Object.values(privateRooms).map(room => ({
    id: room.id,
    name: room.name,
    description: room.description,
    ownerName: room.ownerName,
    playerCount: room.players.length,
    maxPlayers: room.maxPlayers
  }));
}

function getPrivateRoomPlayers(roomId) {
  return privateRooms[roomId]?.players
    .filter(id => players[id])
    .map(id => ({
      id: id,
      name: players[id].name,
      reputation: players[id].reputation || 0
    })) || [];
}

function broadcastToPrivateRoom(roomId, message, excludeId = null) {
  const msgStr = JSON.stringify(message);
  if (!privateRooms[roomId]) return;
  
  privateRooms[roomId].players.forEach(id => {
    if (id !== excludeId && players[id] && players[id].ws.readyState === WebSocket.OPEN) {
      players[id].ws.send(msgStr);
    }
  });
}

function findPlayerByName(name) {
  return Object.values(players).find(p => p.name === name);
}

function getFriendsList(playerId) {
  const friendIds = friendships[playerId] || [];
  return friendIds.map(id => ({
    id: id,
    name: players[id]?.name || 'مجهول',
    isOnline: players[id] ? true : false,
    reputation: players[id]?.reputation || 0
  }));
}

function notifyFriendsOffline(playerId) {
  const friendIds = friendships[playerId] || [];
  friendIds.forEach(friendId => {
    if (players[friendId] && players[friendId].ws.readyState === WebSocket.OPEN) {
      sendTo(players[friendId].ws, { 
        type: 'friend_offline', 
        data: { name: players[playerId]?.name || 'مجهول' } 
      });
    }
  });
}

function sendFriendsOnlineStatus(playerId) {
  const friendIds = friendships[playerId] || [];
  friendIds.forEach(friendId => {
    if (players[friendId] && players[friendId].ws.readyState === WebSocket.OPEN) {
      sendTo(players[friendId].ws, { 
        type: 'friend_online', 
        data: { name: players[playerId].name } 
      });
    }
  });
}

function sendTo(ws, message) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(message));
  }
}

function broadcastToRoomAll(room, message) {
  const msgStr = JSON.stringify(message);
  if (!publicRooms[room]) return;
  
  publicRooms[room].players.forEach(id => {
    if (players[id] && players[id].ws.readyState === WebSocket.OPEN) {
      players[id].ws.send(msgStr);
    }
  });
}

function broadcastToRoom(room, message, excludeId = null) {
  const msgStr = JSON.stringify(message);
  if (!publicRooms[room]) return;
  
  publicRooms[room].players.forEach(id => {
    if (id !== excludeId && players[id] && players[id].ws.readyState === WebSocket.OPEN) {
      players[id].ws.send(msgStr);
    }
  });
}

console.log('🎮 WebSocket Server (Chat) running on port 3000');
console.log(`📝 الشات العام: main`);
console.log(`📝 متطلبات إنشاء غرفة خاصة: سمعة >= ${REQUIRED_REPUTATION}`);

// ===== خادم الإشارات (Signaling Server) للصوت =====
const signalingWss = new WebSocket.Server({ port: 3002 });

// 🗃️ متتبع الغرف للصوت
const voiceRooms = new Map();
const voiceClients = new Map(); // Global map for quick player lookup

signalingWss.on('connection', (ws) => {
  console.log('🔌 Client connected for voice signaling');
  
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message.toString());
      const { type, room_id, player_id, player_name } = data;
      
      // 0️⃣ تسجيل اللاعب (بديل لـ join_voice_room)
      if (type === 'register') {
        const pid = String(msg.player_id || msg.player_id || Math.floor(Math.random() * 10000));
        const pname = msg.player_name || 'Unknown';
        const rid = msg.room_id || 'main';
        
        // Save to WebSocket object
        ws.playerId = pid;
        ws.playerName = pname;
        ws.currentVoiceRoom = rid;
        
        // Add to voiceClients Map (by ID)
        voiceClients.set(pid, ws);
        
        // Add to voiceRooms Map (by room)
        if (!voiceRooms.has(rid)) {
          voiceRooms.set(rid, new Set());
        }
        voiceRooms.get(rid).add(ws);
        
        console.log(`✅ [DEBUG] Player registered: ID=${pid}, Name=${pname}, Room=${rid}`);
        console.log(`📋 [DEBUG] voiceClients size: ${voiceClients.size}`);
        console.log(`📋 [DEBUG] voiceRooms[${rid}] size: ${voiceRooms.get(rid).size}`);
        
        // ✅ إرسال تأكيد التسجيل
        ws.send(JSON.stringify({ 
          type: 'voice_registered', 
          player_id: pid,
          room_id: rid,
          players: [{ id: pid, name: pname }]
        }));
        return;
      }
      
      // 1️⃣ دخول غرفة صوتية
      if (type === 'join_voice_room') {
        if (!room_id) {
          ws.send(JSON.stringify({ type: 'error', msg: 'معرف الغرفة مطلوب' }));
          return;
        }
        
        if (!voiceRooms.has(room_id)) {
          voiceRooms.set(room_id, new Set());
        }
        
        voiceRooms.get(room_id).add(ws);
        ws.currentVoiceRoom = room_id;
        ws.playerId = player_id || ws.playerId || Math.floor(Math.random() * 10000);
        ws.playerName = player_name || 'لاعب';
        
        console.log(`🎙️ اللاعب ${ws.playerName} (ID: ${ws.playerId}) دخل الغرفة الصوتية: ${room_id}`);
        
        const players = Array.from(voiceRooms.get(room_id)).map(p => ({
          id: p.playerId,
          name: p.playerName
        }));
        
        ws.send(JSON.stringify({ 
          type: 'voice_room_joined', 
          room_id: room_id, 
          players: players 
        }));
        
        // ✅ إشعار اللاعبين الآخرين بانضمام لاعب جديد
        voiceRooms.get(room_id).forEach(peer => {
          if (peer !== ws && peer.readyState === WebSocket.OPEN) {
            peer.send(JSON.stringify({
              type: 'player_joined',
              player_id: ws.playerId,
              player_name: ws.playerName,
              room_id: room_id
            }));
          }
        });
        
        return;
      }
      
      // 2️⃣ مغادرة غرفة صوتية
      if (type === 'leave_voice_room') {
        if (ws.currentVoiceRoom && voiceRooms.has(ws.currentVoiceRoom)) {
          voiceRooms.get(ws.currentVoiceRoom).delete(ws);
          
          if (voiceRooms.get(ws.currentVoiceRoom).size === 0) {
            voiceRooms.delete(ws.currentVoiceRoom);
          } else {
            // إعلام الباقين بالمغادرة
            const leaveMsg = JSON.stringify({ 
              type: 'voice_player_left', 
              player_id: ws.playerId, 
              room_id: ws.currentVoiceRoom 
            });
            voiceRooms.get(ws.currentVoiceRoom).forEach(peer => {
              if (peer !== ws && peer.readyState === WebSocket.OPEN) {
                peer.send(leaveMsg);
              }
            });
          }
        }
        ws.currentVoiceRoom = null;
        return;
      }
      
      // 3️⃣ توجيه إشارات WebRTC للغرفة فقط
      if (type === 'sdp' || type === 'ice') {
        if (!ws.currentVoiceRoom || !voiceRooms.has(ws.currentVoiceRoom)) {
          console.log(`⚠️player ${ws.playerId} not in any room, ignoring ${type}`);
          return;
        }
        
        const routingMsg = JSON.stringify({
          type: type,
          from_id: ws.playerId,
          from_name: ws.playerName,
          room_id: ws.currentVoiceRoom,
          sdp: data.sdp,
          sdp_type: data.sdp_type,
          mid: data.mid,
          index: data.index
        });
        
        voiceRooms.get(ws.currentVoiceRoom).forEach(peer => {
          if (peer !== ws && peer.readyState === WebSocket.OPEN) {
            peer.send(routingMsg);
          }
        });
        
        console.log(`📡 [${type}] relayed to room ${ws.currentVoiceRoom}`);
        return;
      }
      
      // 4️⃣ طلبات المكالمة (voice_offer/voice_answer)
      if (type === 'voice_offer' || type === 'voice_answer') {
        if (!ws.currentVoiceRoom || !voiceRooms.has(ws.currentVoiceRoom)) return;
        
        const targetId = data.target_id;
        console.log(`[DEBUG] Processing ${type}: targetId=${targetId}, room=${ws.currentVoiceRoom}`);
        
        // Find specific target
        let found = false;
        voiceRooms.get(ws.currentVoiceRoom).forEach(peer => {
          if (peer !== ws && peer.readyState === WebSocket.OPEN) {
            // Send to specific target (by matching playerId)
            if (String(peer.playerId) === String(targetId)) {
              const routingMsg = JSON.stringify({
                type: type,
                from_id: ws.playerId,
                from_name: ws.playerName,
                room_id: ws.currentVoiceRoom,
                accept: data.accept,
                target_id: data.target_id
              });
              peer.send(routingMsg);
              console.log(`[DEBUG] Sent ${type} to specific target: ${peer.playerName} (ID: ${peer.playerId})`);
              found = true;
            }
          }
        });
        
        if (!found) {
          console.log(`[DEBUG] Target ${targetId} not found in room, broadcasting to all`);
          // Fallback: broadcast to everyone
          const routingMsg = JSON.stringify({
            type: type,
            from_id: ws.playerId,
            from_name: ws.playerName,
            room_id: ws.currentVoiceRoom,
            accept: data.accept,
            target_id: data.target_id
          });
          voiceRooms.get(ws.currentVoiceRoom).forEach(peer => {
            if (peer !== ws && peer.readyState === WebSocket.OPEN) {
              peer.send(routingMsg);
            }
          });
        }
        
        console.log(`📞 [${type}] sent`);
        return;
      }
      
      // 4b️⃣ voice_call_invite - direct message
      if (type === 'voice_call_invite') {
        const targetId = String(data.target_id);
        console.log(`[DEBUG] voice_call_invite: targetId=${targetId}, myId=${ws.playerId}, room=${ws.currentVoiceRoom}`);
        
        // ✅ التحقق من التسجيل
        if (!ws.playerId) {
          console.log(`[DEBUG] ❌ Sender not registered yet! Sending error response.`);
          ws.send(JSON.stringify({
            type: 'error',
            msg: 'Register first before calling'
          }));
          return;
        }
        
        if (!ws.currentVoiceRoom || !voiceRooms.has(ws.currentVoiceRoom)) {
          console.log(`[DEBUG] Not in any room!`);
          return;
        }
        
        let found = false;
        voiceRooms.get(ws.currentVoiceRoom).forEach(peer => {
          if (peer !== ws && peer.readyState === WebSocket.OPEN) {
            if (String(peer.playerId) === targetId) {
              const msg = JSON.stringify({
                type: 'voice_call_invite',
                from_id: ws.playerId,
                from_name: ws.playerName,
                target_id: targetId
              });
              peer.send(msg);
              console.log(`[DEBUG] ✅ Sent voice_call_invite to ${peer.playerName} (ID: ${peer.playerId})`);
              found = true;
            }
          }
        });
        
        if (!found) {
          console.log(`[DEBUG] ❌ Target ${targetId} not found in room`);
          console.log(`[DEBUG] Room players: ${Array.from(voiceRooms.get(ws.currentVoiceRoom)).map(p => p.playerId).join(', ')}`);
        }
        return;
      }
      
      // 5️⃣ رسالة شات نصية (معزولة بالغرفة)
      if (type === 'chat_message' && ws.currentVoiceRoom && room_id === ws.currentVoiceRoom) {
        const chatMsg = JSON.stringify({
          type: 'chat_message',
          room_id: ws.currentVoiceRoom,
          sender_id: ws.playerId,
          sender_name: ws.playerName,
          content: (data.content || "").substring(0, 500),
          timestamp: data.timestamp || new Date().toISOString()
        });
        
        voiceRooms.get(ws.currentVoiceRoom).forEach(peer => {
          if (peer.readyState === WebSocket.OPEN) {
            peer.send(chatMsg);
          }
        });
        
        console.log(`💬 [Chat] relayed to room ${ws.currentVoiceRoom}`);
        return;
      }
      
      // 6️⃣ دعوة لاعب (إرسال رابط غرفة)
      if (type === 'invite_player' && ws.currentVoiceRoom) {
        const inviteCode = Buffer.from(`${ws.currentVoiceRoom}:${ws.playerId}`).toString('base64');
        const inviteLink = `souqhikayat://join?code=${inviteCode}`;
        ws.send(JSON.stringify({ 
          type: 'invite_generated', 
          invite_code: inviteCode, 
          invite_link: inviteLink 
        }));
        console.log(`🔗 Invite generated for room ${ws.currentVoiceRoom}`);
        return;
      }
      
      // 7️⃣ تحديث حالة اللاعب (مايك/فيديو/كتابة/حالة)
      if (type === 'player_state_update' && ws.currentVoiceRoom) {
        ws.status = data.status || ws.status || 'online';
        ws.mic = data.mic !== undefined ? data.mic : ws.mic;
        ws.video = data.video !== undefined ? data.video : ws.video;
        ws.typing = data.typing !== undefined ? data.typing : ws.typing;
        
        const updateMsg = JSON.stringify({
          type: 'player_state_broadcast',
          room_id: ws.currentVoiceRoom,
          player_id: ws.playerId,
          status: ws.status,
          mic: ws.mic,
          video: ws.video,
          typing: ws.typing
        });
        
        voiceRooms.get(ws.currentVoiceRoom).forEach(peer => {
          if (peer !== ws && peer.readyState === WebSocket.OPEN) {
            peer.send(updateMsg);
          }
        });
        
        console.log(`👤 [State] player ${ws.playerId} updated: mic=${ws.mic}, typing=${ws.typing}`);
        return;
      }
      
      // 8️⃣ طلب قائمة الأصدقاء
      if (type === 'friend_list_request') {
        ws.send(JSON.stringify({ 
          type: 'friend_list', 
          friends: ws.friends || [],
          message: "📋 نظام الأصدقاء قيد التطوير"
        }));
        return;
      }
      
      // 9️⃣ إضافة صديق
      if (type === 'friend_add' && data.target_id) {
        if (!ws.friends) ws.friends = [];
        if (!ws.friends.includes(data.target_id)) {
          ws.friends.push(data.target_id);
          ws.send(JSON.stringify({ type: 'friend_action_result', action: 'added', target_id: data.target_id }));
          console.log(`👫 Friend added: ${ws.playerId} -> ${data.target_id}`);
        }
        return;
      }
      
    } catch (e) {
      console.error('[Voice] Error: ' + e.message);
    }
  });

  ws.on('close', () => {
    // تنظيف عند الانقطاع
    if (ws.playerId) {
      voiceClients.delete(ws.playerId);
      console.log(`🗑️ [DEBUG] Removed ${ws.playerId} from voiceClients`);
    }
    
    if (ws.currentVoiceRoom && voiceRooms.has(ws.currentVoiceRoom)) {
      voiceRooms.get(ws.currentVoiceRoom).delete(ws);
      
      if (voiceRooms.get(ws.currentVoiceRoom).size === 0) {
        voiceRooms.delete(ws.currentVoiceRoom);
      } else {
        const leaveMsg = JSON.stringify({ 
          type: 'voice_player_left', 
          player_id: ws.playerId, 
          room_id: ws.currentVoiceRoom 
        });
        voiceRooms.get(ws.currentVoiceRoom).forEach(peer => {
          if (peer.readyState === WebSocket.OPEN) {
            peer.send(leaveMsg);
          }
        });
      }
    }
    console.log(`❌ Client ${ws.playerId} disconnected from voice signaling`);
  });
});

console.log('🎙️ Voice Signaling Server running on ws://localhost:3002 (with room support)');

// دالة مساعدة للحصول على WebSocket اللاعب
function _get_player_ws_by_id(playerId) {
  const player = players[playerId];
  if (player && player.ws) {
    return player.ws;
  }
  return null;
}

process.on('uncaughtException', (err) => {
    console.error('❌ Uncaught Exception:', err.stack || err.message);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});