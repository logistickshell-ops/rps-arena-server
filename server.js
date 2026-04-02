// server.js
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
require('dotenv').config();

// --- Конфигурация ---
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.CORS_ORIGIN || "*", // В продакшене укажи точный URL фронтенда
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error("Ошибка: Не установлен JWT_SECRET в .env или переменных окружения.");
  process.exit(1);
}

// --- Middleware ---
app.use(express.json());
app.use(cors());

// --- Имитация базы данных (заменить на реальную БД позже) ---
let users = []; // [{ id, email, passwordHash, balance, level, inventory, deck, stats, achievements }, ...]

// --- Валидационные схемы Joi ---
const registerSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  playerName: Joi.string().min(3).max(30).required(), // Добавлено имя игрока
  confirmPassword: Joi.string().valid(Joi.ref('password')).required() // Добавлено подтверждение пароля
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required()
});

// --- Функции аутентификации ---
const generateToken = (userId) => {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' }); // Токен на 7 дней
};

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Доступ запрещён. Требуется токен.' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error("Ошибка проверки токена:", err);
      return res.status(403).json({ error: 'Неверный токен.' });
    }
    req.userId = decoded.userId;
    next();
  });
};

// --- Роуты аутентификации ---
app.post('/api/auth/register', async (req, res) => {
  try {
    const { error, value } = registerSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { email, password, playerName } = value; // Извлекаем playerName

    // Проверка, существует ли пользователь с таким email или playerName
    const existingUserByEmail = users.find(u => u.email === email);
    if (existingUserByEmail) {
      return res.status(409).json({ error: 'Пользователь с таким email уже существует.' });
    }
    
    const existingUserByName = users.find(u => u.playerName === playerName);
    if (existingUserByName) {
      return res.status(409).json({ error: 'Имя игрока уже занято.' });
    }

    // Хэширование пароля
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Создание пользователя
    const newUser = {
      id: Date.now().toString(), // Простой ID, в реальной БД - UUID или автоинкремент
      email,
      playerName, // Сохраняем имя игрока
      passwordHash: hashedPassword,
      balance: 1000, // Начальный баланс
      level: 1,
      inventory: [], // Коллекция карт
      deck: [],      // Боевая колода
      stats: {       // Статистика
        totalWins: 0,
        totalLosses: 0,
        currentStreak: 0,
        bestStreak: 0,
        totalBattles: 0
      },
      achievements: {}, // Достижения
      quests: []         // Ежедневные задания
    };

    users.push(newUser);

    // Генерация токена
    const token = generateToken(newUser.id);

    // Возвращаем токен и базовую информацию
    res.status(201).json({
      message: 'Регистрация успешна',
      token,
      user: { 
        id: newUser.id, 
        email: newUser.email,
        playerName: newUser.playerName, // Возвращаем имя игрока
        balance: newUser.balance, 
        level: newUser.level 
      }
    });
  } catch (error) {
    console.error("Ошибка при регистрации:", error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { email, password } = value;

    // Поиск пользователя
    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(401).json({ error: 'Неверный email или пароль.' });
    }

    // Проверка пароля
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Неверный email или пароль.' });
    }

    // Генерация токена
    const token = generateToken(user.id);

    // Возвращаем токен и базовую информацию
    res.json({
      message: 'Вход успешен',
      token,
      user: { 
        id: user.id, 
        email: user.email,
        playerName: user.playerName, // Возвращаем имя игрока
        balance: user.balance, 
        level: user.level 
      }
    });
  } catch (error) {
    console.error("Ошибка при входе:", error);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

// --- Защищённые роуты (требуют токен) ---
// Пример: Получить профиль пользователя
app.get('/api/user/profile', authenticateToken, (req, res) => {
  // req.userId содержит ID аутентифицированного пользователя
  const user = users.find(u => u.id === req.userId);
  if (!user) {
    return res.status(404).json({ error: 'Пользователь не найден' });
  }

  // Возвращаем информацию, НЕ включая passwordHash
  res.json({
    id: user.id,
    email: user.email,
    playerName: user.playerName, // Возвращаем имя игрока
    balance: user.balance,
    level: user.level,
    inventory: user.inventory,
    deck: user.deck,
    stats: user.stats,
    achievements: user.achievements,
    quests: user.quests
  });
});

// Пример: Обновить баланс пользователя
app.put('/api/user/balance', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.userId);
  if (!user) {
    return res.status(404).json({ error: 'Пользователь не найден' });
  }
  
  const { newBalance } = req.body;
  if (typeof newBalance !== 'number' || newBalance < 0) {
    return res.status(400).json({ error: 'Неверный формат баланса' });
  }
  
  user.balance = newBalance;
  res.json({ message: 'Баланс обновлён', newBalance: user.balance });
});

// Пример: Обновить боевую колоду пользователя
app.put('/api/user/deck', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.userId);
  if (!user) {
    return res.status(404).json({ error: 'Пользователь не найден' });
  }
  
  const { newDeck } = req.body;
  // Проверка, что newDeck - массив и не превышает 5 карт
  if (!Array.isArray(newDeck) || newDeck.length > 5) {
    return res.status(400).json({ error: 'Колода может содержать не более 5 карт' });
  }
  
  // Проверка, что все карты из колоды принадлежат пользователю (опционально)
  // ... логика проверки ...
  
  user.deck = newDeck;
  res.json({ message: 'Колода обновлена', deck: user.deck });
});

// Пример: Обновить статистику пользователя после боя
app.put('/api/user/stats', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.userId);
  if (!user) {
    return res.status(404).json({ error: 'Пользователь не найден' });
  }
  
  const { won, newStats } = req.body;
  if (typeof won !== 'boolean' || !newStats) {
    return res.status(400).json({ error: 'Неверный формат данных статистики' });
  }
  
  // Проверка, что newStats соответствует структуре
  user.stats = newStats;
  
  // Опционально: обновить достижения
  // ... логика обновления достижений ...
  
  res.json({ message: 'Статистика обновлена', stats: user.stats });
});

// --- Обработка WebSocket подключений ---
io.use((socket, next) => {
  // Пример: Извлечение токена из query параметра при подключении
  const token = socket.handshake.auth.token;
  if (!token) {
    next(new Error("Требуется аутентификация"));
    return;
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return next(new Error("Неверный токен"));
    }
    socket.userId = decoded.userId; // Сохраняем ID пользователя в сокете
    next();
  });
});

io.on('connection', (socket) => {
  console.log(`Пользователь ${socket.userId} подключился через Socket.IO`);

  // Пример: обработка события начала боя
  socket.on('start_battle_request', (data) => {
    // Логика поиска противника, создания комнаты и т.д.
    console.log(`Пользователь ${socket.userId} хочет начать бой.`);
    // ... реализация ...
  });

  socket.on('disconnect', () => {
    console.log(`Пользователь ${socket.userId} отключился`);
  });
});

// --- Простой маршрут для проверки ---
app.get('/', (req, res) => {
  res.send('RPS Arena MP Server is running!');
});

// --- Запуск сервера ---
server.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});

module.exports = { app, io };
