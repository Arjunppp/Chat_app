import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import mongoose from 'mongoose';
import { User } from './models/userModel.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import http from 'http';
import { Server } from 'socket.io';

const port = 5000;
const app = express();
const server = http.createServer(app);
const io = new Server(server); //this will handle the socket request

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.static(path.resolve(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

mongoose.connect('mongodb://localhost:27017/blogSite').then(() => {
    console.log('Db is connected');
});

app.get('/', (req, res) => {
    res.sendFile(path.resolve(__dirname, 'public', 'html', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.resolve(__dirname, 'public', 'html', 'login.html'));
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    let result = await User.find({ username: username });
    let ispasswordMatch = await bcrypt.compare(password, result[0].password);

    if (ispasswordMatch) {
        let tokenData = { "id": result[0]._id, "username": result[0].username, "role": result[0].role };
        const token = jwt.sign({ tokenData }, 'CHATSECRETKEY');
        res.cookie('userToken', token).redirect('/chat');
    } else {
        res.redirect('/login');
    }
});

app.get('/signup', (req, res) => {
    res.sendFile(path.resolve(__dirname, 'public', 'html', 'signup.html'));
});

app.get('/chat', (req, res) => {
    res.sendFile(path.resolve(__dirname, 'public', 'html', 'chat.html'));
});

const authenticate = (socket, next) => {
    const token = socket.handshake.auth.token;
    try {
        const user = jwt.verify(token, 'CHATSECRETKEY');
        socket.user = user.tokenData.username;
        console.log('Authenticated user:', socket.user);
        next();
    } catch (err) {
        console.error('Authentication error:', err);
        next(new Error('Authentication error'));
    }
};

const userSockets = new Map();

io.use(authenticate).on('connection', (socket) => {
    console.log('User connected:', socket.id);
    userSockets.set(socket.user, socket);
    console.log('Current userSockets length:', userSockets.size);

    socket.on('private message', ({ message, recipient }) => {
        console.log('Received private message:', { message, recipient });
        const recipientSocket = userSockets.get(recipient);
        if (recipientSocket) {
            console.log('Sending message to recipient:', recipient);
            console.log('Recipient socket:', recipientSocket.id);
            recipientSocket.emit('private message', {
                sender: socket.user,
                message: message
            });
        } else {
            console.log('Recipient not connected:', recipient);
        }
    });

    socket.on('disconnect', () => {
        userSockets.delete(socket.user);
        console.log('Updated userSockets:', userSockets.size);
    });
});

server.listen(port, () => {
    console.log('The Chat Application is running on port', port);
});
