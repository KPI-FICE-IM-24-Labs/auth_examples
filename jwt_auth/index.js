const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('jsonwebtoken');

const port = 3000;
const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SECRET = 'secret';

const users = [
    { login: 'Login', password: 'Password', username: 'Username' },
    { login: 'Login1', password: 'Password1', username: 'Username1' }
];

const jwtAuth = (req, res, next) => {
    const header = req.get('Authorization');

    if (header) {
        try {
            const token = header.split(" ")[1];
            const payload = jwt.verify(token, SECRET);
            const user = users.find(u => u.login === payload.login);

            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }

            return res.json({
                username: user.username,
                logout: 'http://localhost:3000/logout',
            });
        } catch (err) {
            return res.status(401).json({ message: 'Invalid or expired token' });
        }
    }

    next();
};

app.get('/', jwtAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/logout', (req, res) => {
    res.redirect('/');
});

app.post('/api/login', (req, res) => {
    const { login, password } = req.body;

    const user = users.find(u => u.login === login && u.password === password);
    if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ login }, SECRET, { expiresIn: '1m' });
    return res.json({ token });
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});
