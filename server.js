require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());

// Configuração do banco de dados SQLite
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) console.error(err.message);
    else console.log("Banco de dados conectado!");
});

// Criar tabela se não existir
db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");

// Configuração de upload de arquivos (PDFs)
const storage = multer.diskStorage({
    destination: 'uploads/',
    filename: (req, file, cb) => cb(null, 'livro.pdf')
});
const upload = multer({ storage });

// Rota para cadastrar usuário (apenas uma vez)
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hash = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hash], (err) => {
        if (err) return res.status(400).json({ error: "Usuário já existe" });
        res.json({ message: "Usuário criado!" });
    });
});

// Rota de login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: "Usuário ou senha incorretos" });
        }
        const token = jwt.sign({ username }, process.env.SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    });
});

// Rota para enviar um livro PDF (somente com autenticação)
app.post('/upload', upload.single('file'), (req, res) => {
    res.json({ message: "Livro enviado com sucesso!" });
});

// Rota para acessar o livro protegido
app.get('/livro', (req, res) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: "Acesso negado" });

    jwt.verify(token, process.env.SECRET_KEY, (err) => {
        if (err) return res.status(403).json({ error: "Token inválido" });
        res.sendFile(__dirname + '/uploads/livro.pdf');
    });
});

// Iniciar o servidor
app.listen(5000, () => console.log("Servidor rodando na porta 5000"));
