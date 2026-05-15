import express from 'express'
import cookieParser from 'cookie-parser'
import jwt from 'jsonwebtoken'
// Cambiamos JWT_SECRET por SECRET_JWT_KEY para que coincida con tu config.js
import { PORT, SECRET_JWT_KEY } from './config.js' 
import { UserRepository } from './user-repository.js'

const app = express()
app.set('view engine', 'ejs')
app.use(express.json())
app.use(cookieParser())

// Middleware de sesión
app.use((req, res, next) => {
  const token = req.cookies.access_token
  req.session = { user: null }
  
  try {
    // Usamos la clave correcta
    const data = jwt.verify(token, SECRET_JWT_KEY)
    req.session.user = data
  } catch {}
  
  next()
})

app.get('/', (req, res) => {
  res.render('index', { user: req.session.user })
})

app.get('/protected', (req, res) => {
  if (!req.session.user) return res.status(403).send('Acceso denegado')
  // Pasamos el usuario a la vista protegida
  res.render('protected', req.session.user)
})

app.post('/login', async (req, res) => {
  try {
    const user = await UserRepository.login(req.body)
    // Firmamos el token con la clave correcta
    const token = jwt.sign(
      { id: user._id, username: user.username }, 
      SECRET_JWT_KEY, 
      { expiresIn: '1h' }
    )
    
    res.cookie('access_token', token, { 
      httpOnly: true, 
      secure: process.env.NODE_ENV === 'production', // Solo segura en Render (HTTPS)
      sameSite: 'strict',
      maxAge: 1000 * 60 * 60 
    }).send({ user })
    
  } catch (e) { 
    res.status(401).send({ error: e.message }) 
  }
})

app.post('/register', async (req, res) => {
  try {
    await UserRepository.create(req.body)
    res.status(201).send({ ok: true })
  } catch (e) { 
    res.status(400).send({ error: e.message }) 
  }
})

app.post('/logout', (req, res) => {
  res.clearCookie('access_token').send({ ok: true })
})

// Iniciamos el servidor
app.listen(PORT, () => console.log(`Servidor en puerto ${PORT}`))