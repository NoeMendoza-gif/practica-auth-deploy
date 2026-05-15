import DBLocal from 'db-local'
import crypto from 'node:crypto'
import bcrypt from 'bcrypt'
import { SALT_ROUNDS } from './config.js'

const { Schema } = new DBLocal({ path: './db' })

const User = Schema('User', {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true }
})

export class UserRepository {
  static async create ({ username, password }) {
    if (username.length < 3) throw new Error('Usuario muy corto')
    const exists = User.findOne({ username })
    if (exists) throw new Error('El usuario ya existe')

    const id = crypto.randomUUID()
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS)
    User.create({ _id: id, username, password: hashedPassword }).save()
    return id
  }

  static async login ({ username, password }) {
    const user = User.findOne({ username })
    if (!user) throw new Error('Usuario no encontrado')
    const isValid = await bcrypt.compare(password, user.password)
    if (!isValid) throw new Error('Contraseña incorrecta')
    const { password: _, ...publicUser } = user
    return publicUser
  }
}