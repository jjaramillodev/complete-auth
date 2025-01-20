import crypto from 'node:crypto'

import bcrypt from 'bcrypt'
import DBLocal from 'db-local'
import { SALT_ROUNDS } from './config.js'

const { Schema } = new DBLocal({ path: './db' })

const User = Schema('User', {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true }
})

export class UserRepository {
  static async create ({ username, password }) {
    // validaciones
    Validation.username(username)
    Validation.password(password)
    // asegurarse que el username no existe
    const user = User.findOne({ username })
    if (user) throw new Error('username already exists')
    // generar un id
    const id = crypto.randomUUID()
    // hashear el password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS)
    // crear el usuario en la base de datos
    User.create({
      _id: id,
      username,
      password: hashedPassword
    }).save()
    // devolver el id generado
    return id
  }

  static async login ({ username, password }) {
    // validaciones
    Validation.username(username)
    Validation.password(password)
    // verificar que el usuario exista
    const user = User.findOne({ username })
    if (!user) throw new Error('username doest not exist')
    // validar la contraseña
    const isValid = await bcrypt.compare(password, user.password)
    if (!isValid) throw new Error('password is invalid')
    // retornar el usuario
    const { password: _, ...publicUser } = user
    return publicUser
  }
}

class Validation {
  static username (username) {
    if (typeof username !== 'string') throw new Error('username must be a string')
    if (username.length < 3) throw new Error('username must be at least 3 characters long')
  }

  static password (password) {
    if (typeof password !== 'string') throw new Error('password must be a string')
    if (password.length < 6) throw new Error('password must be at least 6 characters long')
  }
}
