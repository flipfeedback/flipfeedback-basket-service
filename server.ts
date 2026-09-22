/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// The basket service: the storefront's basket read endpoint on its own, with the
// storefront's models, auth and helpers. Everything else the storefront served lives
// elsewhere now.

import crypto from 'node:crypto'
import http from 'node:http'
import path from 'node:path'
import express, { type Request, type Response, type NextFunction } from 'express'
import bodyParser from 'body-parser'
import cookieParser from 'cookie-parser'
import config from 'config'
import i18n from 'i18n'

import logger from './lib/logger'
import * as utils from './lib/utils'
import * as security from './lib/insecurity'
import { sequelize } from './models'
import { UserModel } from './models/user'
import { BasketModel } from './models/basket'
import { retrieveBasket } from './routes/basket'

export const app = express()
const server = new http.Server(app)

app.use(cookieParser('kekse'))

i18n.configure({
  locales: ['en'],
  directory: path.resolve('i18n'),
  cookie: 'language',
  defaultLocale: 'en',
  updateFiles: false
})
app.use(i18n.init)

app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())
app.use((req: Request, res: Response, next: NextFunction) => {
  req.body = req.body ?? {}
  next()
})

app.use(security.updateAuthenticatedUsers())
/* Baskets: Unauthorized users are not allowed to access baskets */
app.use('/rest/basket', security.isAuthorized(), security.appendUserId())
app.use('/rest/basket/:id', security.isAuthorized())
app.get('/rest/basket/:id', utils.asyncHandler(retrieveBasket()))

app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  if (err?.name === 'UnauthorizedError') {
    res.status(401).json({ status: 'error', message: err.message })
    return
  }
  logger.error(err?.message ?? String(err))
  res.status(500).json({ status: 'error', message: 'Unexpected error' })
})

/* Two shoppers, each with an empty basket, so a fresh service has something to serve */
async function seedShoppers () {
  for (const [email, name] of [['ana@flipfeedback.com', 'Ana'], ['sam@flipfeedback.com', 'Sam']]) {
    const [user] = await UserModel.findOrCreate({
      where: { email },
      defaults: { email, username: name, password: crypto.randomUUID(), role: 'customer' }
    })
    await BasketModel.findOrCreate({ where: { UserId: user.id }, defaults: { UserId: user.id } })
  }
}

export async function start (readyCallback?: () => void) {
  await sequelize.sync({ force: true })
  await seedShoppers()
  const port = process.env.PORT ?? config.get<number>('server.port')
  server.listen(port, () => {
    logger.info(`Basket service listening on port ${port}`)
    if (readyCallback != null) readyCallback()
  })
}

export function close (exitCode: number | undefined) {
  server.close()
  if (exitCode !== undefined) process.exit(exitCode)
}

if (require.main === module) {
  start().catch((err) => {
    logger.error(err?.message ?? String(err))
    process.exit(1)
  })
}
