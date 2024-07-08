const express = require('express')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const { PrismaClient } = require('@prisma/client')
const prisma = new PrismaClient()
const secret = process.env.SECRET_KEY

const router = express.Router()

router.post('/register', async (req, res) => {
    const { username, password } = req.body

    if (!username || !password) {
        return res
            .status(400)
            .send({ error: 'Missing fields in the request body' })
    }
    const userExists = await prisma.user.findUnique({
        where: { username: username },
    })

    if (userExists) {
        return res.status(409).send({ error: 'User already exists' })
    }
    const hash = await bcrypt.hash(password, 8)
    const user = await prisma.user.create({
        data: {
            username: username,
            password: hash,
        },
    })
    return res.status(201).send({ user })
})

router.post('/login', async (req, res) => {
    const { username, password } = req.body
    try {
        const user = await prisma.user.findUniqueOrThrow({
            where: { username: username },
        })

        const hasMatchingHash = await bcrypt.compare(password, user.password)

        if (!hasMatchingHash) {
            return res.status(401).send({ error: 'Password incorrect' })
        }

        const token = await jwt.sign({ username }, secret)

        return res.status(201).send({ token })
    } catch (e) {
        if (e.code === 'P2025') {
            return res.status(404).send({ error: 'User not found' })
        }

        return res.status(500).send({ error: e.message })
    }
})

router.get('/profile', (req, res) => {
    const parsedAuth = req.headers.authorization.replace('Bearer ', '')

    try {
        const isValid = jwt.verify(parsedAuth, secret)
        return res.send({ isValid:true, username:isValid.username})
    } catch (e) {
        return res.status(401).send({ error: 'Access Forbidden' })
    }
})

module.exports = router
