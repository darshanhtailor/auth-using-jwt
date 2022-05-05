require('dotenv').config()

const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const User = require('./models/user')

app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.set('view-engine', 'ejs')

const mongoURI = process.env.DB_URL
mongoose.connect(mongoURI)
const jwtSec = 60*30

app.get('/', notAuthenticateToken, (req, res)=>{
    res.render('index.ejs')
})

app.get('/home', authenticateToken, async(req, res)=>{
    const users = await User.find().select('name email -_id')
    res.render('home.ejs', {
        users,
        email: req.user.email
    })
})

app.get('/login', notAuthenticateToken, (req, res)=>{
    res.render('login.ejs')
})

app.get('/register', notAuthenticateToken, (req, res)=>{
    res.render('register.ejs')
})

app.post('/login', async(req, res) => {
    const user = await User.findOne({ email: req.body.email })

	if (!user) {
		return res.send('No user found')
	}
    
	try {
        if (await bcrypt.compare(req.body.password, user.password)) {
            const accessToken = jwt.sign({ name: req.body.name, email: req.body.email }, process.env.JWT_SECRET, { expiresIn: jwtSec })
            res.cookie('token', accessToken, { maxAge: jwtSec*1000 })
            res.redirect('/home')
		} else {
			res.send('Incorrect Password')
		}
	} catch (e) {
		res.send(e)
	}   
})

app.post('/register', async(req, res)=>{
    try {
		const hashedPassword = await bcrypt.hash(req.body.password, 10)
		const user = new User({ 
			name: req.body.name, 
			email: req.body.email, 
			password: hashedPassword
		})
		await user.save()
		res.redirect('/login')
	} catch {
		res.redirect('/register')
	}
})

app.post('/refresh', (req, res) => {
    const token = req.cookies.token

    if (!token) return res.status(401).end()

    let payload
	try {
		payload = jwt.verify(token, process.env.JWT_SECRET)
	} catch (e) {
		if (e instanceof jwt.JsonWebTokenError) {
			return res.status(401).end()
		}
		return res.status(400).end()
	}

    const newToken = jwt.sign({ name: payload.name, email: payload.email }, process.env.JWT_SECRET, { expiresIn: jwtSec})
    res.cookie('token', newToken, { maxAge: jwtSec*1000 })
    res.end()
})

function authenticateToken(req, res, next) {
    const token = req.cookies.token

    if (!token) return res.status(401).end()

    jwt.verify(token, process.env.JWT_SECRET, (err, user)=>{
        if(err) return res.status(403).end()

        req.user = user
        next()
    })
}

function notAuthenticateToken(req, res, next) {
    const token = req.cookies.token

    if (!token){
        next()
    } else{
        res.redirect('/home')
    }
}

app.listen(3000, () => {
    console.log('server started on port 3000')
})