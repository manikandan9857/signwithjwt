const express = require('express')
const path  = require('path')
const bodyParser = require('body-parser')
const mongoose = require('mongoose')
const User = require('./model/user')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const JWT_SECRET = 'secret5798@'

mongoose.connect('mongodb://localhost:27017/login-app-db', {

    useNewUrlParser:true,
    useUnifiedTopology: true,
    useCreateIndex: true
})
const app =express()
app.use('/',express.static(path.join(__dirname,'static')))
app.use(bodyParser.json())

app.post('/api/login',async (req,res) => {

    const { username, password } = req.body

    const user = await User.findOne({username}).lean()

    if(!user) {
        return res.json({ status:'error',error: 'Invalid Username and Password'})
    }

    if(await bcrypt.compare(password, user.password)) {
        //username & password combination is successfull

        const token = jwt.sign(
            { 
             id: user._id,
             username: user.username
            },
            JWT_SECRET
        )
        
        jwt.verify(token, JWT_SECRET)
        console.log(token)
        return res.json({status: 'ok', data : token })
        
         

    }

    res.json({status: 'error', error : 'Invalid Username and Password'})
   
})

app.post('/api/register',async (req,res) =>{

    //hashing the password
    const { username, password: plainTextPassword, mobile } = req.body

   if(!username || typeof username !== 'string' ){
        return res.json({status : 'error', error: 'Invalid EmailId'})
    }
    if(!plainTextPassword || typeof plainTextPassword !== 'string' ){
        return res.json({status : 'error', error: 'Invalid password'})
    }
    if(plainTextPassword.length<5){
        return res.json({
            status:'error',
            error: 'Password is too small.Should be atleast 6 characters'
        })
    }

    const password = await bcrypt.hash(plainTextPassword, 10)

    try{

        const response = await User.create({
            username,
            password,
            mobile
        })
        console.log('User Created Successfully:', response)

    }catch(error){
        if(error.code === 11000){

            return res.json({ status :'error', error: 'Email ID Already in Use'})
        }
        
        throw error
    }
    res.json({status: 'ok'})
})


app.listen(7000,()=> {

    console.log('Server started at port 7000')

}) 
