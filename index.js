require('dotenv').config()

const express = require('express')
const cors = require('cors')
const mongoose = require('mongoose')
const port = process.env.PORT || 3001;
const userModel = require('./Model/Users')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const ORIGIN_URL = process.env.ORIGIN_URL


const app = express()
app.use(express.json())
app.use(cookieParser())




app.use(cors({ 
    origin: [`${ORIGIN_URL}`],
    methods: ["GET", "POST"],
    credentials: true
}
));






mongoose.connect(process.env.MONGODB_URL)
    .then(() => console.log('MongoDB is Connected!!'))
    .catch((error) => console.log(error))








const  varifinguser = (req, res, next) =>{
    const token = req.cookies.token;
    if(!token)
    {
        return res.json('Token is missing!')
    }
    else{
        jwt.verify(token, 'jwt-secret-key', (err, decoded) =>{
            if(err){
                return res.json('err is there')
            }
            else{
                if(decoded.role === 'admin'){
                    next()
                }else{
                    return res.json('Not admin')
                }
            }
        })
    }
}


app.get('/table', varifinguser,(req, res) => {
   res.json('Success!')
})
app.get('/', (req, res) => {
    res.send('Hello Nodejs')
})



app.post('/register', (req, res) => {
    const { name, email, dob, password } = req.body
    bcrypt.hash(password, 10)
        .then((hash) => {
            userModel.create({
                name,
                email,
                dob,
                password: hash
            })
                .then(user => res.json({ status: 'OK ' }))
                .catch(err => res.json(err))

        })
        .catch(err => console.log(err))
})


app.post('/login', (req, res) => {
    const { email, password } = req.body;
    userModel.findOne({ email: email })
        .then(user => {
            if (user) {
                bcrypt.compare(password, user.password, (err, response) => {
                    if (response) {
                        const token = jwt.sign({ email: user.email, role: user.role }, "jwt-secret-key", { expiresIn: '1d' });
                        res.cookie("token", token, {
                            withCredentials: true,
                            httpOnly: false,
                        });
                        res.json({ status: 'success', role: user.role });
                        console.log('Logged in successfully!')
                    } else {
                        res.redirect('/signup');
                      
                        console.log('Password is not matching!!');
                          
                    }
                });
            } else {
                res.send('No Record is Found!');
            }
        })
        .catch(err => {
            res.send('Internal Server Error', err);
        });

})





app.listen(port, () => {
    console.log(`The server is working on the port ${port}`)
})