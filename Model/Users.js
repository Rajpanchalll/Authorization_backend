const mongoose = require('mongoose')



const userSchema = new mongoose.Schema({
    name: String,
    email: {
        type: String,
        required: [true, "Your email address is required"],
        unique: true,
      },
    dob: String,
    password: String,
    role:{
        type: String,
        default: 'Visitor'
    }
})



const userModel = mongoose.model('users', userSchema);
module.exports = userModel;




