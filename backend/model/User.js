import mongoose from "mongoose";
import bcrypt from 'bcrypt'

const UserSchema = new mongoose.Schema({
    username : {type: String, required: true, unique: true},
    password : {type: String, required:true}
}, {timestamps:true});

UserSchema.pre('save',async function (next) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next()  
})

export default mongoose.model('User', UserSchema);