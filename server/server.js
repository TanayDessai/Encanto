import express from "express";
import mongoose from "mongoose";
import 'dotenv/config';
import bcrypt from "bcrypt";
import User from "./Schema/User.js";
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";
import cors from "cors";
import admin from "firebase-admin";
import { getAuth } from "firebase-admin/auth";
import serviceAccountKey from "./blogs-website-app-firebase-adminsdk-wxl71-77d63fd143.json" assert{type:"json"};

const server = express();

let PORT = 3000;

admin.initializeApp({
    credential: admin.credential.cert(serviceAccountKey)
})

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

server.use(express.json());
server.use(cors());

mongoose.connect(process.env.DB_LOCATION, {
    autoIndex:true
});

const formatDatatoSend = (user) => {
    const access_token = jwt.sign(
      { id: user._id },
      process.env.SECRET_ACCESS_KEY
    );
    return {
        access_token,
        profile_img: user.personal_info.profile_img,
        username: user.personal_info.username,
        fullname: user.personal_info.fullname,
    }
}

const generateUsername = async(email) => {
    let username = email.split("@")[0];
    let isUsernameNotUnique = await User.exists({"personal_info.username":username}).then((result) => result);
    isUsernameNotUnique ? username += nanoid().substring(0,5) : "";

    return username;
}

server.post("/signup", (req, res) => {
    let {fullname,email,password} = req.body;

    //validate the data
    if(fullname.length < 3){
        return res.status(403).json({"error":"fullname must be at least 3 characters long"})
    }
    if(!email.length){
        return res.status(403).json({"error":"email is required"})
    }
    if(!emailRegex.test(email)){
        return res.status(403).json({"error":"email is invalid"})
    }
    if(!passwordRegex.test(password)){
        return res.status(403).json({"error":"password must be at least 6 characters long and contain at least one uppercase letter and one number"})
    }

    bcrypt.hash(password, 10,async(err,hash_password)=>{
        let username = await generateUsername(email);

        let user = new User({
            personal_info:{
                fullname,
                email,
                username,
               password: hash_password
            },
        })
        user.save().then((u)=>{
            return res.status(200).json(formatDatatoSend(u))
        }).catch(err=>{
            if(err.code == 11000){
                return res.status(500).json({"error":"email already exists"})
            }
            return res.status(500).json({"error":err.message})
        })
    })
})

server.post("/signin", (req, res) => {
    let {email,password} = req.body;

    //validate the data
    if(!email.length){
        return res.status(403).json({"error":"email is required"})
    }
    if(!emailRegex.test(email)){
        return res.status(403).json({"error":"email is invalid"})
    }
    if(!password.length){
        return res.status(403).json({"error":"password is required"})
    }

    User.findOne({"personal_info.email":email}).then((user)=>{
        if(!user){
            return res.status(403).json({"error":"Email does not exist"})
        }
        if(!user.google_auth){
            bcrypt.compare(
              password,
              user.personal_info.password,
              (err, result) => {
                if (err) {
                  return res
                    .status(403)
                    .json({
                      error: "Error occured while login please try again",
                    });
                }

                if (!result) {
                  return res.status(403).json({ error: "Incorrect password" });
                } else {
                  return res.status(200).json(formatDatatoSend(user));
                }
              }
            );
        }
        else{
            return res.status(403).json({"error":"This email was signed in up with google. Please log in with google to access the account"})
        }

    }).catch(err=>{
        return res.status(500).json({"error":err.message})
    })
})

server.post("/google-auth",async(req,res)=>{
    let {access_token} = req.body;

    getAuth()
    .verifyIdToken(access_token)
    .then(async(decodedUser)=>{
        let {email,name,picture} = decodedUser;
        picture = picture.replace("s96-c","s384-c");
        
        let user = await User.findOne({ "personal_info.email": email }).select(
          "personal_info.fullname personal_info.username personal_info.profile_img personal_info.google_auth"
        ).then((u)=>{
            return u || null;
        })
        .catch(err=>{
            return res.status(500).json({"error":err.message});
        })

        if(user){
            if(!user.google_auth){
                return res.status(403).json({"error":"This email was signed in up whithout google. Please log in with password to access the account"})
            }
        }
        else{
            let username = await generateUsername(email);
            user = new User({
                personal_info:{
                    fullname: name,
                    email,
                    username,
                },
                google_auth: true
            })
            await user.save().then((u)=>{
                user = u;
            }).catch(err=>{
                return res.status(500).json({"error":err.message})
            })
        }
        return res.status(200).json(formatDatatoSend(user))
    })
    .catch(err=>{
        return res.status(500).json({"error":"Failed to authenticate with google. Please try again with a different account"})
    })
})

server.listen(PORT, () => {console.log(`listening on port ->`+PORT)})