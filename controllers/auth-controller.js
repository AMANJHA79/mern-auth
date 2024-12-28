const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/user-model');

const transporter = require('../config/nodemailer');



//-------registration--
const register = async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({
            success: false,
            msg: 'Please fill all fields'
        });
    }
    try {
        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(200).json({
                success: false,
                message: `${name} is already registered `
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            name,
            email,
            password: hashedPassword
        });

        await newUser.save();

        const token = jwt.sign(
            {
                id: newUser._id
            }, process.env.JWT_SECRET, {
                expiresIn: '7d'
            }
        );

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        // Sending welcome email using Brevo
        const mailOptions = {
            from: `AUTH project by Aman <${process.env.SENDER_EMAIL}>`,
            to: email,
            subject: 'Welcome to MERN Auth project',
            text: `Hello, welcome to MERN Auth project! Thank you for registering with your email id: ${email}`
        };

        console.log('Sending email to:', email); // Log the email being sent

        await transporter.sendMail(mailOptions);
        console.log('Email sent successfully'); // Log success

        return res.json({
            success: true
        });

    } catch (err) {
        console.error('Error during registration:', err); // Log the error
        return res.status(500).json({
            success: false,
            message: err.message
        });
    }
}

//---login

const login = async (req,res)=>{
    const {email, password}=req.body;

    if(!email || !password){
        return res.status(400).json({
            success: false,
            message:'email or password is required'});
    }
    try{

        const user= await User.findOne({email});
        if(!user){
            return res.status(400).json({
                success: false,
                message: 'Invalid email'
            })
        }


        const isMatch = await bcrypt.compare(password, user.password);


        if(!isMatch){
            return res.status(400).json({
                success: false,
                message: 'Incorrect password'
            })
        }

        const token= jwt.sign(
            {
                id: user._id
            },process.env.JWT_SECRET,{
                expiresIn: '7d'
            }
        )

        res.cookie('token', token ,{
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ?'none': 'strict',
            maxAge: 7*24*60*60*1000
        });

        return res.json({
            success: true
        })

    }
    catch(err){
        return res.status(500).json({
            success: false,
            message: 'Server error'
        })
    }
}


//--logout

const logout = async (req, res) => {
    try{
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ?'none': 'strict',
        })

        return res.json({
            success: true,
            message: 'Logged out successfully'
        })
        

    }
    catch(err){
        return res.status(500).json({
            success: false,
            message: err.message
        })
    }
}

//---send otp-------------
const sendVerifyOtp= async (req, res) => {
    try{
        const { userId } = req.body;

        const user = await User.findById(userId);

        if(user.isAccountVerified){
            return res.status(400).json({
                success: false,
                message: 'Account already verified'
            })
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 24 * 60 *60* 1000; // 1 day 


        await user.save();

        const mailOption = {
            from: `MERN AUTH <${process.env.SENDER_EMAIL}>`,
            to: user.email,
            subject: 'Verify Your Account – Your OTP is Here!',
            text: `Hello ${user.name},

            Thank you for signing up with AUTH project by Aman! To complete your account setup, please use the One-Time Password (OTP) provided below:

            **Your OTP:** ${otp}

            This OTP is valid for 24 hrs. Please ensure you verify your account within this time frame.

            If you didn’t request this, please ignore this email or contact our support team immediately.

            Best regards,  
            The AUTH project by Aman `
        };

        // Sending the email
        await transporter.sendMail(mailOption);

        res.json({
            success: true,
            message: 'OTP sent successfully'
        })

    }
    catch(err){
        return res.status(500).json({
            success: false,
            message: err.message
        })
    }
}



//---verification otp
const verifyEmail= async (req,res)=>{

        const { userId , otp }=req.body;
        if(!userId || !otp){
            return res.status(400).json({
                success: false,
                message: 'userId and otp are required'
            })
        }
    try{
        const user= await User.findById(userId);
        if(!user){
            return res.status(400).json({
                success: false,
                message: 'Invalid userId'
            })
        }
        if(user.verifyOtp=== '' || user.verifyOtp !==otp){
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP'
            })

        }
        if(user.verifyOtpExpireAt < Date.now()){
            return res.status(400).json({
                success: false,
                message: 'OTP expired'
            })
        }

        user.isAccountVerified=true;
        user.verifyOtp='';
        user.verifyOtpExpireAt=0;

        await user.save();

        return res.json({
            success: true,
            message: 'Account verified successfully'
        })

    }
    catch(err){
        return res.status(500).json({
            success: false,
            message: err.message
        })
    }
}



//---is authenticated........

const isAuthenticated = async (req, res) => {
    try {
        return res.json({
            success: true
        });
    } catch (err) {
        return res.status(500).json({
            success: false,
            message: err.message
        });
    }
}

//send password reset otp

const sendResetOtp = async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.json({
            success: false,
            message: 'email is required'
        });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.json({
                success: false,
                message: 'User not found'
            });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000; // 15 minutes
        await user.save();

        const mailOption = {
            from: `MERN AUTH <${process.env.SENDER_EMAIL}>`,
            to: user.email,
            subject: 'Reset Password – Your OTP is Here!',
            text: `Hello ${user.name},

        We received a request to reset your account password. Please use the One-Time Password (OTP) below to proceed with the reset:

        **Your OTP:** ${otp}

        This OTP is valid for 15 minutes. For your account's security, do not share this OTP with anyone.

        If you did not request a password reset, please disregard this email or contact our support team immediately.

        Best regards,  
        The MERN AUTH Team`
        };

        // Sending the email
        await transporter.sendMail(mailOption);

        res.json({
            success: true,
            message: 'OTP sent successfully'
        });

    } catch (err) {
        return res.status(500).json({
            success: false,
            message: err.message
        });
    }
}

//reset password 

const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;
    if (!email ||!otp ||!newPassword) {
        return res.json({
            success: false,
            message: 'email, otp, and newPassword are required'
        });
    }
    try{

        const user=await User.findOne({email});
        if(!user){
            return res.json({
                success: false,
                message: 'User not found'
            })
        }
        if(user.password === newPassword){
            return res.json({
                success: false,
                message: 'New password cannot be same as old password'
            })
        }


        if(user.resetOtp === '' || user.resetOtp!==otp){
            return res.json({
                success: false,
                message: 'Invalid OTP'
            })
        }
        if(user.resetOtpExpireAt < Date.now()){
            return res.json({
                success: false,
                message: 'OTP expired'
            })
        }
        const hashedPassword = await bcrypt.hash(newPassword,10);
        user.password=hashedPassword;
        user.resetOtp='';
        user.resetOtpExpireAt=0;

        await user.save();
        return res.json({
            success: true,
            message: 'Password reset successfully'
        })

        

    }
    catch(err){
        return res.json({
            success: false,
            message: err.message
        })
    }
}





module.exports={
    register,
    login,
    logout,
    sendVerifyOtp,
    verifyEmail,
    isAuthenticated,
    sendResetOtp,
    resetPassword
}