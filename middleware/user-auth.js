const jwt= require('jsonwebtoken');

const userAuth= async (req, res, next) => {
    console.log("Authenticating user...");
    const { token }= req.cookies;
    
    if(!token){
        return res.status(401).json({
            success: false,
            message: 'Not authorized, please login!'});
    }
    try{
        const tokenDecode= jwt.verify(token,process.env.JWT_SECRET );
        if(tokenDecode.id){
            req.body.userId= tokenDecode.id;
            console.log("Authenticated user ID:", req.body.userId);
        }
        else{
            return res.status(403).json({
                success: false,
                message: 'Token expired, please login again!'});
        }
        next();


    }
    catch(err){
        console.error("Authentication error:", err);
        return res.status(500).json({
            success: false,
            message: 'Server error, please try again!'});
    }
}


module.exports= userAuth;