const mongoose = require('mongoose');


const connectDb= async ()=>{
    try{
        await mongoose.connect(`${process.env.MONGO_URI}/mern-auth`);
        console.log('Connected to Mongoose');
        

    }catch(err){
        console.error(err);
        process.exit(1);
    }
}

module.exports=connectDb;