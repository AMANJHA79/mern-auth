const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
dotenv.config();
const cookieParser = require('cookie-parser');
const connectDb = require('./config/mongodb');

const authRouter = require('./routes/auth-routes');
const userRouter = require('./routes/user-routes');


const app = express();




const port = process.env.PORT || 4000;
connectDb();

app.use(express.json());
app.use(cookieParser());
app.use(cors({credentials: true}));


//api endpoint
app.get('/', (req, res) =>{
    res.send('Hello from the server!');
})
app.use('/api/auth',authRouter);
app.use('/api/user',userRouter);





app.listen(port, () => console.log(`Server running on port ${port}`));


