const mongoose = require('mongoose'); 

const dbConnect = async()=>{
    try{
    await mongoose.connect(process.env.MONGO_URI);
    console.log("Connected to MongoDB");    
    }
    catch(err){
        console.log(err.message);
        process.exit(1);
    }
    };

module.exports =dbConnect;


