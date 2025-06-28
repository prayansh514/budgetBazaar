import mongoose from 'mongoose';

export const connectDB = async () => {
    try{
        const conn = await mongoose.connect(process.env.MONGO_URI);
        console.log(conn.connection.host, 'MongoDB connected successfully');
    }
    catch(err){
        console.error('Error connecting to MongoDB:', err.message);
        process.exit(1); // Exit the process with failure
    }
}