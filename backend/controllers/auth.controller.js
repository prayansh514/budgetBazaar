import User from '../models/user.model.js';
import jwt from 'jsonwebtoken';
import {redis} from '../lib/redis.js'; 

const generateTokens = (userId) => {
    const accessToken = jwt.sign({ userId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' }); 
    const refreshToken = jwt.sign({ userId }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

    return { accessToken, refreshToken };
}

const setCookies = (res, accessToken, refreshToken) => {
    res.cookie('accessToken', accessToken, {
        httpOnly: true, //preveent XSS attack
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
        sameSite: "strict", // Helps prevent CSRF attacks cross-site request forgery
        maxAge: 15 * 60 * 1000 // 15 minutes
    });

    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
}

const storeRefreshToken = async (userId, refreshToken) => {
    try {
        await redis.set(`refresh_token:${userId}`, refreshToken, 'EX', 60 * 60 * 24 * 7); // Store for 7 days
    } catch (error) {
        console.error('Error storing refresh token:', error);
    }
};
export const signup = async (req,res)=>{
    const {email,password,name} = req.body;
    try{
        const userExists = await User.findOne({ email });
        if(userExists) {
            return res.status(400).json({ message: 'User already exists' });
        }
        const user = await User.create({
            name,
            email,
            password
        });

        //authenticate user
        const {accessToken,refreshToken} = generateTokens(user._id);//this is how mongo stores the id  we are trying to make accesstoken accessible for 15 mins and refreshtoken for 7 days
        await storeRefreshToken(user._id, refreshToken); // Store the refresh token in Redis

        setCookies(res, accessToken, refreshToken); 

        res.status(201).json({
            user:{
                _id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            },
            message: 'User created successfully'
        });

    }
    catch(err){
        console.error('Error during signup:', err);
        res.status(500).json({message:err.message});
    }
};

export const login = async (req,res)=>{
    try{
        const {email,password} = req.body;
        const user = await User.findOne({ email });
        if(user  && await user.comparePassword(password)) {
            const {accessToken,refreshToken} = generateTokens(user._id);
            await storeRefreshToken(user._id, refreshToken); 
            setCookies(res, accessToken, refreshToken);
            res.json({
                user: {
                    _id: user._id,
                    name: user.name,
                    email: user.email,
                    role: user.role
                },
                message: 'Login successful'
            });
        }
        else{
            return res.status(401).json({ message: 'Invalid email or password' });
        }
    }
    catch(err){
        console.error('Error during login:', err);
        res.status(500).json({message: err.message});
    }
    
};


export const logout = async (req,res)=>{
   try{
        const refreshToken = req.cookies.refreshToken; // Get the refresh token from cookies
        if (refreshToken) {
            const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
            await redis.del(`refreshToken:${decoded.userId}`); // Remove the refresh token from Redis
        }
        res.clearCookie('accessToken'); 
        res.clearCookie('refreshToken');
        res.json({ message: 'Logged out successfully' }); 
   }
   catch(err){
        console.error('Error during logout:', err);
        res.status(500).json({message: err.message});
    }
    
};

export const refreshToken = async (req, res) => {
	try {
		const refreshToken = req.cookies.refreshToken;

		if (!refreshToken) {
			return res.status(401).json({ message: "No refresh token provided" });
		}

		const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
		const storedToken = await redis.get(`refresh_token:${decoded.userId}`);


		if (storedToken !== refreshToken) {
			return res.status(401).json({ message: "Invalid refresh token" });
		}

		const accessToken = jwt.sign({ userId: decoded.userId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });

		res.cookie("accessToken", accessToken, {
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			sameSite: "strict",
			maxAge: 15 * 60 * 1000,
		});

		res.json({ message: "Token refreshed successfully" });
	} catch (error) {
		console.log("Error in refreshToken controller", error.message);
		res.status(500).json({ message: "Server error", error: error.message });
	}
};

export const getProfile = async (req, res) => {
	try {
		res.json(req.user);
	} catch (error) {
		res.status(500).json({ message: "Server error", error: error.message });
	}
};




