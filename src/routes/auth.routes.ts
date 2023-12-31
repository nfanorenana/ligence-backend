import { Request, Response, Router } from "express";
import { body, validationResult } from 'express-validator';
import { User } from "../models/user";
import bcrypt from "bcrypt";

const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config();

const router = Router();
const saltRounds = 10;
const secretKey = process.env.TOKEN_SECRET;
let users: User[] = []

const validationRules = [
    body('login').notEmpty().withMessage('Login is required'),
    body('login').isString().withMessage('Login must be a string'),
    body('password').notEmpty().withMessage('Password is required'),
    body('password').isString().withMessage('Password must be a string'),
]


const extractToken = (bearerHeader: string | undefined): string => {
    let token = '';
    if (typeof bearerHeader !== 'undefined') {
        const bearer = bearerHeader.split(' ');
        token = bearer[1];
    }
    return token;
}

const extractUserFromToken = (token: string): User => {
    const decoded = jwt.verify(token, secretKey);
    return decoded;
}

const authenticate = (req: Request, res: Response, next: () => void) => {
    const bearerHeader = req.headers['authorization'];
    
    // if (typeof bearerHeader !== 'undefined') {
        const token = extractToken(bearerHeader)

        if (!token) {
        return res.status(401).send({ success: false, msg:'Access Denied. No token provided.'});
        }
    
        try {
            req.body.user = extractUserFromToken(token);
            next();
        } catch (error) {
            return res.status(400).send({ success: false, msg:'Invalid Token.'});
        }
    // }
    
};



router.post('/signup', validationRules, (req: Request, res: Response) => {
    const errors = validationResult(req);

    if(!errors.isEmpty()){
        return res.status(400).json({ success: false, msg: errors.array() })
    }

    const check = users.find((user) => user.login === req.body.login);

    if (!check) {
        const hash = bcrypt.hashSync(req.body.password, saltRounds);
        const user: User = {
            userId: users.length + 1,
            login: req.body.login,
            password: hash
        };
    
        users.push(user);
    
        res.status(201).json({ success: true, msg: 'User registered' })
    } else {
        res.status(400).json({ success: false, msg: 'login already used' })
    }
});

router.post('/login', validationRules, (req: Request, res: Response) => {
    const errors = validationResult(req);

    if(!errors.isEmpty()){
        return res.status(400).json({ success: false, msg: errors.array() })
    }
    
    const check = users.find((user) => user.login === req.body.login);
    if (check) {
        bcrypt.compare(req.body.password, check.password, function(err, user) {
            if (user) {
                const accessToken = jwt.sign({ userId:check.userId, login:check.login }, secretKey, {
                    expiresIn: '1h'
                })
                const refreshToken = jwt.sign({ userId:check.userId, login:check.login }, secretKey, {
                    expiresIn: '10h'
                })
                res.status(200).json({ success: true, token: accessToken, refreshToken: refreshToken })
            } else {
                res.status(403).json({ success: false, msg: 'Password doesn\'t match' })
            }
          });
    
    } else {
        res.status(403).json({ success: false, msg: 'No user with your login is not found' })
    }
});

router.post('/refresh', authenticate, (req: Request, res: Response) => {
    try {
        const decoded = jwt.verify(req.body.refreshToken, secretKey);
        const accessToken = jwt.sign({ userId: decoded.userId, login: decoded.login }, secretKey, { expiresIn: '1h' });
    
        res.status(200).json({ success: true, token: accessToken })
    } catch (error) {
        res.status(403).json({ success: false, msg: 'Refresh token invalid or expired' })
    }
});

router.get('/users', authenticate, (req: Request, res: Response) => {
    res.status(200).json({ success: true, users: users })
});

router.get('/recommendations', authenticate, (req: Request, res: Response) => {
    const token = extractToken(req.headers['authorization']);
    const userLogged = extractUserFromToken(token);
    
    let recommendations = [];

    const userArray = [...userLogged.login];

    for(const user of users.filter(item => item.login != userLogged.login)) {
        let tmp = [...user.login];
        let intersection = userArray.filter(x => tmp.includes(x));
        let union = [...new Set([...userArray, ...tmp])];

        // console.log(user.login);
        // console.log(intersection.length/union.length);
        // console.log('==============================');
        

        recommendations.push({login: user.login, similarity: intersection.length/union.length})
    }

    recommendations.sort((a, b) => b.similarity - a.similarity);

    res.status(200).json({success: true, recommendations: recommendations.map(item => item.login)})
});


export default router;


