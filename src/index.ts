import express, { NextFunction, Request, Response } from 'express';
import authRoutes from './routes/auth.routes';

const dotenv = require('dotenv');

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use('/auth', authRoutes);


app.use((err: Error, req: Request, res: Response, naxt: NextFunction) => {
    console.error(err.stack);
    res.status(500).send('Something went wrong');
})

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});

