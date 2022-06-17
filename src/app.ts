
import express, { Express, Request, Response } from 'express';
import dotenv from 'dotenv';
import { fingerprint } from './features/fingerprint';
import cors from 'cors';
import { authFingerprint } from './middleware/auth.fingerprint';

dotenv.config();

const app: Express = express();

app.use(cors());
app.use(express.json());

const port = process.env.PORT;

app.get('/', (req: Request, res: Response) => {
  res.send('Hello World');
});

app.use(authFingerprint).use('/fingerprint', fingerprint);

app.listen(port, () => {
  console.log(`⚡️[server]: Server is running at https://localhost:${port}`);
});
