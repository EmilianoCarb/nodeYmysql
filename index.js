import express from 'express';
const app = express();
import cors from 'cors';
import 'dotenv/config';
import router from './routes/router.js';

const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cors());
app.use('/api', router);

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));