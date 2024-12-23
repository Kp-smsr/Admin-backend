const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const userRoutes = require('./src/routes/userRoutes');

const app = express();
const PORT = 5000;

app.use(cors());
app.use(bodyParser.json());

app.use('/api/users', userRoutes);

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
