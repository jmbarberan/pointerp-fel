const express = require('express');
const morgan = require('morgan');
const config = require('./config');
const bodyParser = require('body-parser');
require('dotenv').config()

const app = express();

app.set('port', process.env.PORT || config.server.port);
app.set('json spaces', config.jsonSpaces);
app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())

app.use(require('./routes/index'));

app.listen(app.get('port'), () => {
    console.log(`Escuchando peticiones en el puerto ${app.get('port')}`);
});