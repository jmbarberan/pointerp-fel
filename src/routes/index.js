const { Router } = require('express');

const config = require('../config');
const { dbsubscripciones } = config;

const firmarComprobante = require('../firmaXades'); 
//const { firmarComprobante } = firmaXades;

const pg = require('pg');
const { Client } = pg;

const router = Router();

const requireJsonContent = (request, response, next) => {
    /*if (request.headers['content-type'] !== 'application/json') {
        response.status(400).send('Server requires application/json')
    } else {
        next()
    }*/
    next();
}

router.get('/saludar', (req, res) => {
    res.json({
        "Saludo": "Hola estimado"
    })
});

router.post('/firmar-comprobante', (req, res) => {
    let respuesta = {
        "resultado" : "false",
        "mensaje": "No se pudo ejecutar el proceso",
        "datos": ""
    }
    try {
        const dbClient = new Client(dbsubscripciones);
        let sql = `Select certificado_file, certificado_pass from ${config.dbsubscripciones_schema}.empresas ` +
            `where subscripcion_id = ${req.body.subscripcion} and empresa_id = ${req.body.empresa}`;

        dbClient.connect().then(() => {
            dbClient.query(sql).then(response => {
                let certArchivo = "";
                let certPass = "";
                let valido = false;
                respuesta.mensaje = "Conteo " + response.rows.length;
                if (response.rows.length > 0) {
                    let fila = response.rows[0]
                    certArchivo = fila.certificado_file
                    let b64Pass = fila.certificado_pass
                    let buff = new Buffer.from(b64Pass, 'base64');
                    certPass = buff.toString('ascii');
                    respuesta.mensaje = `Archivo: ${certArchivo}, Clave: ${certPass}`
                    res.statusCode = 200
                    valido = true;
                } else {
                    res.statusCode = 404;
                    respuesta.mensaje = "No se encontro la empresa"
                }
                if (valido) {
                    let firmado = firmarComprobante(certArchivo, certPass, req.body.comprobante);
                    res.statusCode = 200;
                    respuesta.resultado = true;
                    respuesta.mensaje = "Comprobante firmado correctamente";
                    respuesta.datos = firmado;
                }
                dbClient.end();
                res.json(respuesta);
            }).catch(error => {
                respuesta.mensaje = error;
                res.statusCode = 500;
                dbClient.end();
                res.json(respuesta);
            })
        }).catch(error => {
            respuesta.mensaje = error;
            res.statusCode = 500;
            dbClient.end();
            res.json(respuesta);
        });
    } catch (error) {
        res.statusCode = 500;
        respuesta.mensaje = error;
        res.json(respuesta);
    }
}, requireJsonContent);
 
module.exports = router;