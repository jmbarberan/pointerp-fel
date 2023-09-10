const fs = require('fs');
const path = require('path');
const moment = require ('moment');
const forge = require('node-forge');
const { util, asn1, pkcs12, pki, oids, md } = forge;

const firmarComprobante = function(certFile, certPass, comprobante) {
    
    certContenido = fs.readFileSync(path.resolve(__dirname, `../certs/${certFile}`));
    
    var arrayUint8 = new Uint8Array(certContenido);
    var p12B64 = util.binary.base64.encode(arrayUint8);
    var p12Der = util.decode64(p12B64);
    var p12Asn1 = asn1.fromDer(p12Der);

    var p12 = pkcs12.pkcs12FromAsn1(p12Asn1, certPass);

    var certBags = p12.getBags({bagType:pki.oids.certBag})
    var cert = certBags[oids.certBag][0].cert;
    var pkcs8bags = p12.getBags({bagType:pki.oids.pkcs8ShroudedKeyBag});
    var pkcs8 = pkcs8bags[oids.pkcs8ShroudedKeyBag][0];
    var key = pkcs8.key;

    if( key == null ) {
        key = pkcs8.asn1;
    }

    certificateX509_pem = pki.certificateToPem(cert);

    certificateX509 = certificateX509_pem;
    certificateX509 = certificateX509.substring( certificateX509.indexOf('\n') );
    certificateX509 = certificateX509.substring(0, certificateX509.indexOf('\n-----END CERTIFICATE-----') );

    certificateX509 = certificateX509.replace(/\r?\n|\r/g, '').replace(/([^\0]{76})/g, '$1\n');

    //Pasar certificado a formato DER y sacar su hash:
    certificateX509_asn1 = pki.certificateToAsn1(cert);
    certificateX509_der = asn1.toDer(certificateX509_asn1).getBytes();
    certificateX509_der_hash = sha1_base64(certificateX509_der);

    //Serial Number
    var X509SerialNumber = parseInt(cert.serialNumber, 16);

    exponent = hexToBase64(key.e.data[0].toString(16));            
    modulus = bigint2base64(key.n);

    var issuerName = cert.issuer.attributes[4].shortName + '=' + cert.issuer.attributes[4].value + ', ' +
              cert.issuer.attributes[3].shortName + '=' +cert.issuer.attributes[3].value + ', ' +
              cert.issuer.attributes[2].shortName + '=' +cert.issuer.attributes[2].value + ', ' +
              cert.issuer.attributes[1].shortName + '=' +cert.issuer.attributes[1].value + ', '

    var sha1_comprobante = sha1_base64(comprobante.replace('<?xml version="1.0" encoding="UTF-8"?>', ''));

    var xmlns = `xmlns:ds='http://www.w3.org/2000/09/xmldsig#' xmlns:etsi='http://uri.etsi.org/01903/v1.3.2#'`;

    //numeros involucrados en los hash:
    var Certificate_number = p_obtener_aleatorio();
    var Signature_number = p_obtener_aleatorio();
    var SignedProperties_number = p_obtener_aleatorio();

    //numeros fuera de los hash:
    var SignedInfo_number = p_obtener_aleatorio();
    var SignedPropertiesID_number = p_obtener_aleatorio();
    var Reference_ID_number = p_obtener_aleatorio();
    var SignatureValue_number = p_obtener_aleatorio();
    var Object_number = p_obtener_aleatorio();

    var SignedProperties = '';

    SignedProperties += `<etsi:SignedProperties Id='Signature${Signature_number}-SignedProperties${SignedProperties_number}'>`
        SignedProperties += '<etsi:SignedSignatureProperties>';
            SignedProperties += '<etsi:SigningTime>';

                //SignedProperties += '2016-12-24T13:46:43-05:00';//moment().format('YYYY-MM-DD\THH:mm:ssZ');
                SignedProperties += moment().format('YYYY-MM-DD\THH:mm:ssZ');

            SignedProperties += '</etsi:SigningTime>';
            SignedProperties += '<etsi:SigningCertificate>';
                SignedProperties += '<etsi:Cert>';
                    SignedProperties += '<etsi:CertDigest>';
                        SignedProperties += `<ds:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1'>`;
                        SignedProperties += '</ds:DigestMethod>';
                        SignedProperties += '<ds:DigestValue>';

                            SignedProperties += certificateX509_der_hash;

                        SignedProperties += '</ds:DigestValue>';
                    SignedProperties += '</etsi:CertDigest>';
                    SignedProperties += '<etsi:IssuerSerial>';
                        SignedProperties += '<ds:X509IssuerName>';
                            SignedProperties += issuerName;
                        SignedProperties += '</ds:X509IssuerName>';
                    SignedProperties += '<ds:X509SerialNumber>';

                        SignedProperties += X509SerialNumber;

                    SignedProperties += '</ds:X509SerialNumber>';
                    SignedProperties += '</etsi:IssuerSerial>';
                SignedProperties += '</etsi:Cert>';
            SignedProperties += '</etsi:SigningCertificate>';
        SignedProperties += '</etsi:SignedSignatureProperties>';
        SignedProperties += '<etsi:SignedDataObjectProperties>';
            SignedProperties += `<etsi:DataObjectFormat ObjectReference='#Reference-ID-${Reference_ID_number}'>`;
                SignedProperties += '<etsi:Description>';

                    SignedProperties += 'contenido comprobante';                        

                SignedProperties += '</etsi:Description>';
                SignedProperties += '<etsi:MimeType>';
                    SignedProperties += 'text/xml';
                SignedProperties += '</etsi:MimeType>';
            SignedProperties += '</etsi:DataObjectFormat>';
        SignedProperties += '</etsi:SignedDataObjectProperties>';
    SignedProperties += '</etsi:SignedProperties>'; //fin SignedProperties

    SignedProperties_para_hash = SignedProperties.replace('<etsi:SignedProperties', '<etsi:SignedProperties ' + xmlns);

    var sha1_SignedProperties = sha1_base64(SignedProperties_para_hash);        


    var KeyInfo = '';

    KeyInfo += `<ds:KeyInfo Id='Certificate${Certificate_number}'>`;
        KeyInfo += '<ds:X509Data>';
            KeyInfo += '<ds:X509Certificate>';

                //CERTIFICADO X509 CODIFICADO EN Base64 
                KeyInfo += certificateX509;

            KeyInfo += '</ds:X509Certificate>';
        KeyInfo += '</ds:X509Data>';
        KeyInfo += '<ds:KeyValue>';
            KeyInfo += '<ds:RSAKeyValue>';
                KeyInfo += '<ds:Modulus>';

                    //MODULO DEL CERTIFICADO X509
                    KeyInfo += modulus;

                KeyInfo += '</ds:Modulus>';
                KeyInfo += '<ds:Exponent>';

                    //KeyInfo += 'AQAB';
                    KeyInfo += exponent;

                KeyInfo += '</ds:Exponent>';
            KeyInfo += '</ds:RSAKeyValue>';
        KeyInfo += '</ds:KeyValue>';
    KeyInfo += '</ds:KeyInfo>';

    KeyInfo_para_hash = KeyInfo.replace('<ds:KeyInfo', '<ds:KeyInfo ' + xmlns);

    var sha1_certificado = sha1_base64(KeyInfo_para_hash);


    var SignedInfo = '';

    SignedInfo += `<ds:SignedInfo Id='Signature-SignedInfo${SignedInfo_number}'>`;
        SignedInfo += `<ds:CanonicalizationMethod Algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315'>`;
        SignedInfo += '</ds:CanonicalizationMethod>';
        SignedInfo += `<ds:SignatureMethod Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1'>`;
        SignedInfo += '</ds:SignatureMethod>';
        SignedInfo += `<ds:Reference Id='SignedPropertiesID${SignedPropertiesID_number}' Type='http://uri.etsi.org/01903#SignedProperties' URI='#Signature${Signature_number}-SignedProperties${SignedProperties_number}'>`;
            SignedInfo += `<ds:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1'>`;
            SignedInfo += '</ds:DigestMethod>';
            SignedInfo += '<ds:DigestValue>';

                //HASH O DIGEST DEL ELEMENTO <etsi:SignedProperties>';
                SignedInfo += sha1_SignedProperties;

            SignedInfo += '</ds:DigestValue>';
        SignedInfo += '</ds:Reference>';
        SignedInfo += `<ds:Reference URI='#Certificate${Certificate_number}'>`;
            SignedInfo += `<ds:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1'>`;
            SignedInfo += '</ds:DigestMethod>';
            SignedInfo += '<ds:DigestValue>';

                //HASH O DIGEST DEL CERTIFICADO X509
                SignedInfo += sha1_certificado;

            SignedInfo += '</ds:DigestValue>';
        SignedInfo += '</ds:Reference>';
        SignedInfo += `<ds:Reference Id='Reference-ID-${Reference_ID_number}' URI='#comprobante'>`;
            SignedInfo += '<ds:Transforms>';
                SignedInfo += `<ds:Transform Algorithm='http://www.w3.org/2000/09/xmldsig#enveloped-signature'>`;
                SignedInfo += '</ds:Transform>';
            SignedInfo += '</ds:Transforms>';
            SignedInfo += `<ds:DigestMethod Algorithm='http://www.w3.org/2000/09/xmldsig#sha1'>`;
            SignedInfo += '</ds:DigestMethod>';
            SignedInfo += '<ds:DigestValue>';

                //HASH O DIGEST DE TODO EL ARCHIVO XML IDENTIFICADO POR EL id="comprobante" 
                SignedInfo += sha1_comprobante;

            SignedInfo += '</ds:DigestValue>';
        SignedInfo += '</ds:Reference>';
    SignedInfo += '</ds:SignedInfo>';

    SignedInfo_para_firma = SignedInfo.replace('<ds:SignedInfo', '<ds:SignedInfo ' + xmlns);

    var mdsha1 = md.sha1.create();
    mdsha1.update(SignedInfo_para_firma, 'utf8');

    var signature = btoa(key.sign(mdsha1)).match(/.{1,76}/g).join("");


    var xades_bes = '';

    //INICIO DE LA FIRMA DIGITAL 
    xades_bes += `<ds:Signature ${xmlns} Id='Signature${Signature_number}'>`;
        xades_bes += SignedInfo;

        xades_bes += `<ds:SignatureValue Id='SignatureValue${SignatureValue_number}'>`;

            //VALOR DE LA FIRMA (ENCRIPTADO CON LA LLAVE PRIVADA DEL CERTIFICADO DIGITAL) 
            xades_bes += signature;

        xades_bes += '</ds:SignatureValue>';

        xades_bes += KeyInfo;

        xades_bes += `<ds:Object Id='Signature${Signature_number}-Object${Object_number}'>`;
            xades_bes += `<etsi:QualifyingProperties Target='#Signature${Signature_number}'>`;

                //ELEMENTO <etsi:SignedProperties>';
                xades_bes += SignedProperties;

            xades_bes += '</etsi:QualifyingProperties>';
        xades_bes += '</ds:Object>';
    xades_bes += '</ds:Signature>';

    //FIN DE LA FIRMA DIGITAL 

    return comprobante.replace(/(<[^<]+)$/, xades_bes + '$1');
}

function sha1_base64(txt) {
    var mdsha1 = md.sha1.create();
    mdsha1.update(txt);
    return Buffer.from(mdsha1.digest().toHex(), 'hex').toString('base64')
}

function bigint2base64(bigint){
    var base64 = '';
    base64 = btoa(bigint.toString(16).match(/\w{2}/g).map(function(a){return String.fromCharCode(parseInt(a, 16));} ).join(""));
    
    base64 = base64.match(/.{1,76}/g).join("\n");
    
    return base64;
}

function p_obtener_aleatorio() {
    return Math.floor(Math.random() * 999000) + 990;    
}

function hexToBase64(str) {
    var hex = ('00' + str).slice(0 - str.length - str.length % 2);
    
    return btoa(String.fromCharCode.apply(null,
        hex.replace(/\r|\n/g, "").replace(/([\da-fA-F]{2}) ?/g, "0x$1 ").replace(/ +$/, "").split(" "))
    );
}

module.exports = firmarComprobante;