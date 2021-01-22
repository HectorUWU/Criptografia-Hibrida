/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package practica.pkg5.crypto;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;

public class CryptoHibrida {

    public byte[] cifrarYFirmar(String msg, PrivateKey clavePrivada, PublicKey clavePublica) throws Exception {
        AES aes = new AES();
        SHA1 sha1 = new SHA1();
        RSA rsa = new RSA();
        Key key = aes.generateKey();
        byte[] msgCifrado = aes.cifrar(msg, key);
        byte[] digest = sha1.getSHA1(msg);
        byte[] firma = rsa.cifrarLLavePrivada(digest, clavePrivada);
        byte[] llaveCifrada = rsa.cifrarLLavePublica(key.getEncoded(), clavePublica);
        byte[] out = new byte[msgCifrado.length + firma.length + llaveCifrada.length];
        System.arraycopy(llaveCifrada, 0, out, 0, llaveCifrada.length);
        System.arraycopy(msgCifrado, 0, out, llaveCifrada.length, msgCifrado.length);
        System.arraycopy(firma, 0, out, llaveCifrada.length + msgCifrado.length, firma.length);
        return out;
    }

    public String descifrarYverificar(byte[] msg, PrivateKey clavePrivada, PublicKey clavePublica) throws Exception {
        AES aes = new AES();
        SHA1 sha1 = new SHA1();
        RSA rsa = new RSA();
        byte[] llaveCifrada = new byte[128];
        byte[] msgCifrado = new byte[msg.length - 256];
        System.arraycopy(msg, 0, llaveCifrada, 0, 128);
        byte[] keyBytes = rsa.decifrarLLavePrivada(llaveCifrada, clavePrivada);
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        System.arraycopy(msg, 128 , msgCifrado, 0, msg.length-256);
        String mensaje = aes.descifrar(msgCifrado, key);
        byte[] digest = sha1.getSHA1(mensaje);
        String digestStr = new String(digest, StandardCharsets.UTF_8);
        byte[] firmaCifrada = new byte [128];
        System.arraycopy(msg, msg.length-128, firmaCifrada, 0, 128);
        byte[] firmaBytes = rsa.decifrarLLavePublica(firmaCifrada, clavePublica);
        String firma = new String(firmaBytes, StandardCharsets.UTF_8);
        if(firma.equals(digestStr))
            JOptionPane.showMessageDialog(null, "La firma es correcta");
        else
            JOptionPane.showMessageDialog(null, "La firma es correcta");
        return mensaje;
    }
    
    public byte[] cifrar(String msg, PublicKey clavePublica) throws Exception{
        AES aes = new AES();
        RSA rsa = new RSA();
        Key key = aes.generateKey();
        byte[] msgCifrado = aes.cifrar(msg, key);
        byte[] keyCifrada = rsa.cifrarLLavePublica(key.getEncoded(), clavePublica);
        byte[] out = new byte[msgCifrado.length + keyCifrada.length];
        System.arraycopy(msgCifrado, 0, out, 0, msgCifrado.length);
        System.arraycopy(keyCifrada, 0, out, msgCifrado.length , keyCifrada.length);
        return out;
    }
    
    public String descifrar(byte[] msg, PrivateKey clavePrivada) throws Exception{
        AES aes = new AES();
        RSA rsa = new RSA();
        byte[] msgCifrado = new byte[msg.length-128];
        System.arraycopy(msg, 0, msgCifrado, 0, msg.length-128);
        byte[] keyCifrada = new byte[128];
        System.arraycopy(msg, msg.length-128,keyCifrada, 0, 128);
        byte[] keyBytes = rsa.decifrarLLavePrivada(keyCifrada, clavePrivada);
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        String mensaje = aes.descifrar(msgCifrado, key);
        return mensaje;
    }
    
    public byte [] firmar(String message, PrivateKey clavePrivada){
        RSA rsa = new RSA();
        SHA1 sha1 = new SHA1();
        byte[] rsaIn, firma, messageByte;
        rsaIn = sha1.getSHA1(message);
        firma = rsa.cifrarLLavePrivada(rsaIn, clavePrivada);
        messageByte = message.getBytes();
        byte [] out = new byte[messageByte.length + firma.length];
        System.arraycopy(messageByte, 0, out, 0, messageByte.length);
        System.arraycopy(firma, 0, out, messageByte.length , firma.length);
        return out;   
    }
    
    public Boolean verificar(byte [] message, PublicKey clavePublica) throws UnsupportedEncodingException{
        byte[] digest;
        int j = 0;
        byte[] mess = new byte[message.length-128];
        byte[] firma = new byte[128];
        System.arraycopy(message, 0, mess, 0, message.length-128);
        String messStr =  new String(mess, StandardCharsets.UTF_8);
        System.arraycopy(message, message.length-128, firma, 0, 128);
        RSA rsa = new RSA();
        SHA1 sha1 = new SHA1();
        firma = rsa.decifrarLLavePublica(firma, clavePublica);
        String firmaStr = new String(firma, StandardCharsets.UTF_8);
        digest = sha1.getSHA1(messStr);
        String digestStr = new String(digest, StandardCharsets.UTF_8);
        return firmaStr.equals(digestStr);
    }

}
