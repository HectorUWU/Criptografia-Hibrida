package practica.pkg5.crypto;

import practica.pkg5.crypto.Archivo;
import java.security.*;
import javax.crypto.*;
import java.io.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSA implements Serializable{

    public RSA() {
         Security.addProvider(new BouncyCastleProvider());
    }
    
    public void generarLLaves(){
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
            keyGen.initialize(1024);
            KeyPair clavesRSA = keyGen.generateKeyPair();
            PrivateKey clavePrivada = clavesRSA.getPrivate(); 
            PublicKey clavePublica = clavesRSA.getPublic();
            
            Archivo a = new Archivo("Llave.txt");
            a.guardarLLave(clavePublica, "Publica.txt");
            a.guardarLLave(clavePrivada, "Privada.txt");
            
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public byte[] cifrarLLavePublica(byte[] message, PublicKey clavePublica ){
        byte[] bufferCifrado = null;
        try {
            Cipher cifrador = Cipher.getInstance("RSA", "BC");
            try {
                cifrador.init(Cipher.ENCRYPT_MODE, clavePublica);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
            }
            try {
                bufferCifrado = cifrador.doFinal(message);
            } catch (IllegalBlockSizeException | BadPaddingException ex) {
                Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return bufferCifrado;
    }
    
    public byte[] decifrarLLavePrivada(byte[] cipherText,PrivateKey clavePrivada){
        byte[] bufferPlano2 = null;
        try {
            Cipher cifrador = Cipher.getInstance("RSA", "BC");
            try {
                cifrador.init(Cipher.DECRYPT_MODE, clavePrivada);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
            }
            try {
                bufferPlano2 = cifrador.doFinal(cipherText);
            } catch (IllegalBlockSizeException | BadPaddingException ex) {
                Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return bufferPlano2;
    }
    
    public byte[] cifrarLLavePrivada(byte[] plainText, PrivateKey clavePrivada){
        byte[] bufferPlano2 = null;
        try {
            Cipher cifrador = Cipher.getInstance("RSA", "BC");
            try {
                cifrador.init(Cipher.ENCRYPT_MODE, clavePrivada);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
            }
            try {
                bufferPlano2 = cifrador.doFinal(plainText);
            } catch (IllegalBlockSizeException | BadPaddingException ex) {
                Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return bufferPlano2;
    }
    
    public byte[] decifrarLLavePublica(byte[] cipherText,PublicKey clavePublica){
        byte[] bufferPlano2 = null;
        try {
            Cipher cifrador = Cipher.getInstance("RSA", "BC");
            try {
                cifrador.init(Cipher.DECRYPT_MODE, clavePublica);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
            }
            try {
                bufferPlano2 = cifrador.doFinal(cipherText);
            } catch (IllegalBlockSizeException | BadPaddingException ex) {
                Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return bufferPlano2;
    }
}
