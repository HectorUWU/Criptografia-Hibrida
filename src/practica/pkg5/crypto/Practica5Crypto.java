/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package practica.pkg5.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 *
 * @author hector
 */
public class Practica5Crypto {

    /**
     * @param args the command line arguments
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.NoSuchProviderException
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair clavesRSA = keyGen.generateKeyPair();
        PrivateKey clavePrivada = clavesRSA.getPrivate();
        PublicKey clavePublica = clavesRSA.getPublic();
        CryptoHibrida ch = new CryptoHibrida();
        String msg = "Chinga tu madre nidia";
        byte[] out = ch.cifrarYFirmar(msg, clavePrivada, clavePublica);
        ch.descifrarYverificar(out, clavePrivada, clavePublica);
        out = ch.cifrar(msg, clavePublica);
        ch.descifrar(out, clavePrivada);
        out = ch.firmar(msg, clavePrivada);
        if(ch.verificar(out, clavePublica))
            System.out.println("Esta mamada jala");
    }

}
