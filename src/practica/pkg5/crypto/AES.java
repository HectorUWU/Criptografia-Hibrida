package practica.pkg5.crypto;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

public class AES {
    private static final String algo="AES/CBC/PKCS5PADDING"; //final nunca se vuelve a alterar

    public byte[] cifrar(String data, Key key) throws Exception{
        Cipher c = Cipher.getInstance(algo);
        c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[16]));
        byte[] encValue = c.doFinal(data.getBytes());
        return encValue;
    }

    public  String descifrar(byte[] encryptedData, Key key) throws Exception{
        Cipher c = Cipher.getInstance(algo);
        c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(new byte[16]));
        byte [] decValue = c.doFinal(encryptedData);
        String decryptValue = new String(decValue);
        return decryptValue;
        
    }
    public  Key generateKey() throws Exception{
      KeyGenerator keyGen = KeyGenerator.getInstance("AES");
      keyGen.init(128);
      SecretKey secretKey = keyGen.generateKey();
      return secretKey;
    }
}
