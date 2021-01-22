/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package practica.pkg5.crypto;

import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.security.*;
import java.util.*;

import java.math.BigInteger;
import java.security.MessageDigest;

public class SHA1 {

	public byte[] getSHA1(String value){

		//String value = "hola kevin";
                byte [] sha1out;
		String sha1 = "";
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-1");
	        digest.reset();
	        digest.update(value.getBytes("utf8"));
	        sha1 = String.format("%040x", new BigInteger(1, digest.digest()));
		} catch (Exception e){
			e.printStackTrace();
		}
                sha1out = sha1.getBytes();
                return sha1out;
        }
}