/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package practica.pkg5.crypto;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author user1
 */
public class Archivo {

    private String ruta;

    public Archivo(String ruta) {
        this.ruta = ruta;
    }

    public void guardarLLave(Object llave, String ext) {
        try {
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(ruta.replaceAll(".txt", ext)));
            oos.writeObject(llave);
            oos.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Archivo.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Archivo.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public Object leerLlave() {
        Object llave = null;
        try {
            ObjectInputStream oos = new ObjectInputStream(new FileInputStream(ruta));
            llave = oos.readObject();
        } catch (IOException | ClassNotFoundException e) {
            System.out.println("No se ha podido leer la llave");
        }
        return llave;
    }

    public String getInfo() { //Devuelve la informacion del archivo
        File archivo = null;
        FileReader fr = null;
        BufferedReader br = null;
        String texto = "";
        try {
            // Apertura del fichero y creacion de BufferedReader para poder
            // hacer una lectura comoda (disponer del metodo readLine()).
            archivo = new File(ruta);
            fr = new FileReader(archivo);
            br = new BufferedReader(fr);

            // Lectura del fichero
            String linea;
            while ((linea = br.readLine()) != null) {
                texto = texto + linea + "\n";
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // En el finally cerramos el fichero, para asegurarnos
            // que se cierra tanto si todo va bien como si salta 
            // una excepcion.
            try {
                if (null != fr) {
                    fr.close();
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        return texto;
    }

    public void saveBytes(String ext, byte[] fileArray) {
        FileOutputStream fileOuputStream = null;
        try {
            fileOuputStream = new FileOutputStream(ruta.replaceAll(".txt", ext));
            fileOuputStream.write(fileArray);
            fileOuputStream.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Archivo.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Archivo.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                fileOuputStream.close();
            } catch (IOException ex) {
                Logger.getLogger(Archivo.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public byte[] getBytes() {
        FileInputStream fileInputStream = null;
        File file = new File(ruta);
        byte[] fileArray = new byte[(int) file.length()];
        try {
            fileInputStream = new FileInputStream(file);
            fileInputStream.read(fileArray);
            fileInputStream.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Archivo.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Archivo.class.getName()).log(Level.SEVERE, null, ex);
        }
        return fileArray;
    }

    public void saveInfo(String ext, String text) {
        FileWriter fichero = null;
        PrintWriter pw = null;
        try {
            fichero = new FileWriter(ruta.replaceAll(".txt", ext));
            pw = new PrintWriter(fichero);

            pw.print(text);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                // Nuevamente aprovechamos el finally para 
                // asegurarnos que se cierra el fichero.
                if (null != fichero) {
                    fichero.close();
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    }
}
