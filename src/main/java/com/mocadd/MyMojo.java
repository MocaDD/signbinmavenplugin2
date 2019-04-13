package com.mocadd;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;

@Mojo( name = "sign")
public class MyMojo extends AbstractMojo {

    public void execute() throws MojoExecutionException {

        String dataFile = "";
        String keyFile = "";
        String signFile = "";
        File folder = null;

        int i = 1;
        int c = 0;
        while (i < 5000) try {
            folder = new File("binary_file_" + Integer.toString(i));
            i++;
        } catch (NullPointerException e) {
            --i;
            c = i;
            dataFile = "binary_file_" + Integer.toString(c);
            keyFile = "PrivateKey/PrivateKey_" + Integer.toString(c) + ".key";
            signFile = "Semnatura_" + Integer.toString(c);
            break;
        }


        List<String> lines = null;
        try {
            lines = Files.readAllLines(Paths.get(keyFile), StandardCharsets.US_ASCII);
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (lines.size() < 2)
            throw new IllegalArgumentException("Insufficient input");
        if (!lines.remove(0).startsWith("--"))
            throw new IllegalArgumentException("Expected header");
        if (!lines.remove(lines.size() - 1).startsWith("--"))
            throw new IllegalArgumentException("Expected footer");
        byte[] raw = Base64.getDecoder().decode(String.join("", lines));
        KeyFactory factory = null;
        try {
            factory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        PrivateKey pvt = null;
        try {
            pvt = factory.generatePrivate(new PKCS8EncodedKeySpec(raw));
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }

        Signature sign = null;
        try {
            sign = Signature.getInstance("SHA256withRSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            sign.initSign(pvt);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        InputStream in = null;
        try {
            in = new FileInputStream(dataFile);
            byte[] buf = new byte[2048];
            int len;
            while ((len = in.read(buf)) != -1) {
                sign.update(buf, 0, len);
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } finally {
            if ( in != null ) try {
                in.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        OutputStream out = null;
        try {
            out = new FileOutputStream(signFile);
            byte[] signature = sign.sign();
            out.write(signature);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } finally {
            if ( out != null ) try {
                out.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}