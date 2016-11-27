package com.example.suhas.digitalsignature;

import android.app.Activity;
import android.os.Bundle;
import android.telephony.SmsManager;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;

import android.widget.Toast;

import java.io.*;
import java.security.*;
import java.security.spec.*;


import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

public class MainActivity extends Activity {
    /**
     * Called when the activity is first created.
     */
    EditText eTextMsg, eTextMblNumber, esign;
    Button btnSendSMS, btnds, btnvds;
    KeyPairGenerator keyGen;
    SecureRandom random;
    KeyPair pair;
    PrivateKey priv;
    PublicKey pub;
    byte[] realSig;

    @Override

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        try {
            createkey();
        } catch (Exception e) {
            e.printStackTrace();
        }

        eTextMblNumber = (EditText) findViewById(R.id.etextMblNumber);
        eTextMsg = (EditText) findViewById(R.id.etextMsg);
        btnSendSMS = (Button) findViewById(R.id.btnSendSMS);
        btnds = (Button) findViewById(R.id.btnds);
        btnvds = (Button) findViewById(R.id.btnvds);
        esign = (EditText) findViewById(R.id.esign);

        btnds.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    digital();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
        btnvds.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    vdigital();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
        btnSendSMS.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                // TODO Auto-generated method stub
                sendSMS();
            }
        });

    }

    private void createkey() throws Exception {
        File temp = new File("hello");
        String dir = temp.getAbsolutePath().toString();
        if(this.loadKey(dir,"SHA1withECDSA")==null){

            Toast.makeText(getApplicationContext(),
                    "dir://"+dir, Toast.LENGTH_LONG).show();
            keyGen = KeyPairGenerator.getInstance("EC");
            random = SecureRandom.getInstance("SHA1PRNG");

            keyGen.initialize(256, random);

            pair = keyGen.generateKeyPair();
            priv = pair.getPrivate();
            pub = pair.getPublic();
            this.saveKey(dir, pair);



        }
        else{

            pair = this.loadKey(dir,"SHA1withECDSA");
            priv = pair.getPrivate();
            pub = pair.getPublic();
            Toast.makeText(getApplicationContext(),
                    "loadKey", Toast.LENGTH_LONG).show();

        }



    }


    private void vdigital() throws Exception {

        String str = eTextMsg.getText().toString();


        Signature sig = Signature.getInstance("SHA1withECDSA");
        sig.initVerify(pub);
        sig.update(str.getBytes());

        boolean verifies = sig.verify(realSig);

        Toast.makeText(getApplicationContext(),
                "Signature is verified: " + verifies, Toast.LENGTH_LONG).show();


    }

    private void digital() throws Exception {

        Signature dsa = Signature.getInstance("SHA1withECDSA");

        dsa.initSign(priv);

        String str = eTextMsg.getText().toString();
        byte[] strByte = str.getBytes("UTF-8");
        dsa.update(strByte);

        /*
         * Now that all the data to be signed has been read in, generate a
         * signature for it
         */

        realSig = dsa.sign();
        esign.setText(new BigInteger(1, realSig).toString(16));

        Toast.makeText(getApplicationContext(),
                "String is signed", Toast.LENGTH_LONG).show();

        System.out.println("Signature: " + new BigInteger(1, realSig).toString(16));

    }

    public void sendSMS() {
        SmsManager sm = SmsManager.getDefault();
        String number = eTextMblNumber.getText().toString();
        String msg = esign.getText().toString();
        sm.sendTextMessage(number, null, msg, null, null);
    }

    public void saveKey(String path, KeyPair keyPair) throws IOException {
        Toast.makeText(getApplicationContext(),
                "saveKey", Toast.LENGTH_LONG).show();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Store Public Key.
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                publicKey.getEncoded());
        FileOutputStream fos = new FileOutputStream(path + "/public.key");
        fos.write(x509EncodedKeySpec.getEncoded());
        fos.close();

        // Store Private Key.
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                privateKey.getEncoded());
        fos = new FileOutputStream(path + "/private.key");
        fos.write(pkcs8EncodedKeySpec.getEncoded());
        fos.close();
    }

    
    public KeyPair loadKey(String path, String algorithm)
            throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException {
        // Read Public Key.
        FileInputStream fis;
        File filePublicKey = new File(path + "/public.key");
        if (filePublicKey.exists() && !filePublicKey.isDirectory()) {
            fis = new FileInputStream(path + "/public.key");
            byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
            fis.read(encodedPublicKey);
            fis.close();

            // Read Private Key.
            File filePrivateKey = new File(path + "/private.key");

            fis = new FileInputStream(path + "/private.key");

            byte[] encodedPrivateKey = new byte[(int) filePrivateKey.length()];
            fis.read(encodedPrivateKey);
            fis.close();

            // Generate KeyPair.
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                    encodedPublicKey);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                    encodedPrivateKey);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            return new KeyPair(publicKey, privateKey);
        }
        else return null;
    }
}