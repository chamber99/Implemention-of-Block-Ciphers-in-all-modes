import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class FileCipher {
    Cipher desCipher;
    Cipher tripleDesCipher;
    KeyGenerator desKeygen;
    KeyGenerator tripleDesKeygen;
    SecretKey desKey;
    SecretKey tripleDesKey;
    FileOps fileOps;



    public FileCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        fileOps = new FileOps();

        desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        tripleDesCipher = Cipher.getInstance("TripleDES/ECB/PKCS5Padding");

        desKeygen = KeyGenerator.getInstance("DES");
        tripleDesKeygen = KeyGenerator.getInstance("TripleDES");

        desKey = desKeygen.generateKey();
        tripleDesKey = tripleDesKeygen.generateKey();
    }


    public ArrayList<byte[]> prepareInputs(ProcessType processType ,String key, String fileToBeProcessed){
        ArrayList<byte[]> preparedInput = new ArrayList<>();
        if(processType == ProcessType.ENCRYPTION){



        }else{



        }


        return preparedInput;
    }


    public byte[] XOR(byte[] input1, byte[] input2) {
        byte[] resultArray = new byte[8];
        for (int i = 0; i < 8; i++) {
            resultArray[i] = (byte) (input1[i] ^ input2[i]);
        }
        return resultArray;
    }

    public String CBCEncryption(byte[] IV, byte[] plainText, byte[] encodedKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String encryptedMessage = "";
        byte[] lastCipherText = IV;
        int blockCount = plainText.length / 8;
        int currentBlock = 1;
        while (currentBlock <= blockCount) {
            byte[] currentPlainText = new byte[8];
            int index = 0;
            for (int i = (currentBlock - 1) * 8; i < currentBlock * 8; i++) {
                currentPlainText[index] = plainText[i];
                index++;
            }
            byte[] cipherInput = XOR(lastCipherText, currentPlainText);
            Key key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "DES");
            desCipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = desCipher.doFinal(cipherInput);
            lastCipherText = encrypted;
            encryptedMessage += new String(encrypted);
            currentBlock++;
        }
        return encryptedMessage;

    }



    public String CFBEncryption(byte[] IV, byte[] plainText, byte[] encodedKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String encryptedMessage = "";
        byte[] lastInput = IV;

        int blockCount = plainText.length / 8;
        int currentBlock = 1;

        while (currentBlock <= blockCount) {
            byte[] currentPlainText = new byte[8];
            int index = 0;
            for (int i = (currentBlock - 1) * 8; i < currentBlock * 8; i++) {
                currentPlainText[index] = plainText[i];
                index++;
            }

            byte[] cipherInput = lastInput;
            Key key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "DES");
            desCipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = XOR(currentPlainText, desCipher.doFinal(cipherInput));
            lastInput = encrypted;
            encryptedMessage += new String(encrypted);
            currentBlock++;
        }
        return encryptedMessage;
    }



    public String OFBEncryption(byte[] IV, byte[] plainText, byte[] encodedKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String encryptedMessage = "";
        byte[] lastInput = IV;

        int blockCount = plainText.length / 8;
        int currentBlock = 1;

        while (currentBlock <= blockCount) {
            byte[] currentPlainText = new byte[8];
            int index = 0;
            for (int i = (currentBlock - 1) * 8; i < currentBlock * 8; i++) {
                currentPlainText[index] = plainText[i];
                index++;
            }

            byte[] cipherInput = lastInput;
            Key key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "DES");
            desCipher.init(Cipher.ENCRYPT_MODE, key);


            byte[] output = desCipher.doFinal(cipherInput);
            byte[] encrypted = XOR(currentPlainText, output);
            lastInput = output;
            encryptedMessage += new String(encrypted);
            currentBlock++;
        }
        return encryptedMessage;
    }

    public String OFBDecryption(byte[] IV,byte[] cipherText, byte[] encodedKey) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String decryptedMessage = "";
        byte[] lastInput = IV;

        int blockCount = cipherText.length / 8;
        int currentBlock = 1;

        while (currentBlock <= blockCount) {
            byte[] currentCipherText = new byte[8];
            int index = 0;
            for (int i = (currentBlock - 1) * 8; i < currentBlock * 8; i++) {
                currentCipherText[index] = cipherText[i];
                index++;
            }

            byte[] cipherInput = lastInput;
            Key key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "DES");
            desCipher.init(Cipher.ENCRYPT_MODE, key);


            byte[] output = desCipher.doFinal(cipherInput);
            byte[] decrypted = XOR(currentCipherText, output);
            lastInput = output;
            decryptedMessage += new String(decrypted);
            currentBlock++;
        }
        return decryptedMessage;
    }

    public String CTREncryption(byte[] nonce, byte[] plainText, byte[] encodedKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String encryptedMessage = "";

        int blockCount = plainText.length / 8;
        int currentBlock = 1;

        while (currentBlock <= blockCount) {
            byte[] currentPlainText = new byte[8];
            int index = 0;
            for (int i = (currentBlock - 1) * 8; i < currentBlock * 8; i++) {
                currentPlainText[index] = plainText[i];
                index++;
            }

            BigInteger bigint = BigInteger.valueOf(currentBlock - 1);
            byte[] cipherInput = XOR(nonce,bigint.toByteArray());

            Key key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "DES");
            desCipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] output = desCipher.doFinal(cipherInput);
            byte[] encrypted = XOR(currentPlainText, output);

            encryptedMessage += new String(encrypted);
            currentBlock++;
        }
        return encryptedMessage;
    }

    public String CTRDecryption(byte[] nonce, byte[] cipherText, byte[] encodedKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        String decryptedMessage = "";

        int blockCount = cipherText.length / 8;
        int currentBlock = 1;

        while (currentBlock <= blockCount) {
            byte[] currentCipherText = new byte[8];
            int index = 0;
            for (int i = (currentBlock - 1) * 8; i < currentBlock * 8; i++) {
                currentCipherText[index] = cipherText[i];
                index++;
            }

            BigInteger bigint = BigInteger.valueOf(currentBlock - 1);
            byte[] cipherInput = XOR(nonce,bigint.toByteArray());

            Key key = new SecretKeySpec(encodedKey, 0, encodedKey.length, "DES");
            desCipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] output = desCipher.doFinal(cipherInput);
            byte[] decrypted = XOR(currentCipherText, output);

            decryptedMessage += new String(decrypted);
            currentBlock++;
        }
        return decryptedMessage;
    }




}
