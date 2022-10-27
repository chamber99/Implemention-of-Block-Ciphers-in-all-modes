import javax.crypto.*;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Main {
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        // ECB ------------------------------------------------------
        /*Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        KeyGenerator keygenerator = KeyGenerator.getInstance("DES");
        SecretKey desKey = keygenerator.generateKey();
        desCipher.init(Cipher.ENCRYPT_MODE, desKey);
        byte[] message = "a".getBytes(StandardCharsets.US_ASCII);
        byte[] encryptedMessage = desCipher.doFinal(message);
        desCipher.init(Cipher.DECRYPT_MODE, desKey);
        byte[] decryptedMessage = desCipher.doFinal(encryptedMessage);
        //System.out.println(new String(encryptedMessage));

        for(Byte b : encryptedMessage){
            System.out.println(Integer.toBinaryString(0x100 + (int) (b & 0xFF)).substring(1));
        }
        System.out.println("-----");

        System.out.println(new String(decryptedMessage));*/


        // CBC
        FileCipher fileCipher = new FileCipher();

        byte[] message = "denemexd".getBytes(StandardCharsets.UTF_8);

        byte[] IV = "iviviviv".getBytes(StandardCharsets.UTF_8);

        //byte[] key = "5YBuFATucUweceMY".getBytes(StandardCharsets.UTF_8);
        byte[] key = "denemeas".getBytes(StandardCharsets.UTF_8);

        byte[] nonce = "noncenon".getBytes(StandardCharsets.UTF_8);

        String enc = fileCipher.OFBEncryption(IV,message,key);

        System.out.println(enc);

        System.out.println(fileCipher.OFBDecryption(IV,enc.getBytes(StandardCharsets.UTF_8),key));







    }
}