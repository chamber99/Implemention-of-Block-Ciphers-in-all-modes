import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


public class FileCipher {
    // Cipher object to implement all necessary algorithms.
    private static Cipher des;
    public static void main(String[] args)  {
        try {
            run(args);
        } catch (IOException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException |
                 NoSuchPaddingException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    //All command line arguments are passed to this function.
    public static void run(String[] commands) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        // Starting the timer to calculate the runtime.
        long startTime = System.currentTimeMillis();
        // Initiating our DES algorithm in ECB mode.
        des = Cipher.getInstance("DES/ECB/NoPadding");
        String operation = commands[0];
        String inputFile = commands[2];
        String outputFile = commands[4];
        String algorithm = commands[5];
        String mode = commands[6];
        String keyFile = commands[7];
        int algoInput;
        // Creating a FileOps object to perform all file operations.
        FileOps fileOps = new FileOps(inputFile,outputFile,keyFile,mode,algorithm,operation);
        // Reading the bytes of the input file.
        byte[] input = fileOps.readInputFile();
        byte[] padded;
        // Generating the IV and nonce values.
        byte[] IV = generateIVorNonce(fileOps.getIV());
        byte[] nonce = generateIVorNonce(fileOps.getNonce());
        SecretKey[] keys;

        // Checking the algorithm that is specified in command.
        if(algorithm.equals("DES")){
            keys = generateKey(fileOps.getKey(),1);
            algoInput = 1;
        }else{
            keys = generateKey(fileOps.getKey(),2);
            algoInput = 2;
        }

        byte[] result;

        //Checking the operations and the mode of operations.
        if(operation.equals("-e")){
            padded = padPlainText(input);
            switch (mode){
                case "CBC":
                    result = CBCEncryption(IV,padded,keys,algoInput);
                    break;
                case "CFB":
                    result = CFBEncryption(IV,padded,keys,algoInput);
                    break;
                case "OFB":
                    result = OFBEncryption(IV,padded,keys,algoInput);
                    break;
                case "CTR":
                    result = CTREncryption(IV,padded,keys,algoInput);
                    break;
                default:
                    result = new byte[0];
                    break;
            }
        } else if (operation.equals("-d")) {
            switch (mode){
                case "CBC":
                    result = CBCDecryption(IV,input,keys,algoInput);
                    break;
                case "CFB":
                    result = CFBDecryption(IV,input,keys,algoInput);
                    break;
                case "OFB":
                    result = OFBDecryption(IV,input,keys,algoInput);
                    break;
                case "CTR":
                    result = CTRDecryption(IV,input,keys,algoInput);
                    break;
                default:
                    result = new byte[0];
                    break;
            }
        }else{
            result = new byte[0];
        }

        // Generating the output file and end the timer.
        fileOps.writeOutputFile(result);
        long endTime = System.currentTimeMillis();
        // This method creates the log file.
        fileOps.end(endTime-startTime);

    }

    // This method performs PKCS5 Padding operation.
    public static byte[] padPlainText(byte[] plainText) {
        byte[] byteArray = plainText;
        int remainder = byteArray.length % 8;
        byte[] padded = new byte[byteArray.length + (8 - remainder)];
        Arrays.fill(padded, (byte) (8 - remainder));
        int index = 0;
        for (byte b : byteArray) {
            padded[index++] = b;
        }
        return padded;
    }
    // This method clears padding bytes after decryption.
    public static byte[] clearPadding(byte[] padded){
        byte lastByte = padded[padded.length - 1];
        int plainTextLength = padded.length - lastByte;
        byte[] withoutPadding = new byte[plainTextLength];
        for (int i = 0; i < plainTextLength; i++) {
            withoutPadding[i] = padded[i];
        }
        return withoutPadding;
    }

    // Implementation of the CBC mode of encryption by using a simple DES.
    public static byte[] CBCEncryption(byte IV[], byte plainText[], SecretKey[] key, int algorithm) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] lastCipherText = IV;
        int blockCount = plainText.length / 8;
        byte[] encryptedMessage = new byte[plainText.length];
        int outputIndex = 0;
        int currentBlock = 1;
        // Each block is encrypted separately.
        while (currentBlock <= blockCount) {
            byte[] currentPlainText = new byte[8];
            int index = 0;
            //Fetching the bytes in current block.
            for (int i = (currentBlock - 1) * 8; i < currentBlock * 8; i++) {
                currentPlainText[index] = plainText[i];
                index++;
            }
            //Calculating the cipherInput.
            byte[] cipherInput = XOR(lastCipherText, currentPlainText);
            byte[] encrypted = null;
            // Calculating the cipher output.
            if (algorithm == 1) {
                encrypted = useDES(cipherInput, key[0], 1);
            }
            else if (algorithm == 2) {
                encrypted = use3DES(cipherInput, key, 1);
            }
            for (byte b : encrypted) {
                encryptedMessage[outputIndex++] = b;
            }
            lastCipherText = encrypted;
            // Moving to the next block.
            currentBlock++;
        }
        return encryptedMessage;

    }
    // Implementation of the CBC mode of decryption by using a simple DES.
    public static byte[] CBCDecryption(byte IV[], byte cipherText[], SecretKey[] key, int algorithm) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] decryptedMessage = new byte[cipherText.length];
        int outputIndex = 0;
        byte[] previousCipherText = IV;
        int blockCount = cipherText.length / 8;
        int currentBlock = 1;
        // Each block is decrypted separately.
        while (currentBlock <= blockCount) {
            byte[] currentCipherText = new byte[8];
            int index = 0;
            //Fetching the bytes in current block.
            for (int i = (currentBlock - 1) * 8; i < currentBlock * 8; i++) {
                currentCipherText[index] = cipherText[i];
                index++;
            }
            byte[] decrypted = null;
            //Calculating the cipher output.
            if (algorithm == 1) {
                decrypted = XOR(useDES(currentCipherText, key[0], 2), previousCipherText);

            } else if (algorithm == 2) {
                decrypted = XOR(use3DES(currentCipherText, key, 2), previousCipherText);
            }
            previousCipherText = currentCipherText;
            for (byte b : decrypted) {
                decryptedMessage[outputIndex++] = b;
            }
            // Moving to the next block.
            currentBlock++;
        }
        // Clearing the padding before returning.
        return clearPadding(decryptedMessage);
    }
    // Implementation of the CFB mode of encryption by using a simple DES.
    public static byte[] CFBEncryption(byte[] IV, byte[] plainText, SecretKey[] key, int algorithm) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] lastInput = IV;
        int blockCount = plainText.length / 8;
        int currentBlock = 1;
        byte[] encryptedMessage = new byte[plainText.length];
        int outputIndex = 0;
        // Each block is decrypted separately.
        while (currentBlock <= blockCount) {
            byte[] currentPlainText = new byte[8];
            int index = 0;
            //Fetching the bytes in current block.
            for (int i = (currentBlock - 1) * 8; i < currentBlock * 8; i++) {
                currentPlainText[index] = plainText[i];
                index++;
            }

            byte[] cipherInput = lastInput;
            byte[] encrypted = null;
            // Calculation of the cipher output.
            if (algorithm == 1) {
                encrypted = XOR(currentPlainText, useDES(cipherInput, key[0], 1));
            } else if (algorithm == 2) {
                encrypted = XOR(currentPlainText, use3DES(cipherInput, key, 1));
            }
            for (byte b : encrypted) {
                encryptedMessage[outputIndex++] = b;
            }
            lastInput = encrypted;
            // Moving to the next block.
            currentBlock++;
        }
        return encryptedMessage;
    }
    // Implementation of the CFB mode of decryption by using a simple DES.
    public static byte[] CFBDecryption(byte[] IV, byte[] cipherText, SecretKey[] key, int algorithm) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] decryptedMessage = new byte[cipherText.length];
        int outputIndex = 0;
        byte[] lastInput = IV;
        int blockCount = cipherText.length / 8;
        int currentBlock = 1;
        //Fetching the bytes in current block.
        while (currentBlock <= blockCount) {
            byte[] currentCipherText = new byte[8];
            int index = 0;
            for (int i = (currentBlock - 1) * 8; i < currentBlock * 8; i++) {
                currentCipherText[index] = cipherText[i];
                index++;
            }

            byte[] cipherInput = lastInput;
            byte[] decrypted = null;
            // Calculation of cipher output.
            if (algorithm == 1) {
                decrypted = XOR(useDES(cipherInput, key[0], 1), currentCipherText);
            } else if (algorithm == 2) {
                decrypted = XOR(use3DES(cipherInput, key, 1), currentCipherText);
            }

            for (byte b : decrypted) {
                decryptedMessage[outputIndex++] = b;
            }
            lastInput = currentCipherText;
            currentBlock++;
            // Moving to the next block.
        }
        //Clearing padding before returning the result.
        return clearPadding(decryptedMessage);
    }
    // Implementation of the OFB mode of encryption by using a simple DES.
    public static byte[] OFBEncryption(byte[] IV, byte[] plainText, SecretKey[] key, int algorithm) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] encryptedMessage = new byte[plainText.length];
        int outputIndex = 0;
        byte[] lastInput = IV;
        int blockCount = plainText.length / 8;
        int currentBlock = 1;
        while (currentBlock <= blockCount) {
            byte[] currentPlainText = new byte[8];
            int index = 0;
            //Fetching the bytes in current block.
            for (int i = (currentBlock - 1) * 8; i < currentBlock * 8; i++) {
                currentPlainText[index] = plainText[i];
                index++;
            }

            byte[] cipherInput = lastInput;
            byte[] output = null;
            // Calculating the cipher output.
            if (algorithm == 1) {
                output = useDES(cipherInput, key[0], 1);
            } else if (algorithm == 2) {
                output = use3DES(cipherInput, key, 1);
            }
            byte[] encrypted = XOR(currentPlainText, output);
            lastInput = output;
            // Moving to the next block.
            currentBlock++;

            for (Byte b : encrypted) {
                encryptedMessage[outputIndex++] = b;
            }

        }
        return encryptedMessage;
    }
    // Implementation of the OFB mode of decryption by using a simple DES.
    public static byte[] OFBDecryption(byte[] IV, byte[] cipherText, SecretKey[] key, int algorithm) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        byte[] decryptedMessage = new byte[cipherText.length];
        int outputIndex = 0;
        byte[] lastInput = IV;
        byte[] bytes = new byte[cipherText.length];
        int blockCount = cipherText.length / 8;
        int currentBlock = 1;
        // Each block is decrypted separately.
        while (currentBlock <= blockCount) {
            byte[] currentCipherText = new byte[8];
            int index = 0;
            // Fetching the bytes in current block.
            for (int i = (currentBlock - 1) * 8; i < currentBlock * 8; i++) {
                currentCipherText[index] = cipherText[i];
                index++;
            }
            byte[] cipherInput = lastInput;
            byte[] output = null;
            // Calculating the cipher output.
            if (algorithm == 1) {
                output = useDES(cipherInput, key[0], 1);
            } else if (algorithm == 2) {
                output = use3DES(cipherInput, key, 1);
            }
            byte[] decrypted = XOR(currentCipherText, output);
            lastInput = output;

            for (byte b : decrypted) {
                decryptedMessage[outputIndex++] = b;
            }
            // Moving to the next block.
            currentBlock++;
        }
        return clearPadding(decryptedMessage);
    }
    // Implementation of the CTR mode of encryption by using a simple DES.
    public static byte[] CTREncryption(byte[] nonce, byte[] plainText, SecretKey[] key, int algorithm) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] encryptedMessage = new byte[plainText.length];
        int outputIndex = 0;
        int blockCount = plainText.length / 8;
        int currentBlock = 1;
        // Each block is encrypted seperately
        while (currentBlock <= blockCount) {
            byte[] currentPlainText = new byte[8];
            int index = 0;
            // Fetching the bytes in current block.
            for (int i = (currentBlock - 1) * 8; i < currentBlock * 8; i++) {
                currentPlainText[index] = plainText[i];
                index++;
            }
            // Generating an 8 byte array with the counter value.
            byte[] counterBytes = ByteBuffer.allocate(8).putInt(currentBlock - 1).array();
            // Since we use block size of 8,XOR operation was used.
            byte[] cipherInput = XOR(nonce, counterBytes);
            byte[] output = null;
            // Calculating the cipher output.
            if (algorithm == 1) {
                output = useDES(cipherInput, key[0], 1);
            } else if (algorithm == 2) {
                output = use3DES(cipherInput, key, 1);
            }
            byte[] encrypted = XOR(currentPlainText, output);
            for (byte b : encrypted) {
                encryptedMessage[outputIndex++] = b;
            }
            currentBlock++;
        }
        return encryptedMessage;
    }
    // Implementation of the CTR mode of decryption by using a simple DES.
    public static byte[] CTRDecryption(byte[] nonce, byte[] cipherText, SecretKey[] key, int algorithm) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] decryptedMessage = new byte[cipherText.length];
        int outputIndex = 0;
        int blockCount = cipherText.length / 8;
        int currentBlock = 1;
        // Each block is decrypted separately.
        while (currentBlock <= blockCount) {
            byte[] currentCipherText = new byte[8];
            int index = 0;
            // Fetching the bytes in current block.
            for (int i = (currentBlock - 1) * 8; i < currentBlock * 8; i++) {
                currentCipherText[index] = cipherText[i];
                index++;
            }
            // Generating an 8 byte array with the counter value.
            byte[] counterBytes = ByteBuffer.allocate(8).putInt(currentBlock - 1).array();
            // Calculating the cipher input.
            byte[] cipherInput = XOR(nonce, counterBytes);
            byte[] output = null;
            // Calculating the cipher output.
            if (algorithm == 1) {
                output = useDES(cipherInput, key[0], 1);
            } else if (algorithm == 2) {
                output = use3DES(cipherInput, key, 1);
            }
            // Calculating the result.
            byte[] decrypted = XOR(currentCipherText, output);
            for (byte b : decrypted) {
                decryptedMessage[outputIndex++] = b;
            }
            // Moving to the next block.
            currentBlock++;
        }
        return clearPadding(decryptedMessage);
    }

    // Encryption and decryption with DES.
    public static byte[] useDES(byte[] input, SecretKey key, int operation) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (operation == 1) {
            des.init(Cipher.ENCRYPT_MODE, key);

        } else if (operation == 2) {
            des.init(Cipher.DECRYPT_MODE, key);
        }
        return des.doFinal(input);
    }
    // Implementation of 3DES by using DES.
    public static byte[] use3DES(byte[] input, SecretKey[] keys, int operation) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        // 3 keys version
        SecretKey firstKey = keys[0];
        SecretKey secondKey = keys[1];
        SecretKey thirdKey = keys[2];
        byte[] output = new byte[input.length];
        // 3DES Encryption
        if (operation == 1) {
            byte[] firstStep = useDES(input, firstKey, 1);
            byte[] secondStep = useDES(firstStep, secondKey, 2);
            output = useDES(secondStep, thirdKey, 1);
        }
        // 3DES Decryption
        else if (operation == 2) {
            byte[] firstStep = useDES(input, thirdKey, 2);
            byte[] secondStep = useDES(firstStep, secondKey, 1);
            output = useDES(secondStep, firstKey, 2);
        }
        return output;
    }

    // Implementation of XOR operation between two byte arrays.
    public static byte[] XOR(byte[] input1, byte[] input2) {
        byte[] resultArray = new byte[8];
        for (int i = 0; i < 8; i++) {
            resultArray[i] = (byte) (input1[i] ^ input2[i]);
        }
        return resultArray;

    }
    // This method creates a byte array of size 8 by using an integer value.
    public static byte[] createByteArray(int hashCode) {
        // Creating 2 arrays of size 4 and combining them by using integer value(hash) taken as parameter.
        byte[] firstArray = ByteBuffer.allocate(4).putInt(hashCode).array();
        byte[] secondArray = ByteBuffer.allocate(4).putInt(hashCode * 2).array();
        byte[] finalArray = new byte[8];
        int index = 0;
        // Combining operation
        for (int i = 0; i < 4; i++) {
            finalArray[index++] = firstArray[i];
        }
        for (int j = 0; j < 4; j++) {
            finalArray[index++] = secondArray[j];
        }
        return finalArray;
    }

    // This method generates SecretKey object by using the hashcode of the input string.
    public static SecretKey[] generateKey(String input, int operation){
        SecretKey[] keys = null;
        int hashCode = input.hashCode();
        byte[] keyBytes = createByteArray(hashCode);
        SecretKey key = new SecretKeySpec(keyBytes, "DES");
        // 1 key is needed for DES
        if (operation == 1) {
            keys = new SecretKey[1];
            keys[0] = key;
        }
        // 3 keys are needed for 3DES.
        else if (operation == 2) {
            // Generating 3 different keys by using hash value.
            keys = new SecretKey[3];
            keys[0] = key;
            keys[1] = new SecretKeySpec(XOR(keyBytes, keyBytes), "DES");
            keys[2] = new SecretKeySpec(XOR(createByteArray(hashCode + 500), createByteArray(hashCode - 500)), "DES");
        }
        return keys;
    }

    // This method generates a byte array of size 8 by using the hash value of the input string .
    public static byte[] generateIVorNonce(String input) {
        int hashCode = input.hashCode();
        byte[] bytes = createByteArray(hashCode);
        return bytes;
    }


}
