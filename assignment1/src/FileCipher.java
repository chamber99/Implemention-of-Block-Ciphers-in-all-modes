import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class FileCipher {
    private Cipher des;

    public FileCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
        // Initiating our DES algorithm in ECB mode.
        des = Cipher.getInstance("DES/ECB/NoPadding");
    }

    public void run(String[] commands) {
        String operation = commands[1];
        String inputFile = commands[3];
        String outputFile = commands[5];
        String algorithm = commands[6];
        String mode = commands[7];
        String keyFile = commands[8];
        // File operations and log file creation........................
    }

    public byte[] padPlainText(byte[] plainText) {
        byte byteArray[] = plainText;
        int remainder = byteArray.length % 8;
        byte padded[] = new byte[byteArray.length + (8 - remainder)];
        Arrays.fill(padded, (byte) (8 - remainder));
        int index = 0;
        for (byte b : byteArray) {
            padded[index++] = b;
        }
        return padded;
    }

    public byte[] CBCEncryption(byte IV[], byte plainText[], SecretKey[] key, int algorithm) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] lastCipherText = IV;
        int blockCount = plainText.length / 8;
        byte[] encryptedMessage = new byte[plainText.length];
        int outputIndex = 0;
        int currentBlock = 1;
        while (currentBlock <= blockCount) {
            byte[] currentPlainText = new byte[8];
            int index = 0;
            for (int i = (currentBlock - 1) * 8; i < currentBlock * 8; i++) {
                currentPlainText[index] = plainText[i];
                index++;
            }
            byte[] cipherInput = XOR(lastCipherText, currentPlainText);
            byte[] encrypted = null;
            if (algorithm == 1) {
                encrypted = useDES(cipherInput, key[0], 1);
            } else if (algorithm == 2) {
                encrypted = use3DES(cipherInput, key, 1);
            }
            for (byte b : encrypted) {
                encryptedMessage[outputIndex++] = b;
            }
            lastCipherText = encrypted;
            currentBlock++;
        }
        return encryptedMessage;

    }

    public byte[] CBCDecryption(byte IV[], byte cipherText[], SecretKey[] key, int algorithm) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] decryptedMessage = new byte[cipherText.length];
        int outputIndex = 0;
        byte[] previousCipherText = IV;
        int blockCount = cipherText.length / 8;
        System.out.println(blockCount);
        int currentBlock = 1;
        while (currentBlock <= blockCount) {
            byte[] currentCipherText = new byte[8];
            int index = 0;
            for (int i = (currentBlock - 1) * 8; i < currentBlock * 8; i++) {
                currentCipherText[index] = cipherText[i];
                index++;
            }
            byte[] decrypted = null;
            if (algorithm == 1) {
                decrypted = XOR(useDES(currentCipherText, key[0], 2), previousCipherText);

            } else if (algorithm == 2) {
                decrypted = XOR(use3DES(currentCipherText, key, 2), previousCipherText);
            }
            previousCipherText = currentCipherText;
            for (byte b : decrypted) {
                decryptedMessage[outputIndex++] = b;
            }
            currentBlock++;
        }
        byte lastByte = decryptedMessage[decryptedMessage.length - 1];
        int plainTextLength = decryptedMessage.length - lastByte;
        byte[] withoutPadding = new byte[plainTextLength];
        for (int i = 0; i < plainTextLength; i++) {
            withoutPadding[i] = decryptedMessage[i];
        }

        return withoutPadding;
    }

    public byte[] CFBEncryption(byte[] IV, byte[] plainText, SecretKey[] key, int algorithm) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] lastInput = IV;
        int blockCount = plainText.length / 8;
        int currentBlock = 1;
        byte[] encryptedMessage = new byte[plainText.length];
        int outputIndex = 0;
        while (currentBlock <= blockCount) {
            byte[] currentPlainText = new byte[8];
            int index = 0;
            for (int i = (currentBlock - 1) * 8; i < currentBlock * 8; i++) {
                currentPlainText[index] = plainText[i];
                index++;
            }

            byte[] cipherInput = lastInput;
            byte[] encrypted = null;
            if (algorithm == 1) {
                encrypted = XOR(currentPlainText, useDES(cipherInput, key[0], 1));
            } else if (algorithm == 2) {
                encrypted = XOR(currentPlainText, use3DES(cipherInput, key, 1));
            }
            for (byte b : encrypted) {
                encryptedMessage[outputIndex++] = b;
            }
            lastInput = encrypted;
            currentBlock++;
        }
        return encryptedMessage;
    }

    public byte[] CFBDecryption(byte[] IV, byte[] cipherText, SecretKey[] key, int algorithm) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] decryptedMessage = new byte[cipherText.length];
        int outputIndex = 0;
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
            byte[] decrypted = null;
            if (algorithm == 1) {
                decrypted = XOR(useDES(cipherInput, key[0], 1), currentCipherText);
            } else if (algorithm == 2) {
                XOR(use3DES(cipherInput, key, 1), currentCipherText);
            }

            for (byte b : decrypted) {
                decryptedMessage[outputIndex++] = b;
            }
            lastInput = currentCipherText;
            currentBlock++;
        }
        return decryptedMessage;
    }

    public byte[] OFBEncryption(byte[] IV, byte[] plainText, SecretKey[] key, int algorithm) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] encryptedMessage = new byte[plainText.length];
        int outputIndex = 0;
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
            byte[] output = null;
            if (algorithm == 1) {
                output = useDES(cipherInput, key[0], 1);
            } else if (algorithm == 2) {
                output = use3DES(cipherInput, key, 1);
            }
            byte[] encrypted = XOR(currentPlainText, output);
            lastInput = output;
            currentBlock++;

            for (Byte b : encrypted) {
                encryptedMessage[outputIndex++] = b;
            }

        }
        return encryptedMessage;
    }

    public byte[] OFBDecryption(byte[] IV, byte[] cipherText, SecretKey[] key, int algorithm) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        byte[] decryptedMessage = new byte[cipherText.length];
        int outputIndex = 0;
        byte[] lastInput = IV;
        byte[] bytes = new byte[cipherText.length];
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
            byte[] output = null;
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
            currentBlock++;
        }
        return decryptedMessage;
    }

    public byte[] CTREncryption(byte[] nonce, byte[] plainText, SecretKey[] key, int algorithm) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] encryptedMessage = new byte[plainText.length];
        int outputIndex = 0;
        int blockCount = plainText.length / 8;
        int currentBlock = 1;
        while (currentBlock <= blockCount) {
            byte[] currentPlainText = new byte[8];
            int index = 0;
            for (int i = (currentBlock - 1) * 8; i < currentBlock * 8; i++) {
                currentPlainText[index] = plainText[i];
                index++;
            }

            byte[] counterBytes = ByteBuffer.allocate(8).putInt(currentBlock - 1).array();
            byte[] result = XOR(nonce, counterBytes);
            byte[] cipherInput = new byte[8];
            for (int i = 0; i < 8; i++) {
                cipherInput[i] = result[i];
            }
            byte[] output = null;
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

    public byte[] CTRDecryption(byte[] nonce, byte[] cipherText, SecretKey[] key, int algorithm) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] decryptedMessage = new byte[cipherText.length];
        int outputIndex = 0;
        int blockCount = cipherText.length / 8;
        int currentBlock = 1;
        while (currentBlock <= blockCount) {
            byte[] currentCipherText = new byte[8];
            int index = 0;
            for (int i = (currentBlock - 1) * 8; i < currentBlock * 8; i++) {
                currentCipherText[index] = cipherText[i];
                index++;
            }

            byte[] counterBytes = ByteBuffer.allocate(8).putInt(currentBlock - 1).array();
            byte[] result = XOR(nonce, counterBytes);
            byte[] cipherInput = new byte[8];
            for (int i = 0; i < 8; i++) {
                cipherInput[i] = result[i];
            }
            byte[] output = null;
            if (algorithm == 1) {
                output = useDES(cipherInput, key[0], 1);
            } else if (algorithm == 2) {
                output = use3DES(cipherInput, key, 1);
            }
            byte[] decrypted = XOR(currentCipherText, output);
            for (byte b : decrypted) {
                decryptedMessage[outputIndex++] = b;
            }
            currentBlock++;
        }
        return decryptedMessage;
    }

    public byte[] useDES(byte[] input, SecretKey key, int operation) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (operation == 1) {
            this.des.init(Cipher.ENCRYPT_MODE, key);

        } else if (operation == 2) {
            this.des.init(Cipher.DECRYPT_MODE, key);
        }
        return this.des.doFinal(input);
    }

    public byte[] use3DES(byte[] input, SecretKey[] keys, int operation) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        SecretKey firstKey = keys[0];
        SecretKey secondKey = keys[1];
        SecretKey thirdKey = keys[2];
        byte[] output = new byte[input.length];
        if (operation == 1) {
            byte[] firstStep = useDES(input, firstKey, 1);
            byte[] secondStep = useDES(firstStep, secondKey, 2);
            output = useDES(secondStep, thirdKey, 1);
        } else if (operation == 2) {
            byte[] firstStep = useDES(input, thirdKey, 2);
            byte[] secondStep = useDES(firstStep, secondKey, 1);
            output = useDES(secondStep, firstKey, 2);
        }
        return output;
    }

    public byte[] XOR(byte[] input1, byte[] input2) {
        byte[] resultArray = new byte[8];
        for (int i = 0; i < 8; i++) {
            resultArray[i] = (byte) (input1[i] ^ input2[i]);
        }
        return resultArray;

    }

    public byte[] createByteArray(int hashCode) {
        byte[] firstArray = ByteBuffer.allocate(4).putInt(hashCode).array();
        byte[] secondArray = ByteBuffer.allocate(4).putInt(hashCode * 2).array();
        byte[] finalArray = new byte[8];
        int index = 0;
        for (int i = 0; i < 4; i++) {
            finalArray[index++] = firstArray[i];
        }
        for (int j = 0; j < 4; j++) {
            finalArray[index++] = secondArray[j];
        }
        return finalArray;
    }

    public SecretKey[] generateKey(String input, int operation) {
        SecretKey[] keys = null;
        int hashCode = input.hashCode();
        byte[] keyBytes = createByteArray(hashCode);
        SecretKey key = new SecretKeySpec(keyBytes, "DES");
        if (operation == 1) {
            keys = new SecretKey[1];
            keys[0] = key;
        } else if (operation == 2) {
            keys = new SecretKey[3];
            keys[0] = key;
            keys[1] = new SecretKeySpec(XOR(keyBytes, keyBytes), "DES");
            keys[2] = new SecretKeySpec(XOR(createByteArray(hashCode + 500), createByteArray(hashCode - 500)), "DES");
        }
        return keys;

    }

    public byte[] generateIV(String input) {
        int hashCode = input.hashCode();
        byte[] bytes = createByteArray(hashCode);
        return bytes;
    }


}
