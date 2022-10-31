import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Timer;

public class FileOps {
    // Instance variables
    private InputStream inputFileStream;
    private OutputStream outputFileStream;
    private String key;
    private String nonce;
    private String IV;
    private String inputFileName;
    private String outputFileName;
    private String OperationName;
    private String CipherName;
    private String ModeName;

    // Constructor
    public FileOps(String inputFile, String outputFile, String keyFile, String modeName, String cipherName, String operationName) throws IOException {
        inputFileName = inputFile;
        outputFileName = outputFile;
        OperationName = operationName;
        ModeName = modeName;
        CipherName = cipherName;
        inputFileStream = new FileInputStream(inputFile);
        File OutputFile = new File(outputFileName);
        outputFileStream = new FileOutputStream(outputFile);
        readKeyIvNonce(keyFile);
    }

    public String getKey() {
        return key;
    }

    public String getNonce() {
        return nonce;
    }

    public String getIV() {
        return IV;
    }

    // Stops the timer and creates/updates the log file.
    public void end(long runtime) {
        writeLog(inputFileName + " " + outputFileName + " " + OperationName + " " + CipherName + " " + ModeName + " " + runtime);

    }
    // Reads the bytes of input file.
    public byte[] readInputFile() throws IOException {
        byte[] inputArray = new byte[inputFileStream.available()];
        inputFileStream.read(inputArray);
        return inputArray;
    }

    // Creates/Updates the output file by using the content.
    public void writeOutputFile(byte[] content) throws IOException {
        outputFileStream.write(content);
    }

    // Reads the key file and splits the components.
    public void readKeyIvNonce(String keyFile) throws IOException {
        String[] allLines = readFile(keyFile);
        String result = "";
        for (String s : allLines) {
            result = result.concat(s);
        }

        String[] splitter = result.split("-");
        IV = splitter[0].trim();
        key = splitter[1].trim();
        nonce = splitter[2].trim();
    }

    // Creates/Updates run.log file by using the content.
    public void writeLog(String content) {
        File file = new File("run.log");
        if (file.isFile() && file.exists()) {
            try {
                content = "\n" + content;

                Files.write(Paths.get("run.log"), content.getBytes(), StandardOpenOption.APPEND);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            try {
                FileWriter writer = new FileWriter("run.log");
                writer.write(content);
                writer.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    // Reads files as string.
    public String[] readFile(String path) {
        try {
            int i = 0;
            int length = Files.readAllLines(Paths.get(path)).size();
            String[] results = new String[length];
            for (String line : Files.readAllLines(Paths.get(path))) {
                results[i++] = line;
            }
            return results;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

    }

}














