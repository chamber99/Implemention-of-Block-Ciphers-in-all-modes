import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Timer;

public class FileOps {
    private InputStream inputFileStream;
    private OutputStream outputFileStream;
    private String key;
    private String nonce;
    private String IV;

    private String inputFileName;
    private String outputFileName;
    private String modeName;
    private String cipherName;
    private String operationName;

    private long startTime;
    private long endTime;

    public FileOps(String inputFile, String outputFile, String keyFile) throws IOException {
        inputFileName = inputFile;
        outputFileName = outputFile;


        //inputFileStream = new FileInputStream(inputFile);

        //os = new FileOutputStream(outputFile);
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

    public void startTimer() {
        startTime = System.currentTimeMillis();
    }

    public void endTimer() {
        endTime = System.currentTimeMillis();
    }

    public String calculateRuntime() {
        String runTime = "";
        long difference = endTime - startTime;
        runTime = String.valueOf(difference);

        endTime = 0L;
        startTime = 0L;
        return runTime;
    }
    public byte[] readInputFile() throws IOException {
        return inputFileStream.readAllBytes();
    }

    public void writeOutputFile(byte[] content) throws IOException {
        outputFileStream.write(content);
    }

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














