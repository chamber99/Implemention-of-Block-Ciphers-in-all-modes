import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class FileOps {
    public void appendLine(String content) {
        String filename = "run.log";
        try {
            FileReader fileReader = new FileReader(filename);
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            List<String> list = bufferedReader.lines().collect(Collectors.toList());
            list.add(content);

            FileWriter fileWriter = new FileWriter(filename);
            BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);

            for (String s : list) {
                bufferedWriter.write(s);
            }


        } catch (IOException e) {
            throw new RuntimeException(e);

        }

        

    }

    public void writeFile(String name, String content) throws IOException {
        File file = new File(name);

        if (file.isFile() && file.exists()) {
            appendLine(content);
        } else {
            try {
                FileWriter writer = new FileWriter(name);
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














