import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class FileOps {
        public void appendLine(String filename, String content){
            // do stuff
        }

        public void writeFile(String name,String content){
            String file_name = name+".txt";
            File file = new File(file_name);

            if(file.isFile() && file.exists()){

            }else{

            }


//            try {
//                FileWriter writer = new FileWriter(file_name);
//                writer.write(content);
//                writer.close();
//            } catch (IOException e) {
//                e.printStackTrace();
//            }
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














