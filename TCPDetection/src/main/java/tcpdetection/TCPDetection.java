package tcpdetection;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.jms.Connection;
import javax.jms.ConnectionFactory;
import javax.jms.MessageConsumer;
import javax.jms.Queue;
import javax.jms.Session;
import javax.jms.JMSException;
import org.apache.activemq.ActiveMQConnection;
import org.apache.activemq.ActiveMQConnectionFactory;
import org.apache.activemq.BlobMessage;

public class TCPDetection {

    public static void main(String[] args) throws IOException, JMSException {
        System.out.println("Monitoring adresses:");

        for (int i = 0; i < args.length; i++) {
            System.out.println(args[i]);
        }

        ReaderFromQueue reader = new ReaderFromQueue("tcp://147.175.98.24:61616", "PCAPS_TCP");
        File tempFile;
        Detector detector = new Detector(args);

        while ((tempFile = reader.readFile()) != null) {
            String fileName = tempFile.getName();
            System.out.println("File name: " + fileName);
            detector.run(tempFile);
        }

        reader.closeConnection();
    }
}
