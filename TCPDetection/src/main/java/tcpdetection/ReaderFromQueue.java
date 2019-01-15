package tcpdetection;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import javax.jms.Connection;
import javax.jms.ConnectionFactory;
import javax.jms.JMSException;
import javax.jms.MessageConsumer;
import javax.jms.Queue;
import javax.jms.Session;
import org.apache.activemq.ActiveMQConnection;
import org.apache.activemq.ActiveMQConnectionFactory;
import org.apache.activemq.BlobMessage;

public class ReaderFromQueue {

    ConnectionFactory connectionFactory;
    Connection connection;
    Session session;
    Queue destination;
    MessageConsumer consumer;

    String url, queue;

    ReaderFromQueue(String mqUrl, String q) throws JMSException, IOException {
        queue = q;
        url = mqUrl;

        connectionFactory = new ActiveMQConnectionFactory(url);
        connection = (ActiveMQConnection) connectionFactory.createConnection();
        connection.start();
        session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
        destination = session.createQueue(queue);
        consumer = session.createConsumer(destination);
    }

    public File readFile() {
        File tempFile = null;
        try {
            BlobMessage blobMessage = (BlobMessage) consumer.receive();

            String dir = "/tmp/";
            String PREFIX = blobMessage.getStringProperty("FILE.NAME");
            String SUFFIX = ".tmp";

            tempFile = File.createTempFile(dir + PREFIX, SUFFIX);
            tempFile.deleteOnExit();

            InputStream in = blobMessage.getInputStream();
            try (FileOutputStream out = new FileOutputStream(tempFile)) {
                byte[] buffer = new byte[1024];
                while (true) {
                    int bytesRead = in.read(buffer);
                    if (bytesRead == -1) {
                        break;
                    }

                    out.write(buffer, 0, bytesRead);
                }
                out.close();
            }
        } catch (JMSException ex) {
        } catch (IOException ex) {
        } finally {
            return tempFile;
        }
    }

    public void closeConnection() {
        try {
            connection.close();
        } catch (JMSException ex) {
        }
    }

    public void deleteFile(File tempFile) {
        tempFile.delete();
    }
}
