package tcpdetection;

import java.sql.*;

public class DBConn {
    private String Driver;
    private String Host;
    private String Database;
    private String Password;

    public DBConn(String Host, String Database, String Password) {
        this.Driver = "org.mariadb.jdbc.Driver";
        if (Host.contains("jdbc:mariadb://"))
            this.Host = Host;
        else 
            this.Host = "jdbc:mariadb://" + Host;
        this.Database = Database;
        this.Password = Password;
    }
    
    private Connection Connect() throws Exception {
        Class.forName(Driver);
        return DriverManager.getConnection(Host, Database, Password);
    }
    
    public void SendTCPFlood(String destination, long value) {
        try {
            String[] parts = destination.split(":");
            String ip = parts[0];
            int port = Integer.parseInt(parts[1]);

            Connection conn = Connect();
            System.out.println("[TCPDetection] Connected to DB");
            PreparedStatement statement = conn.prepareStatement("INSERT INTO tcp_flood (ip, port, value) VALUES (?,?,?)");
            statement.setString(1, ip);
            statement.setInt(2, port);
            statement.setLong(3, value);
            statement.execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
