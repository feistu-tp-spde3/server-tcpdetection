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
            Connection conn = Connect();
            PreparedStatement statement = conn.prepareStatement("INSERT INTO TCPFLOODS VALUES (?,?,?,?)");
            statement.setNull(1, java.sql.Types.INTEGER);
            statement.setString(2, destination);
            statement.setLong(3, value);
            statement.setNull(4, java.sql.Types.TIMESTAMP);
            statement.execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void SendUDPFlood(String fromDestination, String toDestination) {
        try {
            Connection conn = Connect();
            PreparedStatement statement = conn.prepareStatement("INSERT INTO UDPFLOODS VALUES (?,?,?,?)");
            statement.setNull(1, java.sql.Types.INTEGER);
            statement.setString(2, fromDestination);
            statement.setString(3, toDestination);
            statement.setNull(4, java.sql.Types.TIMESTAMP);
            statement.execute();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
