package tcpdetection;

import java.io.File;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.protocol.lan.Ethernet;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.BitSet;
import java.nio.ByteBuffer;
import java.io.*;
import java.net.*;
import java.io.DataOutputStream;

public class Detector {
    private List<String> monitoredIP = new ArrayList<String>();

    // maximalna hranica
    private long THRESHOLD = 200;

    // casove okno
    private long TTL = 5;

    // cielova adresa+port : pocitadlo
    private HashMap<String, Long> monitor = new HashMap<String, Long>();

    // TTL pre jednotlive spojenia
    private HashMap<String, Long> ttl = new HashMap<String, Long>();
    
    // Trieda k pripojeniu k db
    // private DBConn db = new DBConn(--HOST--, --USER--, --PASS--);
    
    // konstruktor
    Detector(String args[]) {
        for (int i = 0; i < args.length; i++) {
            monitoredIP.add(args[i]);
        }
    }

    public static long bytesToLong(byte[] bytes) {
        long b = ByteBuffer.wrap(bytes).getLong();
        return b;
    }

    // parsovanie pcap suboru
    public void run(File pcapFile) throws IOException {
        StringBuilder errbuf = new StringBuilder();
        Pcap pcap = Pcap.openOffline(pcapFile.getAbsolutePath(), errbuf);

        if (pcap == null) {
            System.out.println(errbuf);
            return;
        }

        PcapHeader hdr = new PcapHeader(JMemory.POINTER);
        JBuffer buf = new JBuffer(JMemory.POINTER);
        int id = JRegistry.mapDLTToId(pcap.datalink());

        int parsed_packets = 0;
        int monitored_packets = 0;
        while (pcap.nextEx(hdr, buf) == Pcap.NEXT_EX_OK) {
            PcapPacket packet = new PcapPacket(hdr, buf);
            packet.scan(id);

            Ip4 ip = new Ip4();
            Tcp tcp = new Tcp();

            if (!packet.hasHeader(ip) || !packet.hasHeader(tcp)) {
                continue;
            }

            parsed_packets++;

            // ziskanie zdrojovej a cielovej adresy
            byte[] s_ip = new byte[4];
            s_ip = packet.getHeader(ip).source();
            String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(s_ip);

            byte[] d_ip = new byte[4];
            d_ip = packet.getHeader(ip).destination();
            String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(d_ip);

            // System.out.println("Packet " + sourceIP + " -> " + destinationIP + ", size: " + Integer.toString(packet.getTotalSize()));

            // kontrola ci monitorujeme cielovu adresu
            boolean isMonitored = false;
            for (String i : monitoredIP) {
                if (i.equals(destinationIP)) {
                    isMonitored = true;
                    break;
                }
            }

            if (!isMonitored) {
                continue;
            }

            monitored_packets++;

            String hash = destinationIP + "_" + Integer.toString(tcp.destination());

            if (monitor.containsKey(hash)) {
                if (tcp.flags_SYN()) {
                    long a = monitor.get(hash);
                    a++;
                    monitor.put(hash, a);
                }

                if (tcp.flags_FIN()) {
                    long a = monitor.get(hash);
                    a--;
                    monitor.put(hash, a);
                }
            } else {
                monitor.put(hash, 0L);
                ttl.put(hash, System.currentTimeMillis());

                if (tcp.flags_SYN()) {
                    long a = monitor.get(hash);
                    a++;
                    monitor.put(hash, a);
                }
                if (tcp.flags_FIN()) {
                    long a = monitor.get(hash);
                    a--;
                    monitor.put(hash, a);
                }
            }
        }

        System.out.println(">> Parsed " + pcapFile.getPath() + " (packets: " + Integer.toString(parsed_packets) + ", monitored: " + Integer.toString(monitored_packets) + ")");

        // detekcia
        for (Map.Entry<String, Long> entry : monitor.entrySet()) {
            String destination = entry.getKey();
            Long value = entry.getValue();

            if (value > THRESHOLD) {
                System.out.println("[+] TCP flood alert for destination: " + destination + ", value: " + Long.toString(value));
                //db.SendTCPFlood(key, value);
            }
        }

        for (Map.Entry<String, Long> entry : ttl.entrySet()) {
            long currentTime = System.currentTimeMillis();

            TimeUnit unit = TimeUnit.SECONDS;
            long passedSeconds = unit.convert(currentTime - entry.getValue(), TimeUnit.MILLISECONDS);

            if (passedSeconds > TTL) {
                entry.setValue(currentTime);

                if (monitor.containsKey(entry.getKey())) {
                    long a = monitor.get(entry.getKey());
                    a = 0L;
                    monitor.put(entry.getKey(), a);
                }
            }
        }

        pcap.close();
    }
}
