package tcpdetection;

import java.io.File;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.Udp;
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

   // konstruktor
   Detector(String args[]) {
      for(int i = 0; i < args.length; i++)
         monitoredIP.add(args[i]);
   }

   public static long bytesToLong(byte[] bytes) {
        long b = ByteBuffer.wrap(bytes).getLong();
        return b;
    }

   // parsovanie pcap suboru
   public void run(File pcapFile) throws IOException {
      StringBuilder errbuf = new StringBuilder();
      Pcap pcap = Pcap.openOffline(pcapFile.getAbsolutePath(), errbuf);

      if(pcap == null)
      {
         System.out.println(errbuf);
         return;
      }

      PcapHeader hdr = new PcapHeader(JMemory.POINTER);
      JBuffer buf = new JBuffer(JMemory.POINTER);
      Ip4 ip = new Ip4();
      Udp udp = new Udp();
	  Ethernet eth = new Ethernet();
      int id = JRegistry.mapDLTToId(pcap.datalink());

      while(pcap.nextEx(hdr, buf) == Pcap.NEXT_EX_OK)
      {
         PcapPacket packet = new PcapPacket(hdr, buf);
         packet.scan(id);

         // zistenie typu transportneho protokolu
         byte protocol = buf.getByte(9);

         if(protocol == 6)
         {
            // ziskanie cielovej adresy
            byte[] d_IP = new byte[4];

            d_IP[0] = buf.getByte(16);
            d_IP[1] = buf.getByte(17);
            d_IP[2] = buf.getByte(18);
            d_IP[3] = buf.getByte(19);

            String dip = org.jnetpcap.packet.format.FormatUtils.ip(d_IP);

            // kontrola ci monitorujeme cielovu adresu
            boolean isMonitored = false;
            for(String i : monitoredIP)
            {
                if(i.equals(dip))
                {
                   isMonitored = true;
                   break;
                }
            }

            if(isMonitored)
            {
                // cielovy port
                byte[] d_port = new byte[8];

                d_port[6] = buf.getByte(22);
                d_port[7] = buf.getByte(23);

                long port = bytesToLong(d_port);

                String hash = dip + "_" + Long.toString(port);
                byte flags = buf.getByte(33);

                BitSet f = BitSet.valueOf(new byte[]{flags});
                boolean isSyn = f.get(1);
                boolean isFin =  f.get(0);

                if(monitor.containsKey(hash))
                {
                  if(isSyn)
                  {
                      long a = monitor.get(hash);
                      a++;
                      monitor.put(hash, a);
                  }

                  if(isFin)
                  {
                      long a = monitor.get(hash);
                      a--;
                      monitor.put(hash, a);
                  }
                } else {
                   monitor.put(hash, 0L);
                   ttl.put(hash, System.currentTimeMillis());

                   if(isSyn)
                   {
                      long a = monitor.get(hash);
                      a++;
                      monitor.put(hash, a);
                   }
                   if(isFin)
                   {
                      long a = monitor.get(hash);
                      a--;
                      monitor.put(hash, a);
                   }
                }
            }
        }
     }

     // detekcia
     for(Map.Entry<String, Long> entry : monitor.entrySet())
     {
        String key = entry.getKey();
        Long value = entry.getValue();

        if(value > THRESHOLD)
        {
           System.out.println("TCP flood alert for destination: " + key + " Value: " + Long.toString(value));
		   
		   try {
                String msg = "TCP flood alert for destination: " + key + " Value: " + Long.toString(value);
                Socket socket = new Socket("147.175.106.17", 9999);
                DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                output.writeUTF(msg);
                socket.close();
           } catch(IOException ex) {
                ex.printStackTrace();
			}
        }
     }

     for(Map.Entry<String, Long> entry : ttl.entrySet())
     {
        long currentTime = System.currentTimeMillis();

        TimeUnit unit = TimeUnit.SECONDS;
        long passedSeconds = unit.convert(currentTime - entry.getValue(), TimeUnit.MILLISECONDS);

        if(passedSeconds > TTL)
        {
           entry.setValue(currentTime);

           if(monitor.containsKey(entry.getKey()))
           {
             long a = monitor.get(entry.getKey());
             a = 0L;
             monitor.put(entry.getKey(), a);
           }
        }
     }

     pcap.close();
  }
}