package ca.ubc.cs317.dnslookup;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.*;

public class DNSQueryHandler {

    private static final int DEFAULT_DNS_PORT = 53;
    private static DatagramSocket socket;
    private static boolean verboseTracing = false;

    private static final Random random = new Random();

    /**
     * Sets up the socket and set the timeout to 5 seconds
     *
     * @throws SocketException if the socket could not be opened, or if there was an
     *                         error with the underlying protocol
     */
    public static void openSocket() throws SocketException {
        socket = new DatagramSocket();
        socket.setSoTimeout(5000);
    }

    /**
     * Closes the socket
     */
    public static void closeSocket() {
        socket.close();
    }

    /**
     * Set verboseTracing to tracing
     */
    public static void setVerboseTracing(boolean tracing) {
        verboseTracing = tracing;
    }

    /**
     * Builds the query, sends it to the server, and returns the response.
     *
     * @param message Byte array used to store the query to DNS servers.
     * @param server  The IP address of the server to which the query is being sent.
     * @param node    Host and record type to be used for search.
     * @return A DNSServerResponse Object containing the response buffer and the transaction ID.
     * @throws IOException if an IO Exception occurs
     */
    public static DNSServerResponse buildAndSendQuery(byte[] message, InetAddress server,
                                                      DNSNode node) throws IOException {
        // TODO (PART 1): Implement this
        //setup header
        int id = random.nextInt(0xffff);
//        System.out.println(String.format("0x%04X", id));
        if (verboseTracing) {
            System.out.println("\n\n");
            System.out.printf("Query ID:     %s %s  %s --> %s\n", id, node.getHostName(), node.getType(), server.getHostAddress());
        }

        //id
        message[0] = (byte) ((id & 0xff00) >> 8);
        message[1] = (byte) (id & 0x00ff);
        //1qr,4 opcode, 1AA,1TC,1RD,1RA, 3 Z, 4 r code
        message[2] = (byte) 0;
        message[3] = (byte) 0;
        //q count
        message[4] = (byte) 0;
        message[5] = (byte) 1;
        //a count
        message[6] = (byte) 0;
        message[7] = (byte) 0;
        //ns count
        message[8] = (byte) 0;
        message[9] = (byte) 0;
        //arcount
        message[10] = (byte) 0;
        message[11] = (byte) 0;

        int byteOffset = 12;
        //dns question
        List<String> nameClasses = breakHostnameIntoClass(node);
        for (String name : nameClasses) {
//            System.out.println(name);
            message[byteOffset] = (byte) name.length();
            byteOffset++;
            for (char c : name.toCharArray()) {
                message[byteOffset] = (byte) c;
                byteOffset++;
            }
        }
        //signal end of fqdn
        message[byteOffset] = (byte) 0;
        byteOffset++;
        //q type
        message[byteOffset] = (byte) 0;
        byteOffset++;
        message[byteOffset] = (byte) node.getType().getCode();
        byteOffset++;
        //q class
        message[byteOffset] = (byte) 0;
        byteOffset++;
        message[byteOffset] = (byte) 1;
        byteOffset++;


        DatagramPacket queryPacket = new DatagramPacket(message, byteOffset, server, DEFAULT_DNS_PORT);
        socket.send(queryPacket);
//        System.out.println("packet sent");
        //clear buffer for receive
        clearMessageBuffer(message);
        byte[] replyBytes = new byte[1024];
        DatagramPacket replyPacket = new DatagramPacket(replyBytes, replyBytes.length, server, DEFAULT_DNS_PORT);
        //receive response
        socket.setSoTimeout(2000);
        int attempts = 0;
        while (bufferIsEmpty(replyBytes) && attempts < 3) {
            try {
                attempts++;
                socket.receive(replyPacket);
            } catch (SocketTimeoutException ignored) {
                System.out.println("time out");
            }
        }
        if (bufferIsEmpty(replyBytes)) {
            System.err.println("socket timed out while receiving");
        }
        return new DNSServerResponse(ByteBuffer.wrap(replyPacket.getData()), id);
    }

    //breaks the hostname in dnsnode into domain name classes: for example, www.google.com will be broken
    //into string["www","google","com"]
    private static List<String> breakHostnameIntoClass(DNSNode node) {
        List<String> res = new ArrayList<>();
        String classname = "";
        for (int i = 0; i < node.getHostName().length(); i++) {
            if (node.getHostName().charAt(i) == '.') {
                res.add(classname);
                classname = "";
            } else {
                classname += node.getHostName().charAt(i);
            }
        }
        res.add(classname);
        return res;
    }

    private static boolean bufferIsEmpty(byte[] buf) {
        boolean ans = true;
        for (byte b : buf) {
            if (b != 0) {
                ans = false;
                break;
            }
        }
        return ans;
    }

    /**
     * Decodes the DNS server response and caches it.
     *
     * @param transactionID  Transaction ID of the current communication with the DNS server
     * @param responseBuffer DNS server's response
     * @param cache          To store the decoded server's response
     * @return A set of resource records corresponding to the name servers of the response.
     */
    public static Set<ResourceRecord> decodeAndCacheResponse(int transactionID, ByteBuffer responseBuffer,
                                                             DNSCache cache) {
        // TODO (PART 1): Implement this
        byte[] message = responseBuffer.array();
        Set<ResourceRecord> resourceRecordsToReturn = new HashSet<>();
//        System.out.println("printing response in decode:");

        int index = 0;
        //check if there is anything in the buffer
        if (message[0] == (byte) ((transactionID & 0xff00) >> 8) && message[1] == (byte) (transactionID & 0x00ff)) {
            index += 3;
            //we are going to check if server returns error message, if so, we return empty set
            if ((message[index] & 0xf) != 0) {
                System.out.println("error " + (message[index] & 0xf));
                return null;
            }
            index += 1;
            index += 2;

            //now we are at answer count in header
            int numAnswers = (message[index] << 8) + message[index + 1];
            index += 2;
            //now we are at ns count in header
            int numNameServers = (message[index] << 8) + message[index + 1];
            index += 2;
            //now we are at ar count
            int numar = (message[index] << 8) + message[index + 1];
            index += 2;

            //now we are at start of query name. we arent using the name for now, just traversing to increment the index
            StringBuilder qName = new StringBuilder();
            index = traverseTextAnswer(message, index, qName);
            index += 4;

            //now we are at start of first answer
            //we will traverse every answer, and call helper function to create ResourceRecord instances according to whether
            for (int i = 0; i < numAnswers + numNameServers; i++) {
                index = parseAnswer(message, index, resourceRecordsToReturn);
            }
            //now we are at start of AR
            for (int i = 0; i < numar; i++) {
                index = parseAnswer(message, index, resourceRecordsToReturn);
            }

            ArrayList<ResourceRecord> l = new ArrayList<>(resourceRecordsToReturn);
            l.sort(new Comparator<ResourceRecord>() {
                @Override
                public int compare(ResourceRecord o1, ResourceRecord o2) {
                    if (o1.getType() == o2.getType()) {
                        return 0;
                    }
                    if (o1.getType() == RecordType.NS) {
                        return -1;
                    }
                    if (o1.getType() == RecordType.A && o2.getType() == RecordType.AAAA) {
                        return -1;
                    }
                    return 1;
                }
            });
            int ns = 0;
            for (ResourceRecord r : l) {
                if (r.getType() != RecordType.NS) {
                    break;
                }
                ns++;
            }
            if (verboseTracing) {
                System.out.printf("Response ID: %s Authoritative = %s\n", transactionID, resourceRecordsToReturn.size() == 0);
                System.out.printf("  Nameservers (%s)\n", ns);
            }

            boolean flag = false;
            for (ResourceRecord r : l) {
                if (r.getType() != RecordType.NS && !flag) {
                    if (verboseTracing) {
                        System.out.printf("  Additional Information (%s)\n", l.size() - ns);
                    }
                    flag = true;
                }
                if (verboseTracing) {
                    verbosePrintResourceRecord(r, r.getType().getCode());
                }
                cache.addResult(r);
            }
        } else {
            System.out.println("no valid response (transaction id dont match)");
        }
        return resourceRecordsToReturn;
    }

    private static int parseAnswer(byte[] message, int index, Set<ResourceRecord> set) {
        StringBuilder name = new StringBuilder();
        index = traverseTextAnswer(message, index, name);

        //now we are at type
        int type = (message[index] & 0xff << 8) + (message[index + 1] & 0xff);
        index += 2;
        //now we are at class
        int QClass = (message[index] & 0xff << 8) + (message[index + 1] & 0xff);
        index += 2;
        int ttl = ((message[index] & 0xff) << 24) + ((message[index + 1] & 0xff) << 16) + ((message[index + 2] & 0xff) << 8) + (message[index + 3]);
        index += 4;
        int dataLength = (message[index] & 0xff << 8) + (message[index + 1] & 0xff);
        index += 2;

        if (type == RecordType.A.getCode() || type == RecordType.AAAA.getCode()) {
            //address answer
            int numbytes = 4;
            if (type == RecordType.AAAA.getCode()) {
                numbytes = 16;
            }
            byte[] ip = new byte[numbytes];
            System.arraycopy(message, index, ip, 0, numbytes);
            try {
                set.add(new ResourceRecord(name.toString(), RecordType.getByCode(type), ttl, InetAddress.getByAddress(ip)));
            } catch (UnknownHostException e) {
                System.err.println("adding resource record failed because InetAddress v6 cannot be resolved");
                throw new RuntimeException(e);
            }
        } else if (type == RecordType.NS.getCode() || type == RecordType.CNAME.getCode()) {
            StringBuilder textAnswer = new StringBuilder();
            traverseTextAnswer(message, index, textAnswer);
//            System.out.println("next name server: " + nextNameServer);
            set.add(new ResourceRecord(name.toString(), RecordType.getByCode(type), ttl, textAnswer.toString()));
        }
        index += dataLength;
        return index;
    }

    /**
     * Formats and prints record details (for when trace is on)
     *
     * @param record The record to be printed
     * @param rtype  The type of the record to be printed
     */
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    private static void printMessgae(byte[] message, int highlightposition) {
        int column = 0;
        for (int i = 0; i < message.length; i++) {
            if (i == highlightposition) {
                System.out.print("HERE|");
            }
            System.out.print(String.format("%02X", message[i]));

            column++;
            if (column == 2) {
                System.out.print("\n");
                column = 0;
            }
        }
    }

    //clear byte buffer
    private static void clearMessageBuffer(byte[] buff) {
        Arrays.fill(buff, (byte) 0);
    }

    //traverse a xxx.xxx.xxx name, including pointers, saves that text to the StringBuilder, and returns what the index should be set to.
    private static int traverseTextAnswer(byte[] message, int index, StringBuilder name) {
        int finalIndex = index;
        int classNumber = (message[index] & 0xff);
        boolean isLiteral = false; //this is here for the odd case where a pointer c0 points to index c0, without
        //this check the program thinks the new index location is also a pointer.
        while (classNumber != 0) {
            if (classNumber == 0xc0 && !isLiteral) {
                //compressed name
                index = message[index + 1] & 0xff;
                classNumber = (message[index] & 0xff);
                if (classNumber == 0xc0) {
                    isLiteral = true;
                }
            } else {
                //read normally
                index++;
                for (int i = 0; i < classNumber; i++) {
                    name.append((char) message[index]);
                    index++;
                }
                name.append(".");
                classNumber = (message[index] & 0xff);
            }
        }
        if (name.length() > 0) {
            name.deleteCharAt(name.length() - 1);
        }
//        System.out.println(name);
        //calculate final index;
        int compressed = 0;
        while (message[finalIndex] != 0) {
            if ((message[finalIndex] & 0xff) == 0xc0) {
                compressed = 1;
            }
            finalIndex++;
        }
        if (compressed == 0) {
            finalIndex++;
        } //to get over the 00 byte indicating end of string

        return finalIndex;
    }

//    f.gtld-servers.net

    private static void printRecords(Set<ResourceRecord> set) {
        for (ResourceRecord r : set) {
            System.out.printf("%-30s %-5s %-8d %s\n", r.getHostName(),
                    r.getType(), r.getTTL(), r.getTextResult());
        }
    }


}


