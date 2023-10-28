import java.net.*;
import java.util.Random;

public class Client {

    public static final int MIN_PORT = 1;
    public static final int MAX_PORT = 65535;

    public static void main(String[] args) {
        Client.argumentValidation(args);

        String resolverIP = args[0];
        int resolverPort = Integer.parseInt(args[1]);
        String name = args[2];
        int timeoutInSecs = Integer.parseInt(args[3]);
        int type = getTypeAsInt(args[4]);

        DNSMessage dnsQuery = Client.constructDNSQuery(name, type);

        try {
            // Prepare a UDP socket
            DatagramSocket socket = new DatagramSocket();
            socket.setSoTimeout(timeoutInSecs * 1000);

            // Prepare a UDP packet with data to send
            byte[] dnsQueryBytes = dnsQuery.toByteArray();
            InetAddress resolverAddress = InetAddress.getByName(resolverIP);
            DatagramPacket sendPacket = new DatagramPacket(dnsQueryBytes, dnsQueryBytes.length, resolverAddress, resolverPort);

            // Send the DNS query packet
            socket.send(sendPacket);

            // Prepare a UDP packet to receive data into
            byte[] responseBuffer = new byte[512]; // will be trucncated this no overflow is possible
            DatagramPacket receivePacket = new DatagramPacket(responseBuffer, responseBuffer.length);

            // Wait for the response from the DNS resolver
            socket.receive(receivePacket);

            byte[] dnsResponseBytes = receivePacket.getData();

            // Close the socket
            socket.close();

            DNSMessage dnsResponse = new DNSMessage(dnsResponseBytes);

            Client.parseAndDisplayResponse(dnsResponse, args);

        } catch (SocketTimeoutException e) {
            System.out.println("Error: Timeout reached while waiting for resolvers's response.");
            System.out.println("Timeout = " + timeoutInSecs + "s.");
            System.exit(1);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static int getTypeAsInt(String type) {
        type = type.toLowerCase();
        switch(type) {
            case ("a"):
                return 1;
            case ("ns"):
                return 2;
            case ("mx"):
                return 15;
            case ("ptr"):
                return 12;
            case ("cname"):
                return 5;
            default:
                // undefined functionality for type cant get here aas already error checked
                return 0;
        }
    }

    private static void argumentValidation(String[] args) {
        // BASIC ARGUEMENT VALIDATION
        // Check that the necessary number of arguments are provided
        if (args.length != 5) {
            System.err.println("Error: invalid number of arguments");
            Client.usageMessage();
            System.exit(1);
        }

        // Check that its type A ip addresss
        if (!Client.isValidTypeAIP(args[0])) {
            System.err.println("Error: invalid type A ip address");
            Client.usageMessage();
            System.exit(1);
        }

        // Check port number is in the range
        try {
            int resolverPort = Integer.parseInt(args[1]);
            if (resolverPort < Client.MIN_PORT || resolverPort > Client.MAX_PORT) {
                System.err.println("Error: invalid port number, should be between 1024 and 65535");
                Client.usageMessage();
                System.exit(1);
            }
        } catch (NumberFormatException e) {
            System.err.println("Error: invalid port number, it should be a valid integer");
            Client.usageMessage();
            System.exit(1);
        }

        // currently isnt checking if domain name is valid

        // Check timeout number is valid
        try {
            int timeoutInSecs = Integer.parseInt(args[3]);
            if (timeoutInSecs <= 0) {
                System.err.println("Error: invalid timeout number, should be greater then 0");
                Client.usageMessage();
                System.exit(1);
            }
        } catch (NumberFormatException e) {
            System.err.println("Error: invalid timeout number, it should be a valid integer");
            Client.usageMessage();
            System.exit(1);
        }

        // check type is valid
        String type = args[4].toLowerCase();
        if (!((type.equals("mx")) || (type.equals("ptr")) || (type.equals("a")) || (type.equals("ns")) || (type.equals("cname")))) {
            // inlvaid type
            System.err.println("Error: invalid type, it should be MX, PTR, A, NS, CNAME.");
            Client.usageMessage();
            System.exit(1);
        }
    }

    private static void parseAndDisplayResponse(DNSMessage dnsResponse, String[] args) {

        if (dnsResponse.header.rcode == 3) {
            System.err.println("Error: server can't find " + dnsResponse.questions.get(0).qName);
            System.exit(1);
        } else if (dnsResponse.header.rcode != 0) {
            // error in response
            System.out.println("Error: Not a valid response: RCODE = " + dnsResponse.header.rcode);
            System.exit(1);
        }

        int ancount = dnsResponse.answers.size();
        if (ancount == 0) {
            System.err.println("Error: server can't find " + dnsResponse.questions.get(0).qName);
            System.exit(1);
        }

        System.out.println("Is response authoritative? " + (dnsResponse.header.aa ? "Yes" : "No"));
        System.out.println("Is response truncated? " + (dnsResponse.header.tc ? "Yes" : "No"));
        System.out.println("Answers: ");

        for (DNSResourceRecord answer : dnsResponse.answers) {
            if (answer.type != dnsResponse.questions.get(0).qType) {
                continue;
            }
            switch(answer.type) {
                case 1:
                    // type A record
                    System.out.println(Client.typeIPAnswer(answer.rdata));
                    break;
                case 2:
                    // type NS record
                    System.out.println(Client.typeDomainAnswer(answer.rdata, dnsResponse));
                    break;
                case 5:
                    // type cname
                    System.out.println(Client.typeDomainAnswer(answer.rdata, dnsResponse));
                    break;
                case 12:
                    // type ptr
                    System.out.println(Client.typeDomainAnswer(answer.rdata, dnsResponse));
                    break;
                case 15:
                    // type mx
                    byte[] rdataNew = new byte[answer.rdata.length - 2];
                    int preferenceValue = (answer.rdata[0] << 8) | (answer.rdata[1]);
                    System.arraycopy(answer.rdata, 2, rdataNew, 0, rdataNew.length);
                    System.out.println("Preference value = " + preferenceValue + ". Mailserver = " + Client.typeDomainAnswer(rdataNew, dnsResponse));
                    break;
                default:
                    // undefined functionality for that type of answer
                    break;
            }
        }
    }


    public static boolean isValidTypeAIP(String ipString) {
        String[] parts = ipString.split("\\.");

        if (parts.length != 4) {
            return false;
        }

        for (String number : parts) {
            int val = Integer.parseInt(number);
            if (val < 0 || val > 255) {
                return false;
            }
        }
        return true;
    }

    private static DNSMessage constructDNSQuery(String name, int type) {
        // DNS Header
        Random randomGenerator = new Random();
        int queryID = randomGenerator.nextInt(65536); // Random 16 bit number for ID

        // (make sure true when testing public servers and false for using Resolver.java)
        boolean recursionDesired = false;

        // int id, boolean qr, int opcode, boolean aa, boolean tc, boolean rd, boolean ra, int rcode
        DNSHeader header = new DNSHeader(queryID, false, 0, false, false, recursionDesired, false, 0);

        //DNS Question
        // Type 'type' query
        // Class IN
        DNSQuestion question = new DNSQuestion(name, type, 1);

        DNSMessage dnsQuery = new DNSMessage(header);
        dnsQuery.addQuestion(question);

        return dnsQuery;
    }

    public static void usageMessage() {
        System.err.println("Usage: java Client resolver_ip resolver_port name timeout type");
    }

    public static String typeIPAnswer(byte[] rdata) {
        StringBuilder ipAddress = new StringBuilder();
        int index = 0;

        for (int j = 0; j < 4; j++) {
            if (j > 0) {
                ipAddress.append(".");
            }
            ipAddress.append(rdata[index++] & 0xFF);
        }

        return ipAddress.toString();
    }

    private static String typeDomainAnswer(byte[] rdata, DNSMessage dnsResponse) {
        return dnsResponse.extractDomainFromRData(rdata);
    }
}
