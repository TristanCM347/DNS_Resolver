import java.io.*;
import java.net.*;
import java.util.regex.*;
import java.util.Random;
import java.util.Stack;

public class Resolver {

    public static final int MIN_PORT = 1024;
    public static final int MAX_PORT = 65535;

    public static void main(String[] args) throws IOException {
        Resolver.argumentValidation(args);

        int resolverPort = Integer.parseInt(args[0]);
        int timeoutInSecs = Integer.parseInt(args[1]);

        try (DatagramSocket resolverClientSocket = new DatagramSocket(resolverPort)) {;
            byte[] receiveData = new byte[512];
            System.out.println("Listening: ");
            while (true) {
                // network stack of the operating system takes care of the queuing process automatically.
                DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
                resolverClientSocket.receive(receivePacket);

                byte[] dnsQueryBytes = receivePacket.getData();
                DNSMessage dnsQuery = new DNSMessage(dnsQueryBytes);

                System.out.println("Received query from Client.");

                DNSMessage dnsResponse = Resolver.resolveDomainName(dnsQuery, timeoutInSecs);

                byte[] dnsResponseBytes = dnsResponse.toByteArray();
                DatagramPacket sendPacket = new DatagramPacket(dnsResponseBytes, dnsResponseBytes.length, receivePacket.getAddress(), receivePacket.getPort());
                resolverClientSocket.send(sendPacket);

                System.out.println("Returned response to Client.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void argumentValidation(String[] args) {
        // BASIC ARGUEMENT VALIDATION
        if (args.length != 2) {
            System.err.println("Error: invalid number of arguments");
            Resolver.usageMessage();
            System.exit(1);
        }

        try {
            int resolverPort = Integer.parseInt(args[0]);
            if (resolverPort < Resolver.MIN_PORT && resolverPort > Resolver.MAX_PORT) {
                System.err.println("Error: invalid port number, should be between 1024 and 65535");
                Resolver.usageMessage();
                System.exit(1);
            }
        } catch (NumberFormatException e) {
            System.err.println("Error: invalid port number, it should be a valid integer");
            Resolver.usageMessage();
            System.exit(1);
        }

        try {
            int resolverPort = Integer.parseInt(args[1]);
            if (resolverPort <= 0) {
                System.err.println("Error: invalid timeout number, should be greater then 0");
                Resolver.usageMessage();
                System.exit(1);
            }
        } catch (NumberFormatException e) {
            System.err.println("Error: invalid timeout number, it should be a valid integer");
            Resolver.usageMessage();
            System.exit(1);
        }


    }

    private static Stack<String> loadRootServers() throws IOException {
        Stack<String> rootServers = new Stack<>();
        try (BufferedReader reader = new BufferedReader(new FileReader("named.root"))) {
            String line;

            while ((line = reader.readLine()) != null) {
                Matcher matcher = Pattern.compile("^(.+?)\\s+\\d+\\s+IN\\s+A\\s+(.+)$").matcher(line);

                if (matcher.matches()) {
                    rootServers.push(matcher.group(2));
                }
            }
        }
        return rootServers;
    }

    private static DNSMessage resolveDomainName(DNSMessage dnsQuery, int timeoutInSecs) throws IOException {
        // Initially, contact a root server
        // Load the root server ip addresses.
        Stack<String> slist = Resolver.loadRootServers();

        // this dns message is only returned if allt he queries are exhausted and the last one is its error flag set
        DNSMessage dnsResponse = null;

        while (!slist.isEmpty()) {
            String serverIP = slist.pop();

            // contact the server and get response in bytes
            byte[] dnsResponseBytes = Resolver.contactServer(dnsQuery.toByteArray(), serverIP, timeoutInSecs);

            if (dnsResponseBytes.length == 0) {
                // something went wrong with the query to server (e.g. timeout)
                continue;
                // go to next server
            }

            dnsResponse = new DNSMessage(dnsResponseBytes);

            // Check the error message
            if (dnsResponse.header.rcode == 2) {
                // server failure
                // continue query process with other servers in SLIST
                continue;
            } else if (dnsResponse.header.rcode != 0) {
                // terminate resolution process and forward to client
                return dnsResponse;
            }

            // assumes only 1 question
            // check if it contains any valid answers
            for (DNSResourceRecord answer : dnsResponse.answers) {
                if (dnsResponse.questions.get(0).qType == answer.type) {
                    // question type equals answer type
                    return dnsResponse;
                }
            }

            // check if theres cnames
            for (DNSResourceRecord answer : dnsResponse.answers) {
                if (dnsResponse.questions.get(0).qType == 1 && answer.type == 5) {
                    // if question is type and and answer is cname
                    // create a new query for the new name
                    // start search all over again from roots
                    String newQNAME = dnsResponse.extractDomainFromRData(answer.rdata);
                    return Resolver.resolveDomainName(constructDNSQueryQuestionChanged(dnsQuery, newQNAME), timeoutInSecs);
                }
            }

            int amountReferrals = 0;
            // no valid answer thus check for referals that are type A
            for (DNSResourceRecord additional : dnsResponse.additionals) {
                if (additional.type == 1) {
                    // A
                    // the rdata section is a byte array of numbers (typeA)
                    // add the ip address to the slist stack
                    slist.push((additional.rdata[0] & 0xFF) + "." + (additional.rdata[1] & 0xFF) + "." + (additional.rdata[2] & 0xFF) + "." + (additional.rdata[3] & 0xFF));
                    amountReferrals++;
                }
            }

            // if theres no server referals go find ips of the domains in authority section
            // then add to slist
            if (amountReferrals == 0) {
                System.out.println("Now resolving authority nameservers for IP addresses.");
                for (DNSResourceRecord authority : dnsResponse.authorities) {
                    if (authority.type == 2) {
                        String name = dnsResponse.extractDomainFromRData(authority.rdata);
                        DNSMessage authorityQuery = Resolver.constructDNSQuery(name, 1);
                        DNSMessage authorityResponse = Resolver.resolveDomainName(authorityQuery, timeoutInSecs);
                        for (DNSResourceRecord answer : authorityResponse.answers) {
                            if (answer.type == 1) {
                                String authortiesIp = Client.typeIPAnswer(answer.rdata);
                                slist.push(authortiesIp);
                                System.out.println("Authority nameservers IP = " + authortiesIp);
                            }
                        }
                    }
                }
            }
        }

        // this means no answer was found
        return constructDNSResponseNoAnswers(dnsQuery);
    }

    private static byte[] contactServer(byte[] dnsQuery, String serverIP, int timeoutInSecs) {
        System.out.println("Contacting server: " + serverIP);
        try {
            DatagramSocket resolverServerSocket = new DatagramSocket();
            resolverServerSocket.setSoTimeout(timeoutInSecs * 1000);

            InetAddress serverAddress = InetAddress.getByName(serverIP);
            DatagramPacket sendPacket = new DatagramPacket(dnsQuery, dnsQuery.length, serverAddress, 53);

            resolverServerSocket.send(sendPacket);

            byte[] responseBuffer = new byte[512];
            DatagramPacket receivePacket = new DatagramPacket(responseBuffer, responseBuffer.length);

            resolverServerSocket.receive(receivePacket);

            resolverServerSocket.close();

            byte[] dnsResponseBytes = receivePacket.getData();

            // Return the response
            return dnsResponseBytes;
        } catch (SocketTimeoutException e) {
            System.out.println("Error: Timeout reached while waiting for server's response. Timeout = " + timeoutInSecs + "s.");
            System.out.println("Skipping server.");
            return new byte[0];
        } catch (Exception e) {
            e.printStackTrace();
            return new byte[0];
        }
    }

    // for debugging
    public static void byteArrayToHex(byte[] byteArray) {
        StringBuilder hex = new StringBuilder(byteArray.length * 2);
        for(byte b : byteArray)
            hex.append(String.format("%02x", b & 0xFF));
        System.out.println(hex.toString());
    }

    // creates exact copy of inputed dns message accept it has qr field = response
    private static DNSMessage constructDNSResponseNoAnswers(DNSMessage dnsMessage) {
        // convert the dns message to a byte array so we can create a new instance
        // / copy of the dns message so we can return with the response field checked
        byte[] dnsMessageBytes = dnsMessage.toByteArray();
        DNSMessage dnsResponse = new DNSMessage(dnsMessageBytes);
        dnsResponse.header.qr = true;

        return dnsResponse;
    }

    // assumes one question
    // cahnges only the question name
    private static DNSMessage constructDNSQueryQuestionChanged(DNSMessage dnsMessage, String qName) {
        // convert the dns message to a byte array so we can create a new instance
        byte[] dnsMessageBytes = dnsMessage.toByteArray();
        DNSMessage dnsQuery = new DNSMessage(dnsMessageBytes);
        dnsQuery.questions.get(0).qName = qName;
        return dnsQuery;
    }

    public static void usageMessage() {
        System.err.println("Usage: resolver port timeout");
    }

    private static DNSMessage constructDNSQuery(String name, int type) {
        // DNS Header
        Random randomGenerator = new Random();
        int queryID = randomGenerator.nextInt(65536); // Random 16 bit number for ID
        // Standard Query
        // Recursion Disabled
        // No Recursive services Available
        // No Error
        // int id, boolean qr, int opcode, boolean aa, boolean tc, boolean rd, boolean ra, int rcode
        DNSHeader header = new DNSHeader(queryID, false, 0, false, false, false, false, 0);

        //DNS Question
        // Type 'type' query
        // Class IN
        DNSQuestion question = new DNSQuestion(name, type, 1);

        DNSMessage dnsQuery = new DNSMessage(header);
        dnsQuery.addQuestion(question);

        return dnsQuery;
    }
}