import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

public class PerformanceReportScript {
    private static final String LOCAL_RESOLVER_IP = "127.0.0.1";
    private static final String GOOGLE_PUBLIC_DNS_IP = "8.8.8.8";
    private static final String CLOUDFARE_PUBLIC_DNS_IP = "1.1.1.1";
    private static final int PUBLIC_DNS_PORT = 53;
    private static final int LOCAL_RESOLVER_PORT = 5300;

    private static final int TIMEOUT = 5;
    private static final String QUERY_TYPE = "A";

    public static void main(String[] args) throws Exception {
        List<String> domains = readDomainsFromFile("resolvableDomains.txt");

        int port = LOCAL_RESOLVER_PORT;
        // int port = PUBLIC_DNS_PORT;
        String IP = LOCAL_RESOLVER_IP;
        // String IP = CLOUDFARE_PUBLIC_DNS_IP;
        // String IP = GOOGLE_PUBLIC_DNS_IP;

        for (String domain : domains) {
            String[] clientArgs = {IP, String.valueOf(port), domain, String.valueOf(TIMEOUT), QUERY_TYPE};
            Client.main(clientArgs);
        }
    }

    private static List<String> readDomainsFromFile(String filename) throws Exception {
        List<String> domains = new ArrayList<>();

        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = br.readLine()) != null) {
                domains.add(line.trim());
            }
        }

        return domains;
    }
}
