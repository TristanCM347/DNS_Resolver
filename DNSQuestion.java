import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class DNSQuestion {
    public String qName; // the dot on the end must be removed before being stored here
    public int qType;
    public int qClass;

    // for making domain question
    public DNSQuestion(int index, byte[] dnsMessageBytes) {
        // A pointer can't be used in the QNAME field of the question section
        // because there is no prior data in the message that it could point to.

        StringBuilder stringBuilder = new StringBuilder();
        // assumes it cant be a blank question thus the first byte of the question
        // section is always a label length due to check before
        while (true) {
            int labelLength = dnsMessageBytes[index++];
            // Extract the characters for this label
            for (int i = 0; i < labelLength; i++) {
                stringBuilder.append((char) dnsMessageBytes[index++]);
            }
            if (dnsMessageBytes[index] == 0x00) {
                index++;
                break;
            } else {
                // its the next label lenght
                stringBuilder.append(".");
            }
        }

        qName = stringBuilder.toString();

        if (qName.endsWith(".")) {
            qName = qName.substring(0, qName.length() - 1);
        }

        // QTYPE is two bytes starting at the current index.
        qType = ((dnsMessageBytes[index] & 0xFF) << 8) | (dnsMessageBytes[index + 1] & 0xFF);
        index += 2; // Move the index past the QTYPE.

        // QCLASS is also two bytes, starting at the new index.
        qClass = ((dnsMessageBytes[index] & 0xFF) << 8) | (dnsMessageBytes[index+  1] & 0xFF);
    }

    public DNSQuestion(String qName, int qType, int qClass) {
        if (qType == 12) {
            String[] octets = qName.split("\\.");
            List<String> octetList = Arrays.asList(octets);
            Collections.reverse(octetList);
            String reversedIp = String.join(".", octetList);

            // Append the "in-addr.arpa" domain.
            qName = reversedIp + ".in-addr.arpa.";
        }
        if (qName.endsWith(".")) {
            qName = qName.substring(0, qName.length() - 1);
        }

        this.qName = qName;
        this.qType = qType;
        this.qClass = qClass;
    }

    public int getByteLength() {
        int qNameLength = 0;
        String[] labels = qName.split("\\."); //  splits name by .
        for (String label : labels) {
            qNameLength = qNameLength + 1 + label.length();
        }
        if (!qName.endsWith(".")) {
            qNameLength++; // null label of the root
            // the null label will already get added if it ends with .
            // dont have to worry about ending with mulitple dots since domain names shouldn't end with multiple dots
        }
        return 2 + 2 + qNameLength;
    }
}
