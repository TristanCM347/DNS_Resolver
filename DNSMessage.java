import java.util.ArrayList;

// stores info of a dns message in a more parsable and editable way
// hence can create one vaible certain instructions
// and can create one via a 512 byte , byte array
// has methods for converting info into hex
    // getting certain info

public class DNSMessage {
    public DNSHeader header;
    public ArrayList<DNSQuestion> questions = new ArrayList<>();
    public ArrayList<DNSResourceRecord> answers = new ArrayList<>();
    public ArrayList<DNSResourceRecord> authorities = new ArrayList<>();
    public ArrayList<DNSResourceRecord> additionals = new ArrayList<>();

	public DNSHeader getHeader() {
		return this.header;
	}

	public void setHeader(DNSHeader header) {
		this.header = header;
	}

    public DNSMessage(DNSHeader header) {
        this.header = header;
    }

    public void addQuestion(DNSQuestion question) {
        this.questions.add(question);
    }

    public void addAnswer(DNSResourceRecord answer) {
        this.answers.add(answer);
    }

    public void addAuthority(DNSResourceRecord authority) {
        this.authorities.add(authority);
    }

    public void addAdditional(DNSResourceRecord additional) {
        this.additionals.add(additional);
    }

    // assume bytes is 512 bytes long
    public DNSMessage(byte[] dnsMessageBytes) {
        this.header = new DNSHeader(dnsMessageBytes);

        // QDCOUNT is the 5th and 6th bytes
        int qdcount = ((dnsMessageBytes[4] & 0xFF) << 8) | (dnsMessageBytes[5] & 0xFF);

        // ANCOUNT is the 7th and 8th bytes
        int ancount = ((dnsMessageBytes[6] & 0xFF) << 8) | (dnsMessageBytes[7] & 0xFF);

        // NSCOUNT is the 9th and 10th bytes
        int nscount = ((dnsMessageBytes[8] & 0xFF) << 8) | (dnsMessageBytes[9] & 0xFF);

        // ARCOUNT is the 11th and 12th bytes
        int arcount = ((dnsMessageBytes[10] & 0xFF) << 8) | (dnsMessageBytes[11] & 0xFF);

        int index = 12; // start after the header

        for (int i = 0; i < qdcount; i++) {
            DNSQuestion question = new DNSQuestion(index, dnsMessageBytes);
            questions.add(question);
            index += question.getByteLength();
        }

        for (int i = 0; i < ancount; i++) {
            DNSResourceRecord answer = new DNSResourceRecord(index, dnsMessageBytes);
            answers.add(answer);
            index += answer.getByteLength();
        }

        for (int i = 0; i < nscount; i++) {
            DNSResourceRecord authority = new DNSResourceRecord(index, dnsMessageBytes);
            authorities.add(authority);
            index += authority.getByteLength();
        }

        for (int i = 0; i < arcount; i++) {
            DNSResourceRecord additional = new DNSResourceRecord(index, dnsMessageBytes);
            additionals.add(additional);
            index += additional.getByteLength();
        }
    }

    public String toHexString() {
        byte[] bytes = this.toByteArray();

        StringBuilder hexString = new StringBuilder();

        for (byte b : bytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }

        return hexString.toString();
    }

    public byte[] toByteArray() {
        // figure out how big the array should be
        // check if its a query first beause thats the only time it matters
        byte[] dnsMessage;
        int length = 12; // header section is 12 bytes
        for (DNSQuestion question : questions) {
            length += question.getByteLength();
        }
        for (DNSResourceRecord answer : answers) {
            length += answer.getByteLength();
        }
        for (DNSResourceRecord authority : authorities) {
            length += authority.getByteLength();
        }
        for (DNSResourceRecord additional : additionals) {
            length += additional.getByteLength();
        }

        dnsMessage = new byte[length];
        // automatically intialises whole thing to 0 bits

        int index = 0;

        // Add header
        dnsMessage[index++] = (byte) (header.id >> 8);
        dnsMessage[index++] = (byte) (header.id);

        // automatically sets z to all 000
        short flags = (short) (
                (header.qr ? 0x8000 : 0) |
                (header.opcode & 0x7800) |
                (header.aa ? 0x0400 : 0) |
                (header.tc ? 0x0200 : 0) |
                (header.rd ? 0x0100 : 0) |
                (header.ra ? 0x0080 : 0) |
                (0x0000) |
                (header.rcode & 0x000F)
        );
        dnsMessage[index++] = (byte) (flags >> 8);
        dnsMessage[index++] = (byte) (flags);

        // qdcount
        dnsMessage[index++] = (byte) (questions.size() >> 8);
        dnsMessage[index++] = (byte) (questions.size());

        //ancount
        dnsMessage[index++] = (byte) (answers.size() >> 8);
        dnsMessage[index++] = (byte) (answers.size());

        //nscount
        dnsMessage[index++] = (byte) (authorities.size() >> 8);
        dnsMessage[index++] = (byte) (authorities.size());

        //arcount
        dnsMessage[index++] = (byte) (additionals.size() >> 8);
        dnsMessage[index++] = (byte) (additionals.size());

        // Add question (assume always one question)
        for (DNSQuestion question : questions) {
            index = putName(dnsMessage, index, question.qName);
            dnsMessage[index++] = (byte) (question.qType >> 8);
            dnsMessage[index++] = (byte) (question.qType);
            dnsMessage[index++] = (byte) (question.qClass >> 8);
            dnsMessage[index++] = (byte) (question.qClass);
        }

        // Add answer records
        for (DNSResourceRecord record : answers) {
            System.arraycopy(record.name, 0, dnsMessage, index, record.name.length);
            index += record.name.length;
            dnsMessage[index++] = (byte) (record.type >> 8);
            dnsMessage[index++] = (byte) (record.type);
            dnsMessage[index++] = (byte) (record.classValue >> 8);
            dnsMessage[index++] = (byte) (record.classValue);
            dnsMessage[index++] = (byte) (record.ttl >> 24);
            dnsMessage[index++] = (byte) (record.ttl >> 16);
            dnsMessage[index++] = (byte) (record.ttl >> 8);
            dnsMessage[index++] = (byte) (record.ttl);
            dnsMessage[index++] = (byte) (record.rdata.length >> 8);
            dnsMessage[index++] = (byte) (record.rdata.length);
            System.arraycopy(record.rdata, 0, dnsMessage, index, record.rdata.length);
            index += record.rdata.length;
        }

        // Add authority records
        for (DNSResourceRecord record : authorities) {
            System.arraycopy(record.name, 0, dnsMessage, index, record.name.length);
            index += record.name.length;
            dnsMessage[index++] = (byte) (record.type >> 8);
            dnsMessage[index++] = (byte) (record.type);
            dnsMessage[index++] = (byte) (record.classValue >> 8);
            dnsMessage[index++] = (byte) (record.classValue);
            dnsMessage[index++] = (byte) (record.ttl >> 24);
            dnsMessage[index++] = (byte) (record.ttl >> 16);
            dnsMessage[index++] = (byte) (record.ttl >> 8);
            dnsMessage[index++] = (byte) (record.ttl);
            dnsMessage[index++] = (byte) (record.rdata.length >> 8);
            dnsMessage[index++] = (byte) (record.rdata.length);
            System.arraycopy(record.rdata, 0, dnsMessage, index, record.rdata.length);
            index += record.rdata.length;
        }

        // Add additional records
        for (DNSResourceRecord record : additionals) {
            System.arraycopy(record.name, 0, dnsMessage, index, record.name.length);
            index += record.name.length;
            dnsMessage[index++] = (byte) (record.type >> 8);
            dnsMessage[index++] = (byte) (record.type);
            dnsMessage[index++] = (byte) (record.classValue >> 8);
            dnsMessage[index++] = (byte) (record.classValue);
            dnsMessage[index++] = (byte) (record.ttl >> 24);
            dnsMessage[index++] = (byte) (record.ttl >> 16);
            dnsMessage[index++] = (byte) (record.ttl >> 8);
            dnsMessage[index++] = (byte) (record.ttl);
            dnsMessage[index++] = (byte) (record.rdata.length >> 8);
            dnsMessage[index++] = (byte) (record.rdata.length);
            System.arraycopy(record.rdata, 0, dnsMessage, index, record.rdata.length);
            index += record.rdata.length;
        }

        // assume wont get indicy out of bounds as i wont be touching editing any asnwer parts
        return dnsMessage;
    }

    private int putName(byte[] dnsMessage, int index, String qName) {
        String[] labels = qName.split("\\."); // splits name by .
        for (String label : labels) {
            int length = label.length();
            dnsMessage[index++] = (byte) length;
            for (char c : label.toCharArray()) {
                dnsMessage[index++] = (byte) c;
            }
        }
        dnsMessage[index++] = 0x00; // null label of the root
        return index;
    }

    public String extractDomainFromRData(byte[] rData) {
        int rDataIndex = 0;

        StringBuilder domainName = new StringBuilder();

        while (rDataIndex < rData.length) {
            if ((rData[rDataIndex] & 0xC0) == 0xC0) {
                // Name is compressed, this is an offset
                // get the offset as an interger
                int dnsMessageIndex = ((rData[rDataIndex] & 0x3F) << 8) | (rData[rDataIndex + 1] & 0xFF);
                // go and find domain name
                this.parsePointerValueForDomainName(domainName, dnsMessageIndex);
                // now string is done being built
                break;
            } else if (rData[rDataIndex] == 0x00) {
                // end of the label its reading and string is done being built
                break;
            } else {
                // part of the label
                int labelLength = rData[rDataIndex++];
                // Extract the characters for this label
                for (int i = 0; i < labelLength; i++) {
                    domainName.append((char) rData[rDataIndex++]);
                }
                domainName.append(".");
                // go to next label if there is one
            }
        }

        // note the domain name will alwasys have a '.' on the end which shouldnt be a problem
        return domainName.toString();
    }

    // assumes the string builder haas already been made
    public void parsePointerValueForDomainName(StringBuilder domainName, int dnsMessageIndex) {
        byte[] dnsMessage = this.toByteArray();
        while (true) {
            if ((dnsMessage[dnsMessageIndex] & 0xC0) == 0xC0) {
                // Name is compressed, this is an offset
                // get the offset as an interger
                int dnsMessageIndexNew = ((dnsMessage[dnsMessageIndex] & 0x3F) << 8) | (dnsMessage[dnsMessageIndex + 1] & 0xFF);
                // go and find domain name
                this.parsePointerValueForDomainName(domainName, dnsMessageIndexNew);
                // now string is done being built
                break;
            } else if (dnsMessage[dnsMessageIndex] == 0x00) {
                // end of the label its reading and string is done being built
                break;
            } else {
                // part of the label
                int labelLength = dnsMessage[dnsMessageIndex++];
                // Extract the characters for this label
                for (int i = 0; i < labelLength; i++) {
                    domainName.append((char) dnsMessage[dnsMessageIndex++]);
                }
                domainName.append(".");
                // go to next label if there is one
            }
        }
    }
}
