public class DNSResourceRecord {
    public byte[] name;
    public int type;
    public int classValue;
    public int ttl;
    public byte[] rdata;

    public DNSResourceRecord(int index, byte[] dnsMessageBytes) {
        // get the name
        if ((dnsMessageBytes[index] & 0xC0) == 0xC0) {
            // Name is compressed, this is an offset
            // It's a pointer/offset hence is only 2 bytes
            name = new byte[2];
            System.arraycopy(dnsMessageBytes, index, name, 0, 2);
            index += 2;
        } else {
            int lengthOfName = 0;

            // It's a sequence of labels. Keep reading bytes until we hit a zero byte,
            // or a pointer byte (which would mean that the sequence of labels ends with a pointer)
            while ((dnsMessageBytes[index + lengthOfName] & 0xC0) != 0xC0 && dnsMessageBytes[index + lengthOfName] != 0x00) {
                lengthOfName++;
            }

            // If we encounter a pointer byte, two pointer bytes of length to the name
            if ((dnsMessageBytes[index + lengthOfName] & 0xC0) == 0xC0) {
                lengthOfName++;
                lengthOfName++;
            } else {
                lengthOfName++;
                // add null byte
            }

            // now create name
            name = new byte[lengthOfName];
            // now copy values
            System.arraycopy(dnsMessageBytes, index, name, 0, lengthOfName);

            index += lengthOfName;
        }

        // now add the other bytes
        type = ((dnsMessageBytes[index] & 0xFF) << 8) | (dnsMessageBytes[index + 1] & 0xFF);
        index += 2;
        classValue = ((dnsMessageBytes[index] & 0xFF) << 8) | (dnsMessageBytes[index + 1] & 0xFF);
        index += 2;
        ttl = ((dnsMessageBytes[index] & 0xFF) << 24)
            | ((dnsMessageBytes[index + 1] & 0xFF) << 16)
            | ((dnsMessageBytes[index + 2] & 0xFF) << 8)
            | (dnsMessageBytes[index + 3] & 0xFF);
        index += 4;

        // decode the rdlength field
        int rdlength = ((dnsMessageBytes[index] & 0xFF) << 8) | (dnsMessageBytes[index + 1] & 0xFF);
        index += 2;

        // copy the rdata bytes
        rdata = new byte[rdlength];
        System.arraycopy(dnsMessageBytes, index, rdata, 0, rdlength);
        index += rdlength;
    }

    public int getByteLength() {
        return name.length + 2 + 2 + 4 + 2 + rdata.length;
    }
}
