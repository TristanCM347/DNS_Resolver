public class DNSHeader {
    public int id;
    public boolean qr;
    public int opcode;
    public boolean aa;
    public boolean tc;
    public boolean rd;
    public boolean ra;
    public int rcode;

    public DNSHeader(byte[] dnsMessageBytes) {
        // ID is stored in the first two bytes
        this.id = ((dnsMessageBytes[0] & 0xFF) << 8) | (dnsMessageBytes[1] & 0xFF);

        // QR is the 1st bit of the 3rd byte
        this.qr = (dnsMessageBytes[2] & 0x80) != 0;

        // Opcode is the next 4 bits of the 3rd byte
        this.opcode = (dnsMessageBytes[2] & 0x78) >> 3;

        // AA is the 2nd bit of the 3rd byte
        this.aa = (dnsMessageBytes[2] & 0x04) != 0;

        // TC is the 3rd bit of the 3rd byte
        this.tc = (dnsMessageBytes[2] & 0x02) != 0;

        // RD is the 4th bit of the 3rd byte
        this.rd = (dnsMessageBytes[2] & 0x01) != 0;

        // RA is the 1st bit of the 4th byte
        this.ra = (dnsMessageBytes[3] & 0x80) != 0;

        // RCODE is the last 4 bits of the 4th byte
        this.rcode = dnsMessageBytes[3] & 0x0F;
    }

    public DNSHeader(int id, boolean qr, int opcode, boolean aa, boolean tc, boolean rd, boolean ra, int rcode) {
        this.id = id;
        this.qr = qr;
        this.opcode = opcode;
        this.aa = aa;
        this.tc = tc;
        this.rd = rd;
        this.ra = ra;
        this.rcode = rcode;
    }
}
