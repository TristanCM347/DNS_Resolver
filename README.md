# DNS Resolver Project

## Description

This project provides a DNS resolver along with a client to handle DNS queries and responses. It is constructed based on the specifications described in the [RFC 1034](https://datatracker.ietf.org/doc/html/rfc1034) and [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) documents. The implementation ensures efficient domain name resolution by following these standards.

## Files Included

- **Client.class & Client.java**: Houses the client-side logic for making DNS requests.
- **Resolver.class & Resolver.java**: Encompasses the main DNS resolver logic.
- **DNSHeader.class & DNSHeader.java**: Manages the header portion of a DNS message.
- **DNSMessage.class & DNSMessage.java**: Addresses the overall structure and parsing of DNS messages.
- **DNSQuestion.class & DNSQuestion.java**: Represents the question section of a DNS message.
- **DNSResourceRecord.class & DNSResourceRecord.java**: Pertains to the resource records within a DNS message.

### Auxiliary Files

- `named.root`: Contains the root DNS server information.
- `resolvableDomains.txt`: A list of domains supported for resolution by this resolver.
- `README.md`: This very documentation and usage guide.

## Supported Record Types

- **MX**: Mail Exchange
- **PTR**: Pointer
- **A**: Address
- **NS**: Name Server
- **CNAME**: Canonical Name

## Usage

### Client

To use the client, execute:

```bash
java Client <resolver_ip> <resolver_port> <name> <timeout> <type> 
```

For example

```bash
java Client 127.0.0.1 8080 example.com 10 A 
```

### Resolver

To use the resolver, run:

```bash
java Resolver <port> <timeout>
```

For example

```bash
java Resolver 8080 10
```

## Important Note

Before executing the commands, ensure all required dependencies are installed and the files are appropriately compiled.

## References

For a deep dive into the construction of resolvers and DNS messages, refer to:

- [RFC 1034](https://datatracker.ietf.org/doc/html/rfc1034)
- [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035)

Thank you for choosing my DNS Resolver project!
