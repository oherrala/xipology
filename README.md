# Xipology

A covert channel using nothing but DNS cache.


# Protocol

## The byte format

One byte is stored using 11 bits. The bits are arranged as follows:

```
  0   1   2   3   4   5   6   7   8   9   A
+-------------------------------------------+
| R | G | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | P |
+-------------------------------------------+

R    = Reservation bit
G    = Guard bit
0..7 = Data bits
P    = Parity bit (even)
```

**Reservation bit**: Writer sets Reservation bit to signal that there might be
something to be read.

**Guard bit**: Writer does not set Guard bit. Because reading one bit also
destroys it's state, Guard bit marks if the byte has been already consumed.

**Data bits**: Eight bits of data are written with Most Significant Bit (MSB) first.
High bits are written (do DNS query), low bits are not.

**Parity bit**: Even parity is used. If there are even number of bits set in
data bits, then parity is not set.

## DNS Name Derivation

DNS Names are derived with HKDF ([RFC
5968](https://tools.ietf.org/html/rfc5869)) using SHA-512 digest function ([FIPS
180-4](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)).

Name derivation is started using an user supplied secret ("password"). Each
consecutive DNS name is derived using this secret.

One name is created using 32 bytes of output from Key Derivation Function. These
32 bytes are split into two 16 byte chunks. The chunks are individually encoded
using base64 (`label1 = base64::encode(chunk1)`) and DNS name is created using
the format `<label1>.<label2>.xipology.example.com.`

## The process

### Writing one byte

1. Start Key Derivation Function if it's not already going.
2. Take new DNS Name.
3. Write Reservation Bit.
4. Take new DNS Name.
5. Do not write Guard bit!
7. Take eight DNS names and write eight data bits (1 = make DNS query, 0 = do nothing).
8. Take new DNS Name.
9. Write Parity bit if there's odd number of data bits set.

### Reading one byte

1. Start Key Derivation Function if it's not already going.
2. Take new DNS Name.
3. Read Reservation Bit. If not set, exit.
4. Take new DNS Name.
5. Read Guard Bit. If set, exit.
7. Take eight DNS names and read eight data bits.
8. Take new DNS Name.
9. Read Parity bit and validate.

### Writing bytestring

First byte is the length of the bytestring (between 1 and 255). Then bytestring
is written.

### Read bytestring

Read one byte. The value should be between 1 and 255. Then read as many bytes as
indicated by length.
