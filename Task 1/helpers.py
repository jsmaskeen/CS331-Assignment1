import struct

# default port number, which is ascii sum of our name and roll number strings * 10
default_port = (
    sum(
        ord(i)
        for i in ("karan_sagar_gandhi (23110157)" + "jaskirat_singh_maskeen (23110146)")
    )
    * 10
)


# Receive exactly n bytes from a socket connection.
# Keeps reading until the buffer has n bytes or connection closes.
def recieve_n_bytes(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def is_dns(data: bytes):
    # First 12 bytes = header
    if len(data) < 12:
        raise ValueError("Too short to be DNS packet")

    # header = struct.unpack("!6H", data[:12]) # first 12 bytes store 6 integers each of 16 bits
    header = struct.unpack(
        "!2H", data[:4]
    )  # first 4 bytes store 2 integers each of 16 bits
    (transaction_id, flags) = header

    # QR bit is the MSB of flags
    return flags >> 15 == 0  # QR bit = 0 means query


# DNS parser to extract queried domain name
class DNSPacket:
    def __init__(self, data: bytes):
        self.data = data

    def get_domain(self) -> str:
        data = self.data
        try:
            pos = 12  # Skip fixed 12-byte header
            labels = []
            while True:
                length = data[pos]
                if length == 0: # end of domain
                    pos += 1
                    break
                if length & 0b11000000 == 0b11000000: # compression pointer (two-byte reference)
                    pointer = struct.unpack("!H", data[pos : pos + 2])[0] & 0b0011111111111111
                    return ".".join(self.read_labels(pointer))
                
                # Read label of 'length' bytes and decode
                labels.append(data[pos + 1 : pos + 1 + length].decode(errors="ignore"))
                pos += length + 1
            return ".".join(labels)
        except Exception:
            return "error in parsing"


    # Read domain labels starting from a given position (used for compression). [RFC 1035 section 4.1.4]
    # Stops when length = 0 or another pointer is found.
    def read_labels(self, pos: int):
        data = self.data
        labels = []
        while True: # end of labels
            length = data[pos]
            if length == 0:
                break
            if length & 0b11000000 == 0b11000000:
                pointer = struct.unpack("!H", data[pos : pos + 2])[0] & 0b0011111111111111
                labels.extend(self.read_labels(pointer))
                break
            labels.append(data[pos + 1 : pos + 1 + length].decode(errors="ignore"))
            pos += length + 1
        return labels
