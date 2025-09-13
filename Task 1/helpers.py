import struct

# default port number, which is ascii sum of our name and roll number strings * 10
default_port = (
    sum(
        ord(i)
        for i in ("karan_sagar_gandhi (23110157)" + "jaskirat_singh_maskeen (23110146)")
    )
    * 10
)


def is_dns(data: bytes):
    # First 12 bytes = header
    if len(data) < 12:
        raise ValueError("Too short to be DNS packet")

    header = struct.unpack("!6H", data[:12]) # first 12 bytes store 6 integers each of 16 bits
    # header = struct.unpack(
    #     "!2H", data[:4]
    # )  # first 4 bytes store 2 integers each of 16 bits
    (transaction_id, flags, _, _, _, _) = header

    # QR bit is the MSB of flags
    return flags >> 15 == 0  # QR bit = 0 means query


# DNS parser to extract queried domain name
class DNSPacket:
    def __init__(self, data: bytes,response=None):
        self.is_created_response = response
        self.data = data

    def get_domain(self) -> str:
        data = self.data
        
        if self.get_question_count() == 0:
            return None
        
        try:
            pos = 12  # Skip fixed 12-byte header
            labels = []
            while True:
                length = data[pos]
                if length == 0: # end of domain
                    pos += 1
                    break
                if length & 0b11000000 == 0b11000000: # compression pointer (two-byte reference), if it is a pointer go to that position and read from there.
                    pointer = struct.unpack("!H", data[pos : pos + 2])[0] & 0b0011111111111111
                    return ".".join(self.read_labels(pointer))
                
                # Read label of 'length' bytes and decode
                labels.append(data[pos + 1 : pos + 1 + length].decode(errors="ignore"))
                pos += length + 1
            return ".".join(labels)
        except Exception:
            return "error in parsing"
    
    def get_question_count(self):
        data = self.data
        if len(data) < 12:
            raise ValueError("Too short to be DNS packet")
        return struct.unpack("!H", data[4:6])[0]
    
    def get_answer_count(self):
        data = self.data
        if len(data) < 12:
            raise ValueError("Too short to be DNS packet")
        return struct.unpack("!H", data[6:8])[0]

    def get_answer_offset(self):
        n_questions = self.get_question_count()
        pos = 12  # start after header
        data = self.data
        for _ in range(n_questions):
            while True:
                length = data[pos]
                pos += 1
                if length == 0:
                    break
                if length & 0b11000000 == 0b11000000: # compression pointer (two-byte reference), if it is a pointer go to that position and read from there.
                    pos += 2 # pointer is two bytes
                    break
                pos += length
            pos += 4  # skip QTYPE and QCLASS (2 bytes each)
        return pos

    def get_answer_domain_and_ip(self):
        n_ans = self.get_answer_count()
        data = self.data
        
        if n_ans == 0:
            return None
        
        pos = self.get_answer_offset() # start after header
        name = None
        labels = []
        while True:
            length = data[pos]
            if length == 0:
                pos += 1
                break
            
            if length & 0b11000000 == 0b11000000: # compression pointer (two-byte reference), if it is a pointer go to that position and read from there.
                pointer = struct.unpack("!H", data[pos : pos + 2])[0] & 0b0011111111111111
                name = ".".join(self.read_labels(pointer))
                pos += 2
                break
            labels.append(data[pos + 1 : pos + 1 + length].decode(errors="ignore"))
            pos += length + 1
        if name is None:
            name = ".".join(labels)
            
        type = struct.unpack("!H", data[pos : pos + 2])[0]
        cls = struct.unpack("!H", data[pos + 2 : pos + 4])[0]
        ttl = struct.unpack("!I", data[pos + 4 : pos + 8])[0]
        data_len = struct.unpack("!H", data[pos + 8 : pos + 10])[0]
        ip_bytes = data[pos + 10 : pos + 10 + data_len]
        ip = ".".join(map(str, ip_bytes))
        return name, ip

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
    
    def append_resolved_ip(self, resolved_ip):
        # change the bytes in self.data to add an answer section with the resolved_ip
        # first 12 bytes = header
        data = bytearray(self.data)
        data[6:8] = b'\x00\x01' # increment answer count
        assert self.get_question_count() == 1, "No question section to answer" # only support 1 question
        if self.is_created_response:
            # set the reponse code in flags to be 1
            data[2] |= 0b10000000
        data += b'\xc0\x0c' # Name: Pointer to offset 12 this is where the domain name is present
        data += b'\x00\x01' # Type A
        data += b'\x00\x01' # Class IN
        data += b'\x00\x00\x00\x3c' # TTL 60 seconds
        data += b'\x00\x04' # Data length 4 bytes
        data += bytes(map(int, resolved_ip.split('.'))) # IPv4 address
        self.data = bytes(data)
        
    def visualize(self):
        data = self.data
        print("DNS Packet Overview".center(50,'='))
        # Header 
        if len(data) < 12:
            raise ValueError("Too short to be DNS packet")

        (transaction_id, flags, qd_len, an_len, ns_len, ar_len) = struct.unpack("!6H", data[:12])
        
        qr = (flags >> 15) & 1
        opcode = (flags >> 11) & 0xF
        aa = (flags >> 10) & 1
        trucna = (flags >> 9) & 1
        recur_desir = (flags >> 8) & 1
        recur_avail = (flags >> 7) & 1
        resp_code = flags & 0xF

        print(f"Header (12 bytes):")
        print(f" |- Transaction ID: {transaction_id} (0x{transaction_id:04x})")
        print(f" |- Flags: 0x{flags:04x}")
        print(f" | |- QR:     {qr} ({'Response' if qr else 'Query'})")
        print(f" | |- Opcode: {opcode} ({'Standard Query' if opcode == 0 else 'Other'})")
        print(f" | |- AA:     {aa} (Authoritative Answer)")
        print(f" | |- TC:     {trucna} (Truncated)")
        print(f" | |- RD:     {recur_desir} (Recursion Desired)")
        print(f" | |- RA:     {recur_avail} (Recursion Available)")
        print(f" | |- RCODE:  {resp_code} (Response Code)\n")
        print(f" |- Questions: {qd_len}")
        print(f" |- Answer RRs: {an_len}")
        print(f" |- Authority RRs: {ns_len}")
        print(f" |- Additional RRs: {ar_len}")
        
        pos = 12

        # question section
        if qd_len > 0:
            print("-" * 40)
            print("Question Section:")
        for i in range(qd_len):
            labels = []
            while True:
                length = data[pos]
                if length == 0:
                    pos += 1
                    break
                if (length & 0b11000000) == 0b11000000: # Compression pointer
                    pos += 2
                    pointer = struct.unpack("!H", data[pos-2:pos])[0] & 0b0011111111111111
                    labels.extend(self.read_labels(pointer))
                    break
                labels.append(data[pos + 1 : pos + 1 + length].decode(errors="ignore"))
                pos += length + 1
            qname = ".".join(labels)
            qtype, qclass = struct.unpack("!2H", data[pos:pos+4])
            pos += 4
            print(f" |- Query {i+1}:")
            print(f" | |- Name:  {qname}")
            print(f" | |- Type:  {qtype} ({'A (IPv4)' if qtype == 1 else 'Other'})")
            print(f" | |- Class: {qclass} ({'IN (Internet)' if qclass == 1 else 'Other'})")

        # answer, authority, and additional sections 
        sections = [("Answer", an_len), ("Authority", ns_len), ("Additional", ar_len)]
        for name, count in sections:
            if count > 0:
                print("-" * 40)
                print(f"{name} Section:")
            for i in range(count):
                rr_start_pos = pos
                # Read the domain name, which could be a pointer
                rr_name_labels = self.read_labels(pos)
                rr_name = ".".join(rr_name_labels)
                
                temp_pos = rr_start_pos
                while True:
                    length = data[temp_pos]
                    if (length & 0b11000000) == 0b11000000: # Compression pointer
                        temp_pos += 2
                        break
                    temp_pos += length + 1
                    if length == 0:
                        break
                pos = temp_pos
                
                rtype, rclass, ttl, rdlength = struct.unpack("!2HIH", data[pos:pos+10])
                pos += 10
                
                rdata = data[pos:pos+rdlength]
                
                print(f" |- Resource Record {i+1}:")
                print(f" | |- Name:  {rr_name}")
                print(f" | |- Type:  {rtype}")
                print(f" | |- Class: {rclass}")
                print(f" | |- TTL:   {ttl} seconds")
                print(f" | |- Len:   {rdlength} bytes")
                
                # some common records
                if rtype == 1: # A record
                    ip = ".".join(map(str, rdata))
                    print(f" | |- Addr:  {ip}")
                elif rtype == 5: # CNAME record
                    cname_labels = self.read_labels(pos)
                    print(f" | |- CNAME: {'.'.join(cname_labels)}")
                else:
                    print(f" | |- Data:  {rdata.hex()}")
                
                pos += rdlength
        
        print("="*50,end='\n\n')