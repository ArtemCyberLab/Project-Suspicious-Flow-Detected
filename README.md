To extract and decode encrypted data from a network capture file (traffic.pcapng), retrieve meaningful information (e.g., a MiniDump), and prepare the result for further analysis.

What I Did:
1. Installing and Fixing tshark Dependencies
Initially, I tried to install tshark to analyze the PCAP file, but the installation failed due to missing packages (404 Not Found) from the wireshark-dev/stable PPA.

To resolve this:

I removed the broken PPA:

add-apt-repository --remove ppa:wireshark-dev/stable
Updated package lists:

apt update
Then successfully installed tshark from the official Ubuntu repositories:

apt install tshark -y
2. Extracting Data from the PCAP File
I used tshark to filter network packets destined for IP 10.10.94.106, port 1337, with the ACK and PUSH TCP flags set:

tshark -r traffic.pcapng -Y "ip.dst == 10.10.94.106 and tcp.port == 1337 and tcp.flags.ack == 1 and tcp.flags.push == 1" -Tfields -e "data" > data_1_raw.txt
This produced a file named data_1_raw.txt (size: 555MB).

3. Hex → Base64 → Binary Conversion
3.1: Converting hex to raw bytes:

cat data_1_raw.txt | xxd -r -p > data_1_base64.txt
3.2: Decoding base64 into binary:

cat data_1_base64.txt | base64 -d -i > data_1_xor_encoded.txt
Although the command output an invalid input warning, the file data_1_xor_encoded.txt was successfully created (size: ~277MB).

4. Decoding the XOR-Encoded File
Initially, I wrote a simple Python script (xor_decode.py) that tried to load the entire file into memory. However, it was terminated with a Killed message due to insufficient RAM.

To solve the issue, I rewrote the script to process the file in chunks:

key = 0x41
input_file = "data_1_xor_encoded.txt"
output_file = "data_1.dmp"

chunk_size = 1024 * 1024  # 1 MB at a time

with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
    while True:
        chunk = f_in.read(chunk_size)
        if not chunk:
            break
        decoded = bytearray([b ^ key for b in chunk])
        f_out.write(decoded)
I saved and ran this script, and successfully generated the file data_1.dmp.

Next Step (outside the scope of this report):
In the next phase, I plan to:

Inspect the file type (file data_1.dmp)

If it’s a MiniDump, use tools like pypykatz, mimikatz, or KeePass dump utilities to extract sensitive information.

Summary:
I successfully performed analysis and decoding of network traffic using tshark, xxd, base64, and Python. I resolved package issues, optimized my decoding script for large files, and obtained a decoded dump file ready for deeper forensic analysis.

PART2. FINAL
1.  Packet Analysis with TShark
First, I analyzed the provided traffic.pcapng file. I suspected that TCP traffic on a non-standard port 1337 could be interesting.

I used the following tshark command to extract only the useful packet payloads:

tshark -r traffic.pcapng -T fields -Y 'tcp.dstport == 1337 and frame.len > 100' -e data.data > data_hex.txt
This extracted raw hex data from TCP packets longer than 100 bytes and targeting port 1337.

2. Converting Hex to Binary
The extracted data was in hex format, so I cleaned it and converted it into a raw binary dump:

cat data_hex.txt | tr -d ':' | xxd -r -p > raw_encrypted.dmp
This gave me the actual encrypted binary file.

4. Decryption via XOR + Base64
After inspecting the data, I noticed it was base64-encoded and XOR-encrypted with a single-byte key (likely 'A').

So I wrote a Python script (get_dumpfile.py) to decode and decrypt it:

python

import base64

with open('539.dmp', 'r') as file:
    encoded_data = file.read()

binary_data = base64.b64decode(encoded_data)
xor_key = b'A'

decrypted_data = bytearray(len(binary_data))
for i in range(len(binary_data)):
    decrypted_data[i] = binary_data[i] ^ xor_key[i % len(xor_key)]

with open('1337.dmp', 'wb') as file:
    file.write(decrypted_data)

print("Decryption completed. Saved to 1337.dmp")
After running the script, I successfully generated a decrypted file: 1337.dmp.

4. Analyzing the Memory Dump
I checked the file type:

file 1337.dmp
The output confirmed it was a MiniDump crash report:

Mini DuMP crash report, 18 streams...
I then used strings to search for readable content:

strings 1337.dmp | grep -iE 'flag|pass|key|secret'
And I found the flag:
THM{B3_Upd_Your_K33p455}

