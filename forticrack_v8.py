#!/usr/bin/env python3
# forticrack_v8 by @hacefresko based on Bishop Fox work (https://github.com/BishopFox/forticrack)

import sys, os, re, subprocess, multiprocessing, functools, shutil, hashlib, gzip

REQUIRED_TOOLS = [
    "gunzip",
    "binwalk",
    "cpio"
]

# hardcoded ELF segments and virtual addresses (kernel 4.19.13 v8.0.0 build 0167, same for FGT and FFW)
# extracted them directly from the kernel ELF by reversing the code responsible of decrypting rootfs.gz 
KERNEL_SEGMENTS = [
    (0xffffffff80200000, 0x200000,  0x12fa000),
    (0xffffffff81600000, 0x1600000, 0xe5000),
    (0x0000000000000000, 0x1800000, 0x29000),
    (0xffffffff8170e000, 0x190e000, 0x12e000),
]

RSA_ENC_VA  = 0xffffffff8179a1a0   # 270 bytes of DER, XOR-encoded
RSA_ENC_LEN = 0x10e

XOR_KEY_VA  = 0xffffffff8179a2c0   # 32-byte XOR key


####################### ORIGINAL BISHOP FOX FORTICRACK CODE #######################

# Standard block size for Fortinet firmware images
BLOCK_SIZE = 512

# Load a firmware image into memory (decompressing if necessary)
def load_image_data(image_file):
    try:
        if not os.path.isfile(image_file):
            raise ValueError("file not found")

        # Use gunzip because the Python gzip library won't ignore file signature data
        result = subprocess.run(
            [
                f"gunzip",
                "--to-stdout",  # decompress to stdout and leave the file intact
                "--force",  # allow uncompressed data to pass through
                image_file,
            ],
            check=False,  # ignore trailing garbage warning
            capture_output=True,
        )
        if result.stdout:
            return result.stdout
        else:
            raise ValueError("empty file")

    except Exception as err:
        print(f"    [x] {err}")
        return None


# Validate a derived key by checking against known key values
def validate_key(key):
    # Length must be 32 bytes
    if len(key) != 32:
        return False

    # Key must be an ASCII string
    try:
        string = key.decode("ascii")
    except:
        return False

    # Key bytes only include characters 0-9, A-Z, and a-z
    for char in string:
        valid = re.match(r"[0-9A-Za-z]", char)
        if not valid:
            return False

    # Valid key
    return True


# Derive one byte of the key from two consecutive bytes of ciphertext,
#   one byte of known plaintext, and the key offset
# This is the same XOR operation used in Fortinet's encryption function,
#   but the plaintext and key are swapped
def derive_key_byte(
    key_offset, ciphertext_byte, previous_ciphertext_byte, known_plaintext
):
    key_byte = (
        previous_ciphertext_byte ^ (known_plaintext + key_offset) ^ ciphertext_byte
    )
    key_byte = (key_byte + 256) & 0xFF  # mod 256 to loop negatives
    return key_byte


# Use a known plaintext attack to derive a key from the first 80 bytes of a 512-byte
#   ciphertext block, then decrypt the block header and validate the content
# Known plaintext is 32 null bytes starting from block offset 48
# Only return a key if the decrypted content is valid
def derive_block_key(ciphertext):
    key = bytearray()
    known_plaintext = 0x00

    # Derive the key for this block
    for i in range(32):
        key_offset = (i + 16) % 32  # mod 32 to wrap around key
        plaintext_offset = i + 48
        ciphertext_byte = ciphertext[plaintext_offset]
        previous_ciphertext_byte = ciphertext[plaintext_offset - 1]
        key.append(
            derive_key_byte(
                key_offset, ciphertext_byte, previous_ciphertext_byte, known_plaintext
            )
        )
    key = key[16:] + key[:16]  # swap the first/second halves of the key

    # Validate the key
    if validate_key(key):
        # Decrypt the header and validate contents
        cleartext = decrypt(ciphertext, key)
        if validate_decryption(cleartext):
            return bytes(key)

    # Key was invalid
    return None


# Use multiprocessing to attempt key derivation on all 512-byte blocks in parallel
def derive_key(ciphertext):
    # Determine the number of blocks to read
    num_blocks = (len(ciphertext) + BLOCK_SIZE - 1) // BLOCK_SIZE
    block_header_size = 80

    # Create a pool of worker processes
    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        # Start the workers
        results = [
            pool.apply_async(
                derive_block_key,
                (  # Each worker attacks the 80-byte header of a 512-byte block
                    ciphertext[
                        block_num * BLOCK_SIZE : block_num * BLOCK_SIZE
                        + block_header_size
                    ],
                ),
            )
            for block_num in range(num_blocks)
        ]
        # Look for a successful result
        for result in results:
            key = result.get()
            if key:
                # Kill the workers as soon as we find a valid key
                pool.terminate()
                pool.join()
                return key
    return None


# Validate decryption by checking for known header data
# NOTE: this header isn't always in the first 512-byte block
def validate_decryption(cleartext):
    if (
        # Length must be at least 80 chars
        len(cleartext) >= 80
        # Validate the file signature "magic bytes"
        and cleartext[12:16] == b"\xff\x00\xaa\x55"
    ):
        # Make sure the image name is readable
        try:
            image_name = cleartext[16:46].decode("utf-8", errors="strict")
        except:
            return False
        # Make sure the word "build" is in the image name
        if "build" in image_name.lower():
            # Valid Fortinet image
            return True
    # Unknown format
    return False


# Decrypt data
def decrypt(ciphertext, key, num_bytes=None):
    if num_bytes is None or num_bytes > len(ciphertext):
        num_bytes = len(ciphertext)
    if num_bytes > BLOCK_SIZE:
        num_bytes = BLOCK_SIZE

    key_offset = 0
    block_offset = 0
    cleartext = bytearray()
    previous_ciphertext_byte = 0xFF  # IV is always FF

    while block_offset < num_bytes:
        # If we're testing a partial key, return partial cleartext
        if key_offset >= len(key):
            return bytes(cleartext)

        # For each byte in the block, bitwise XOR the current byte with the
        # previous byte (both ciphertext) and the corresponding key byte
        ciphertext_byte = ciphertext[block_offset]
        xor = (
            previous_ciphertext_byte ^ ciphertext_byte ^ key[key_offset]
        ) - key_offset  # subtract the key offset to undo obfuscation
        xor = (xor + 256) & 0xFF  # mod 256 to loop negatives
        cleartext.append(xor)

        # Proceed to next byte
        block_offset += 1
        key_offset = (
            key_offset + 1  # increment key offset
        ) & 0x1F  # mod 32 to loop around the key
        previous_ciphertext_byte = ciphertext_byte

    # Reached end of block
    return bytes(cleartext)


# Use multiprocessing to decrypt all 512-byte blocks in parallel
def decrypt_file(ciphertext, key, output_file):
    # Determine the number of blocks to read
    num_blocks = (len(ciphertext) + BLOCK_SIZE - 1) // BLOCK_SIZE

    # Create a pool of worker processes
    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        worker = functools.partial(decrypt, key=key)
        worker_map = pool.map_async(
            worker,
            [  # Each worker gets a 512-byte block of ciphertext to decrypt
                ciphertext[block_num * BLOCK_SIZE : block_num * BLOCK_SIZE + BLOCK_SIZE]
                for block_num in range(num_blocks)
            ],
        )
        worker_map.wait()
        results = worker_map.get()
    if not results:
        return False

    # Write the ordered results to the output file
    cleartext = b"".join(results)
    with open(output_file, "wb") as outfile:
        outfile.write(cleartext)
    return True

###################################################################################


# Extract .decrypted firmware image produced by original forticrack with binwalk
def extract_decrypted(decrypted_fw_file):
    try:
        if not os.path.isfile(decrypted_fw_file):
            raise ValueError("file not found")

        result = subprocess.run(
            [
                f"binwalk",
                "-e",
                decrypted_fw_file,
            ],
            check=False,  # ignore trailing garbage warning
            capture_output=True,
        )
        if result.returncode != 0:
            raise ValueError("empty file")

    except Exception as err:
        print(f"    [x] {err}")
        return None
    
    # Rename extracted directory to remove extensions and trailing _
    extracted_dir = os.path.splitext(decrypted_fw_file)[0]
    binwalk_extracted_dir = f"_{os.path.basename(decrypted_fw_file)}.extracted"

    os.rename(binwalk_extracted_dir, extracted_dir)
    return extracted_dir


# Just check that some files are present in the extracted dir
def verify_extracted(decrypted_out_dir):
    files = os.listdir(f"{decrypted_out_dir}/ext-root")

    verify_files = ["flatkc", "rootfs.gz", "datafs.tar.gz"]
    for f in verify_files:
        if f not in files:
            print(f"    [x] {f} not found in extracted directory")
            return False
    
    return True
    
# Extract kernel ELF from flatkc. Used gunzip because gzip was giving me some problems at this was straightforward
def extract_kernel_elf(flatkc):
    GZIP_MAGIC = b'\x1f\x8b'

    offset = flatkc.find(GZIP_MAGIC)
    if offset == -1:
        print("    [x] No gzip magic found in flatkc")
        return None
    
    try:
        result = subprocess.run(
            [
                "gunzip",
                "--to-stdout"
            ],
            input=flatkc[offset:],
            check=False,
            capture_output=True,
        )

        if result.stdout:
            return result.stdout
        else:
            raise ValueError("empty file")
        
    except Exception as err:
        print(f"    [x] {err}")
        return None


####################################################################################################
#### NOTE: tbh, this whole section of crypto related funcs was completely vibe coded by Claude, ####
#### I just reviewed them and made some very little adjustments :P                              ####
####################################################################################################

# Convert virtual address to file offset
def va_to_off(va):
    for vaddr, foff, fsz in KERNEL_SEGMENTS:
        if vaddr <= va < vaddr + fsz:
            return foff + (va - vaddr)
    return None

# Parse PKCS#1 RSAPublicKey DER, return (n: int, e: int).
def parse_rsa_der(data):
    def read_tl(d, p):
        tag = d[p]; p += 1
        length = d[p]; p += 1
        if length & 0x80:
            nb = length & 0x7f
            length = int.from_bytes(d[p:p+nb], 'big')
            p += nb
        return tag, length, p

    tag, l, pos = read_tl(data, 0)
    if tag != 0x30:
        raise ValueError(f"Expected SEQUENCE, got 0x{tag:02x}")
    tag2, l2, pos2 = read_tl(data, pos)
    if tag2 != 0x02:
        raise ValueError(f"Expected INTEGER for n, got 0x{tag2:02x}")
    n_bytes = data[pos2:pos2 + l2]
    if n_bytes[0] == 0:
        n_bytes = n_bytes[1:]
    n = int.from_bytes(n_bytes, 'big')
    pos2 += l2
    tag3, l3, pos3 = read_tl(data, pos2)
    e = int.from_bytes(data[pos3:pos3 + l3], 'big')
    return {"n":n, "e":e}

# XOR-decode and parse the RSA public key embedded in the kernel ELF.
def extract_rsa_key(flatkc):
    try:
        if flatkc[:4] != b'\x7fELF':
            raise ValueError("Not an ELF file (got: %s). Pass the .elf file, not the bzImage." % flatkc[:4].hex())
    
        enc_off = va_to_off(RSA_ENC_VA)
        key_off = va_to_off(XOR_KEY_VA)
        if enc_off is None or key_off is None:
            raise ValueError("RSA key VAs not found in any ELF segment")
        if enc_off + RSA_ENC_LEN > len(flatkc) or key_off + 32 > len(flatkc):
            raise ValueError(f"ELF too small: offsets 0x{enc_off:x}/0x{key_off:x} out of range for {len(flatkc)} bytes")
        
        xor_enc = flatkc[enc_off:enc_off + RSA_ENC_LEN]
        xor_key = flatkc[key_off:key_off + 32]
        decoded  = bytes(xor_enc[i] ^ xor_key[i & 0x1f] for i in range(RSA_ENC_LEN))

        return parse_rsa_der(decoded)
    except Exception as err:
        print(f"    [x] {err}")
        return None

# RSA public-key operation + PKCS#1 v1.5 Type 1 parse.
# The rootfs signature contains the rootfs SHA256 hash and a RC4 decryption key
# Returns {"sha256_in_sig": bytes, "rc4_key": bytes}, or None on failure.
#
# Layout of the 256-byte result:
#     [0x00]       = 0x00
#     [0x01]       = 0x01           block type
#     [0x02..0x9E] = 0xFF * 157     padding
#     [0x9F]       = 0x00           separator
#     [0xA0..0xBF] = SHA256(body)   32 bytes
#     [0xC0..0xDF] = (unused)       32 bytes
#     [0xE0..0xFF] = RC4 key        32 bytes
def rsa_extract_sha_rc4(sig_block_256, rsa_key):
    n, e = rsa_key["n"], rsa_key["e"]

    try:
        sig_int = int.from_bytes(sig_block_256, 'big')
        if sig_int >= n:
            raise ValueError("Signature integer >= modulus")

        result = pow(sig_int, e, n).to_bytes(256, 'big')

        if result[0x00] != 0x00:
            raise ValueError(f"m[0x00] = 0x{result[0x00]:02x}, expected 0x00")
        if result[0x01] != 0x01:
            raise ValueError(f"m[0x01] = 0x{result[0x01]:02x}, expected 0x01")
        if not all(b == 0xFF for b in result[0x02:0x9F]):
            raise ValueError("Padding bytes m[0x02..0x9E] are not all 0xFF")
        if result[0x9F] != 0x00:
            raise ValueError(f"m[0x9F] = 0x{result[0x9F]:02x}, expected 0x00")

    except Exception as err:
        print(f"    [x] {err}")
        return None

    return {"sha256_in_sig": result[0xA0:0xC0], "rc4_key": result[0xE0:0x100],}

# FORT-RC4 stream cipher. Custom Fortinet encryption.
def fort_rc4_decrypt(key_bytes, ciphertext, variant):
    S = list(range(256))
    key = list(key_bytes)
    klen = len(key)

    # reset_j=True  -> FGT variant. The kernel function contains `31 c0 31 d2`
    #                     (xor eax,eax; xor edx,edx) at offset +0x83, zeroing both
    #                     i and j before the PRGA loop begins.
    # reset_j=False -> FFW variant. Those instructions are absent, so the final
    #                     j value from KSA flows directly into the PRGA.
    reset_j = (variant == 'FGT')

    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % klen]) & 0xFF
        S[i], S[j] = S[j], S[i]

    i = 0
    if reset_j:
        j = 0

    result = bytearray(len(ciphertext))
    for k in range(len(ciphertext)):
        i  = (i + 1) & 0xFF
        Si = S[i]
        j  = (j + Si) & 0xFF
        Sj = S[j]
        S[i], S[j] = Sj, Si

        t1     = (Si + Sj) & 0xFF
        idx1   = ((i  << 5) ^ (j  >> 3)) & 0xFF
        idx2   = ((j  << 5) ^ (i  >> 3)) & 0xFF
        mixidx = ((S[idx2] + S[idx1]) ^ 0xAA) & 0xFF
        bVar9  = (S[t1] + S[mixidx]) & 0xFF
        uVar7  = (Sj + j) & 0xFF

        result[k] = ciphertext[k] ^ (bVar9 ^ S[uVar7])

    return bytes(result)


def extract_rootfs(decrypted_rootfs, rootfs_extract_path):
    cpio_data = gzip.decompress(decrypted_rootfs)

    os.makedirs(rootfs_extract_path, exist_ok=True)

    result = subprocess.run(
        [
            "cpio", 
            "-idmv"
        ],
        input=cpio_data,
        cwd=rootfs_extract_path,
        capture_output=True,
    )

    if result.returncode == 2:
        print("    [+] cpio returned with code 2 (non-fatal errors, check cpio.log for more info)")
        with open("cpio.log", "w") as f:
            f.write(result.stderr.decode(errors='replace'))
            f.close()

    if result.returncode == 0 or result.returncode == 2:
        return True

    print(f"    [x] cpio returned with code {result.returncode}")
    print(result.stderr.decode(errors='replace'))
    return True


# Check required tools
for t in REQUIRED_TOOLS:
    if not shutil.which(t):
        print(f"[x] {t} is required! Install it before running {sys.argv[0]}")
        sys.exit(0)

# Parse input
if len(sys.argv) < 2 or sys.argv[1] in ["-h", "--help"]:
    print(f"[x] Usage: python3 {sys.argv[0]} <.out file> [FGT|FFW]")
    sys.exit(0)

encrypted_out_file = sys.argv[1]
variant = None if len(sys.argv) < 3 else sys.argv[2]

# Auto detect variant if not provided
if variant is None:
    if "FGT" in encrypted_out_file:
        variant = "FGT"
    elif "FFW" in encrypted_out_file:
        variant = "FFW"
    else:
        print("[x] Could't determine if .out file is FFW or FGT. Please, specify a variant!")
        sys.exit(0)

# Print banner
print(r" ___  __   __  ___    __   __        __                 __ ")
print(r"|__  /  \ |__)  |  | /  ` |__)  /\  /  ` |__/     \  / (__)")
print(r"|    \__/ |  \  |  | \__, |  \ /~~\ \__, |  \      \/  (__)")
print()
print("                    by @hacefresko based on Bishop Fox work")
print()
print(f"[+] Variant: {variant}")
print()

# 1. Decrypt initial .out file
print(f"[1] Decrypting {encrypted_out_file}")

# Decompress the input .out file
ciphertext = load_image_data(encrypted_out_file)
if not ciphertext:
    print("    [x] Failed to load image data")
    sys.exit(1)
print("    [+] Loaded image data")

# Make sure it's encrypted
for block_offset in range(0, len(ciphertext), BLOCK_SIZE):
    if validate_decryption(ciphertext[block_offset : block_offset + 80]):
        print("    [x] Image is already cleartext")
        sys.exit(0)
print("    [+] Verified that image data is encrypted")

# Identify the key using a known plaintext attack
key = derive_key(ciphertext)
if not key:
    print("    [x] No valid key found")
    sys.exit(1)
print(f"    [+] Found key: {key.decode('utf-8')}")

# Decrypt the file
decrypted_fw_file = f"{os.path.splitext(encrypted_out_file)[0]}.decrypted"
if not decrypt_file(ciphertext, key, decrypted_fw_file):
    print("    [x] Decryption failed")
    sys.exit(1)

print("    [+] Decryption successful!")
print()


# 2. Extract .decrypted file
print("[2] Extracting decrypted firmware (might take a few seconds...)")

# Extract with binwalk
decrypted_out_dir = extract_decrypted(decrypted_fw_file)
if decrypted_out_dir is None:
    print("    [x] Extraction failed")
    sys.exit(1)
print("    [+] Extraction successful")

# Delete .decrypted file
os.remove(decrypted_fw_file)

# Verify files in extracted directory
if not verify_extracted(decrypted_out_dir):
    print("    [x] Verification failed")
    sys.exit(1)
print("    [+] Verified extracted data")

print()


# 3. Decrypt rootfs.gz
print("[3] Decrypting rootfs")

# Read flatkc
flatkc_path = f"{decrypted_out_dir}/ext-root/flatkc"
with open(flatkc_path, 'rb') as f:
    flatkc = f.read()

# Extract kernel ELF
kernel_elf = extract_kernel_elf(flatkc)
if kernel_elf is None:
    print("    [x] Failed extraction of kernel ELF from flatkc")
print("    [+] Extracted kernel ELF from flatkc")

# Extract RSA public key from kernel ELF
rsa_key = extract_rsa_key(kernel_elf)
if rsa_key is None:
    print("    [x] Failed to extract RSA public key from kernel ELF")
    sys.exit(1)
print(f"    [+] Extracted RSA public key from kernel ELF")
print(f"        n = {rsa_key["n"].to_bytes(256, 'big')[:8].hex()}... ({rsa_key["n"].bit_length()} bits)")
print(f"        e = {rsa_key["e"]}")

# Read rootfs
rootfs_path = f"{decrypted_out_dir}/ext-root/rootfs.gz"
with open(rootfs_path, 'rb') as f:
    rootfs = f.read()
rootfs_body      = rootfs[:-256]
rootfs_sig_block = rootfs[-256:]

# Decrypt rootfs signature with RSA public key and extract SHA256 and RC4 key
signature_contents = rsa_extract_sha_rc4(rootfs_sig_block, rsa_key)
if signature_contents is None:
    print("    [x] Failed to decrypt rootfs signature with RSA public key")
    sys.exit(1)
print("    [+] Decrypted rootfs signature with RSA public key:")
print(f"        RC4 key:     {signature_contents["rc4_key"].hex()}")
print(f"        SHA256 hash: {signature_contents["sha256_in_sig"].hex()}")

# Verify that SHA256 extracted from signature matches body SHA256
computed_sha = hashlib.sha256(rootfs_body).digest()
if signature_contents["sha256_in_sig"] != computed_sha:
    print(f"    [!] SHA256 mismatch: signature has {signature_contents["sha256_in_sig"].hex()}, body hashes to {computed_sha.hex()}")
else:
    print(f"    [+] Signature SHA256 matches body SHA256")

# Decrypt rootfs
decrypted_rootfs = fort_rc4_decrypt(signature_contents["rc4_key"], rootfs_body, variant)
if decrypted_rootfs[:2] != b'\x1f\x8b':
    print(f"    [x] rootfs decryption failed")
    sys.exit(1)
print("    [+] Decryption successful!")

print()


# 4. Extract rootfs filesystem
rootfs_extract_path = f"{decrypted_out_dir}/ext-root/rootfs"
print(f"[4] Extracting decrypted rootfs into {rootfs_extract_path}")
if not extract_rootfs(decrypted_rootfs, rootfs_extract_path):
    print("    [x] rootfs extraction failed")
    sys.exit(1)

print("    [+] rootfs extracted successfuly!")