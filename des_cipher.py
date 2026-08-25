#des algorithm

from constants import IP, IP_inv, E, P, S_box, PC1, PC2, SHIFTS

#helpers
block_size = 8

#bytes to bits function
def bytes_tobits(data):
    bits = []
    for byte in data:
        for i in range(7,-1,-1):
            bits.append((byte >> i) & 1)
    return bits

#bits to bytes function
def bits_tobytes(bits):
    data = bytearray()
    for i in range(0,len(bits),8):
        byte = 0
        for j in bits[i:i+8]:
            byte = (byte << 1)|j
        data.append(byte)
    return bytes(data)

#permutation function
def permute(bits,table):
    '''k=0
    for pos in table:
        bits[k] = bits[pos-1]
        k++
        '''
    return [bits[pos-1] for pos in table]

#xor-ing two bit lists 
def xor_list(left,right):
    if len(left) != len(right):
        raise ValueError("Both bit lists must have the same length")
    return [x^y for x,y in zip(right,left)]

#left shift for the keey schedule
def left_rotate(bits,n):
    n = n % len(bits)
    return bits[n:]+bits[:n]

def split(bits):
    mid = len(bits)//2
    return bits[:mid],bits[mid:]


# key schedule
def generate_round_keys(key):
    '''
    64 -> pc1 -> 56 -> split to 28 -> left rotate -> join -> pc2 -> 48
    '''
    if len(key) != 8:
        raise ValueError("DES keys must be exactly 8 bytes")
        
    key_bits = bytes_tobits(key)
    
    #pc1 to 56 bits
    permuted_key = permute(key_bits,PC1)
    
    #split into 28 bits
    c,d = split(permuted_key)

    round_keys = []

    for i in SHIFTS:
        c = left_rotate(c,i)
        d = left_rotate(d,i)
        combined = c + d
        
        #pc2 to 4 bits
        round_key = permute(combined,PC2)
        round_keys.append(round_key)

    return round_keys

# Round function
def s_box(bits):
    '''48 bits into 32 bits'''
    output = []
    for i in range(8):
        chunk = bits[i*6:(i+1)*6]
        row = (chunk[0] << 1)|chunk[5]
        column = ((chunk[1] << 3)|(chunk[2] << 2)|(chunk[3] << 1)|chunk[4])
        value = S_box[i][row][column]
        #integer valur to binary
        output.extend([(value >> 3) & 1, (value >> 2) & 1, (value >> 1) & 1, value & 1])
    return output

    
def f_func(right,round_key):
    '''32 -> E box -> 48 -> xor with round_key -> sbox -> 32 ->pbox -> 32'''
    expanded = permute(right,E)
    xored = xor_list(expanded,round_key)
    #nearly_done = s_box(xored)
    substituted = s_box(xored)
    output = permute(substituted,P)
    return output


# Feistel Network structure
def feistel_network(block,round_keys):
    '''same structure used for both encryption and decryption'''
    if len(block) != 8:
        raise ValueError("DES blocks must be exactly 8 bytes")
    
    block_bits = bytes_tobits(block)

    #inittial permutation
    permuted = permute(block_bits,IP)
    left,right = split(permuted)
    for key in round_keys:
        left1 = right
        right1 = xor_list(left,f_func(right,key))
        left,right = left1,right1

    combined = right + left
    final_bits = permute(combined,IP_inv)
    final = bits_tobytes(final_bits)
    return final


# Encrytption
def encrypt(pt,key):
    '''encrypt one block'''
    round_keys = generate_round_keys(key)
    ct = feistel_network(pt,round_keys)
    return ct

# Decryption
def decrypt(ct,key):
    '''decrypts one block'''
    round_keys = generate_round_keys(key)
    pt = feistel_network(ct,round_keys[::-1])
    return pt