import { readFileSync } from 'fs';
import { createCipheriv, createDecipheriv } from 'crypto';

// Letter and space frequency in English
export let eng_freq = normalize_map(add_caps_to_map(new Map([
  ["a", 0.0834], ["b", 0.0154], ["c", 0.0273], ["d", 0.0414],
  ["e", 0.1260], ["f", 0.0203], ["g", 0.0192],
  ["h", 0.0611], ["i", 0.0671], ["j", 0.0023], ["k", 0.0087],
  ["l", 0.0424], ["m", 0.0253], ["n", 0.0680], ["o", 0.0770], ["p", 0.0166],
  ["q", 0.0009], ["r", 0.0568], ["s", 0.0611],
  ["t", 0.0937], ["u", 0.0285], ["v", 0.0106],
  ["w", 0.0234], ["x", 0.0020], ["y", 0.0204], ["z", 0.0006],
  [" ", 1/5.7] // avg. word length 4.7, so 5.7 with space, so 1/5.7 is space freq.
])));

function normalize_map (map) {
  const total = sum_map_vals(map);
  let map2 = new Map();
  for (let [k, v] of map)
    map2.set(k, v / total);
  return map2;
}

function add_caps_to_map(map) {
  let map2 = new Map();
  for (let [k, v] of map) {
    map2.set(k, v);
    const k_upper = k.toUpperCase();
    if (!map.has(k_upper))
      map2.set(k_upper, v / 30); // Assume uppercase is 30 times more rare
  }
  return map2;
}

// Transcode a hex string to base64
export function hex2base64(hex) {
  return Buffer.from(hex, 'hex').toString('base64');
}

// Sum all the values of a map
function sum_map_vals (map) {
  let sum = 0;
  for (let [k, v] of map)
    sum += v;
  return sum;
}

// Given two byte buffers, return a XOR of the two
// If unequal lengths and wrap=true, the shorter one loops over
export function bxor(b1, b2, wrap=false, debug=false) {
  if (b1.length < b2.length)
    [b1, b2] = [b2, b1]; // Now, b1 is not shorter than b2
  if (!wrap) { // Pad out b2 with zeroes
    b2 = Buffer.concat([b2, Buffer.alloc(b1.length - b2.length)]);
  }

  let res_buf = Buffer.alloc(b1.length);

  for (let i = 0, j = 0; i < b1.length; i++, j = i % b2.length) {
    if (debug)
      console.log("  " + String.fromCharCode(b1[i]) + " xor " + String.fromCharCode(b2[j]));
    res_buf[i] = b1[i] ^ b2[j];
  }

  return res_buf;
}

// Cleanse string from all but alphabetic characters; convert to lowercase
export function clean_str(string) {
  return string.toLowerCase().replace(/[^a-z]/gmi, "")
}

// Extract a character frequency map from a string
// Case-insensitive
export function get_freq_map (dirty_string) {
  // Don't throw away crazy characters, count them towards the error!
  let string = dirty_string; //.toLowerCase(); //clean_str(dirty_string)
  let map = new Map();
  let inc = 1 / string.length;  // increment per occurrence

  for (let i = 0; i < string.length; i++) {
    let letter = string.charAt(i);

    if (map.has(letter))
      map.set(letter, +map.get(letter) + inc);
    else
      map.set(letter, inc);
  }
  return map; // May not cover entire alphabet!
}

// Compute cumulative error by comparing two frequency maps
export function get_freq_error(map) {
  // For each key of REFERENCE map, compute error, sum errors up
  // If given map has no entry for letter, assume 0
  let error = 0;
  //console.log("Compute error for chars that exist")
  for (let [k,v] of eng_freq) {
    let v2 = (map.has(k) ? map.get(k) : 0);
    error += Math.abs(v - v2);
  }

  // Also, for every non-dictionary letter in given map, add to error
  for (let [k, v] of map)
    if (!eng_freq.has(k))
      error += Math.abs(v);

  return error;
}

// Guess the single-byte XOR cypher
// In: byte buffer cyphertext
// Out: [cleartext, error, byte]
export function guess_single_byte(b) {

  let least_error = Infinity;
  let best; // [cleartext, error, byte]

  let byte = 0 // Byte guess
  //console.log("Starting guessing...")
  while (byte < 256) {
    let xor_buf = bxor(b, Buffer.alloc(1, byte), true); // Decypher
    let cleartext = xor_buf.toString('utf8'); // Decode

    // Assign score based on error
    let error = get_freq_error(get_freq_map(cleartext));

    if (error < least_error) {
      let impr = least_error - error;
      //console.log(`Better candidate (-${impr}): ${cleartext}`);
      best = [cleartext, error, byte];
      least_error = error;
    }
    byte += 1;
  }
  return best;
}

// A function to compute the edit distance/Hamming distance between two strings.
// The Hamming distance is just the number of differing bits.
// The distance between:
//   this is a test
// and
//   wokka wokka!!!
// is 37.
export function hamming_dist_strings(s1, s2) {
  return hamming_dist_buffers(Buffer.from(s1, 'utf8'), Buffer.from(s2, 'utf8'));
}

export function hamming_dist_buffers(b1, b2) {
  let accum = 0;
  for (let byte of bxor(b1, b2))
    accum += count_ones(byte.toString(2));
  return accum;
}

function count_ones(string) {
  return (string.match(/1/g) || []).length;
}

export function score_keysizes(cypherbytes, from=2, to=40) {
  console.log(`Guessing keysize in range [${from}, ${to}]`);
  let distance_keysize = [];
  for (let keysize = from; keysize <= to; keysize++) {
    // Take the first 4 keysize-sized bytes,
    // compute Hamming distances between each pair (six in all)
    // Average and record result. Then pick the smallest.
    const num_blocks = 4;
    const num_pairs = num_blocks * (num_blocks - 1) / 2;
    let avg_dist = 0;
    for (let i = 0; i < num_blocks - 1; i++) {
      for (let j = i + 1; j < num_blocks; j++) {
        // compute dist between i-th and j-th block of size keysize
        // and add 1/num_pairs-th part of it to avg_dist
        const block1 = cypherbytes.slice(i * keysize, (i+1) * keysize);
        const block2 = cypherbytes.slice(j * keysize, (j+1) * keysize);

        avg_dist += hamming_dist_buffers(block1, block2) / num_pairs;
      }
    }
    avg_dist /= keysize; // Normalize wrt. keysize
    distance_keysize.push([avg_dist, keysize]);
  }
  return distance_keysize;
}

// Break a buffer (array) of bytes into an array of blocksized arrays
export function array_to_blocks(cypherbytes, blocksize) {
  let blocks = [];
  for (let i = 0; i < cypherbytes.length; i += blocksize)
    blocks.push(cypherbytes.slice(i, i + blocksize));
  return blocks;
}

// Input: a proper matrix (array of arrays)
// Output: same, transposed
export function transpose_blocks(blocks) {
  let transposed = [];
  for (let i = 0; i < blocks[0].length; i++) // for each column index
    transposed.push(blocks.map(x => x[i])); // push column as row
  return transposed;
}


export function read_bytes_from_file(filename, encoding) {
  const lines = readFileSync(filename, 'utf8');
  const continuous = lines.split('\n').join('');
  return Buffer.from(continuous, encoding);
}

export function read_bytes_from_base64_file(filename) {
  return read_bytes_from_file(filename, 'base64');
}

// Updated: now pads an arbitrary-length buffer to a multiple of block size
export function pad_block(buffer, size=16) {
  const delta = size - (buffer.length % size);
  return Buffer.concat([buffer, Buffer.alloc(delta, delta)]);
}

// Simple AES-128 with ECB back-and-forth
// Cleartext and cyphertext are in byte buffers
// Key is a string
// Works on single and multiple blocks, padded or not
// If not padded to size, message will not decrypt!
export function encrypt_AES128ECB(bytes, key_string) {
  const cipher = createCipheriv('AES-128-ECB', key_string, null);
  cipher.setAutoPadding(false); // VERY IMPORTANT, othewise weird stuff happens
  return Buffer.concat([cipher.update(bytes), cipher.final()]);
}

// Fails when bytes are not a multiple of BLOCKSIZE
export function decrypt_AES128ECB(bytes, key_string) {
  const decipher = createDecipheriv('AES-128-ECB', key_string, null);
  decipher.setAutoPadding(false); // VERY IMPORTANT, othewise weird stuff happens
  return Buffer.concat([decipher.update(bytes), decipher.final()]);
}

export const BLOCKSIZE = 16;
// Encrypt using Cipher Block Chaining by hand
// Takes any buffer, pads to size, then does CBC with blocksize=16B
// Returns a buffer
export function encrypt_CBC_manual(bytes, key_string, iv) {
  const clear_padded = pad_block(bytes, BLOCKSIZE);
  let new_blocks = [];
  let prev_cypher = iv || Buffer.alloc(BLOCKSIZE);
  for (let i = 0; i < clear_padded.length; i += BLOCKSIZE) {
    const block = clear_padded.slice(i, i + BLOCKSIZE);
    let new_cypher = encrypt_AES128ECB(bxor(block, prev_cypher), key_string);
    new_blocks.push(new_cypher);
    prev_cypher = new_cypher;
  }
  return Buffer.concat(new_blocks);
}

// And decrypt...
// Assume bytes are a multiple of blocksize
export function decrypt_CBC_manual(bytes, key_string, iv) {
  // For each block of cypherbytes, decrypt and xor with previous, write clearbytes
  //console.log("Decryption main routine");
  let clear_blocks = [];
  let prev_cypher = iv || Buffer.alloc(BLOCKSIZE);
  //console.log("IV = ");
  //console.log(prev_cypher);
  for (let i = 0; i < bytes.length; i += BLOCKSIZE) {
    const cypherblock = bytes.slice(i, i + BLOCKSIZE);
    //console.log("-> Looking at cypher block");
    //console.log(cypherblock);
    const xorblock = decrypt_AES128ECB(cypherblock, key_string);
    //console.log("-> Becomes xor block");
    //console.log(xorblock);
    const clearblock = bxor(xorblock, prev_cypher);
    //console.log("-> Becomes clear block");
    //console.log(clearblock);
    clear_blocks.push(clearblock);
    prev_cypher = cypherblock;
  }
  return Buffer.concat(clear_blocks);
}
