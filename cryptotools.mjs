// Letter and space frequency in English
export let eng_freq = normalize_map(new Map([
  ["a", 0.0834], ["b", 0.0154], ["c", 0.0273], ["d", 0.0414],
  ["e", 0.1260], ["f", 0.0203], ["g", 0.0192],
  ["h", 0.0611], ["i", 0.0671], ["j", 0.0023], ["k", 0.0087],
  ["l", 0.0424], ["m", 0.0253], ["n", 0.0680], ["o", 0.0770], ["p", 0.0166],
  ["q", 0.0009], ["r", 0.0568], ["s", 0.0611],
  ["t", 0.0937], ["u", 0.0285], ["v", 0.0106],
  ["w", 0.0234], ["x", 0.0020], ["y", 0.0204], ["z", 0.0006],
  // THe following is hand-made based on assumption that capital letters
  // occur 1/10 as frequently
  ["A", 0.00834], ["B", 0.00154], ["C", 0.00273], ["D", 0.00414],
  ["E", 0.01260], ["F", 0.00203], ["G", 0.00192],
  ["H", 0.00611], ["I", 0.00671], ["J", 0.00023], ["K", 0.00087],
  ["L", 0.00424], ["M", 0.00253], ["N", 0.00680], ["O", 0.00770], ["P", 0.00166],
  ["Q", 0.00009], ["R", 0.00568], ["S", 0.00611],
  ["T", 0.00937], ["U", 0.00285], ["V", 0.00106],
  ["W", 0.00234], ["X", 0.00020], ["Y", 0.00204], ["Z", 0.00006],
  [" ", 1/5.7] // avg. word length 4.7, so 5.7 with space, so 1/5.7 is space freq.
]));

function normalize_map (map) {  
  const total = sum_map_vals(map);
  let map2 = new Map();
  for (let [k, v] of map)
    map2.set(k, v / total);
  return map2;
}

// Pretty printing for maps
function print_map (map) {
  for (let [k, v] of map)
    console.log(`${k} => ${v}`);
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
