// https://developer.mozilla.org/en-US/docs/Web/JavaScript/A_re-introduction_to_JavaScript

/* Task: do something meaningful with JavaScript
Details: Elliptic curve cryptography
https://arstechnica.com/information-technology/2013/10/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/
https://cryptopals.com/sets/1

*/

'use strict';
import * as ct from './cryptotools.mjs';


function checkResAns(res, ans) {
  console.log(`Computed: ${res}`);
  console.log(`Expected: ${ans}`);
  if (res === ans)
    console.log("MATCH\n");
  else
    console.log("FAIL\n");
}

////////////////////////////////////////////////
console.log("Challenge 1: Convert hex to base64")
const in1 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
const ans1 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

checkResAns(ct.hex2base64(in1), ans1);


////////////////////////////////////////////////
console.log("Challenge 2: Fixed XOR");
// Just a XOR of two hex strings
const in2_1 = "1c0111001f010100061a024b53535009181c";
const in2_2 = "686974207468652062756c6c277320657965";
const ans2 = "746865206b696420646f6e277420706c6179";

let res2 = ct.bxor(Buffer.from(in2_1, 'hex'), Buffer.from(in2_2, 'hex'), true).toString('hex');
checkResAns(res2, ans2);


////////////////////////////////////////////////
console.log("Challenge 3: Single-byte XOR cypher");
const in3 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
// has been XOR'd against a single character. Find the key, decrypt the message.

let res3 = ct.guess_single_byte(Buffer.from(in3, 'hex'));
console.log("  Cypher byte: " + res3[2].toString(2))
console.log("    Cleartext: " + res3[0])


////////////////////////////////////////////////
console.log("\nChallenge 4: Detect single-character XOR");
const filepath = "./4.txt"
import { readFile } from 'fs/promises';
import { readFileSync } from 'fs';

// Content is a multiline string
// No return, just prints solution
function find_encoded_string(content) {
  let least_error = Infinity;
  let best;
  let line_no = 1;
  for (let line of content.split('\n')) {
    let guess = ct.guess_single_byte(Buffer.from(line, 'hex'));
    if (guess[1] < least_error) {
      least_error = guess[1];
      best = [guess[0], guess[1], guess[2], line_no, line];
    }
    line_no++;
  }
  console.log(best);
}

function async_solution() {
  readFile(filepath, 'utf8').then(
    content => find_encoded_string(content),
    error => console.error(error)
  );
}

function sync_solution() {
  find_encoded_string(readFileSync(filepath, 'utf8'));
}

//async_solution();
sync_solution();


////////////////////////////////////////////////
console.log("\nChallenge 5: Implement repeating-key XOR");
const key = "ICE" // Buffer.from("ICE", 'utf8');
const phrase = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

const byte_res = ct.bxor(Buffer.from(key), Buffer.from(phrase), true);
const res5 = byte_res.toString('hex');
console.log(`Encoded: ${res5}`);
console.log("Decoded: " + ct.bxor(Buffer.from(key), byte_res, true).toString('utf8'));
const ans5 = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
checkResAns(res5, ans5);


////////////////////////////////////////////////
console.log("\nChallenge 6: Break repeating-key XOR");
// File '6.txt' has been base64'd after being encrypted with repeating-key XOR.
// Decrypt it.

// Load the file
let base64lines = readFileSync('6.txt', 'utf8');

let base64cont = base64lines.split('\n').join('');
//console.log(base64cont);
const cypherbytes = Buffer.from(base64cont, 'base64');
console.log(`(${cypherbytes.length} bytes):`);
console.log(cypherbytes);

let distance_key = []; // to store results
// Guess keysize statistically
for (let keysize = 2; keysize <= 40; keysize++) {
  //console.log("Looking at keysize=" + keysize)
  // Take the first 4 keysize-sized bytes,
  // compute Hamming distances between each pair (six in all)
  // Average and record result. Then pick the smallest.
  const num_blocks = 4;
  const num_pairs = num_blocks * (num_blocks - 1) / 2;
  let avg_dist = 0;
  for (let i = 0; i < num_blocks - 1; i++) {
    for (let j = i + 1; j < num_blocks; j++) {
      // compute dist between i-th and j-th block of size keysize
      // and add 1/keysize-th part of it to avg_dist
      let block1 = cypherbytes.slice(i * keysize, (i+1) * keysize);
      let block2 = cypherbytes.slice(j * keysize, (j+1) * keysize);
      //console.log(`New pair: ${i * keysize}--${(i+1) * keysize} and ${j * keysize}--${(j+1) * keysize}. Diff=${ct.hamming_dist_buffers(block1, block2)}`);
      avg_dist += ct.hamming_dist_buffers(block1, block2) / num_pairs;
    }
  }
  //console.log(`Avg. dist for keysize=${keysize} is ${avg_dist} (abs) and ${avg_dist / keysize} (normalized)`)
  avg_dist /= keysize; // Normalize wrt. keysize
  //console.log(`keysize=${keysize} : ${avg_dist}`)
  distance_key.push([avg_dist, keysize]);
}

// Best keysize candidates
let best_keysizes = distance_key.sort().slice(0,3).map(x => x[1]);
console.log("Best keysizes are " + best_keysizes);

// Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
// Try this for each candidate keysize
console.log(cypherbytes);
for (let keysize of best_keysizes) {
  let blocks = []; // array of keysize-sized buffers (except, possibly, the last)
  console.log("Trying good keysize " + keysize);
  for (let i = 0; i < cypherbytes.length; i += keysize) { // i = start of new block
    let new_block = cypherbytes.slice(i, i + keysize);
    blocks.push(new_block);
    //console.log(`i=${i}`)
    //console.log("New block:");
    //console.log(new_block);
  }
  // Now transpose the blocks: make a block that is the first byte of every
  // block, and a block that is the second byte of every block, and so on.
  //blocks = [[1,2,3], [4,5,6]]; // debug
  let transposed = [];
  for (let i = 0; i < keysize; i++) { // for each column index
    transposed.push(blocks.map(x => x[i])); // push column as row
  }

  // Solve each block as if it was single-character XOR. You already have code to do this.
  //console.log("For each of the transposed blocks:")
  let key = [];
  for (let block of transposed) {
    let guess = ct.guess_single_byte(Buffer.from(block));
    //console.log("  Cypher byte: " + guess[2].toString(2));
    //console.log("    Cleartext: " + guess[0]);
    key.push(guess[2]);
  }
  let key_str = Buffer.from(key).toString('utf8');
  console.log(`KEY = ${key_str}`);
  let cleartext = ct.bxor(Buffer.from(key), cypherbytes, true).toString();
  console.log(`Cleartext: ${cleartext}`);
  break; // Don't try other sizes, the first one is good
}
