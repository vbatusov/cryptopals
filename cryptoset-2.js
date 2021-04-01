'use strict';
import * as ct from './cryptotools.mjs';
import { readFileSync } from 'fs';

// Set 2 <https://cryptopals.com/sets/2>

// Learning task: unlike the dumb sequential layout of Set 1,
// organize the code here in some sort of containers which can be executed flexibly
// all at once or individually.
// Each challenge: function/object based on same template (class?)
// Individual execution routine: takes challenge as arg, does pretty printing
// "Main": Runs whatever challenges using calls to the execution routine

// Constructor function for challenges
// 'filepath' is a path to data file for current challenge (if any)
function Challenge(num, name, func, filepath, encoding) {
  console.log(`Building challenge ${num}...`)
  this.number = num;
  this.name = name;
  this.filepath = filepath;
  this.encoding = encoding;
  this.func = function() {
    console.log(`\n(Challenge #${this.number} not implemented yet.)\n`);
  };
  this.run = function() {
    // Read file, if given
    const data = (this.filepath !== null) ? ct.read_bytes_from_file(this.filepath, this.encoding) : null;
    console.log(`\n---------- Challenge ${this.number}: ${this.name} ----------`);
    if (this.filepath !== null)
      console.log(`Using file ${this.filepath}`);

    this.func(data); // Run the challenge

    console.log('----------------------- (end) -----------------------\n');
  };
}

// Takes a challenge set and runs all, sequentially
function main(ch_set) {
  console.log("================\nChallenge Set #2\n================");

  for (let ch_no in ch_set.challenges)
    ch_set.challenges[ch_no].run();
}

// [<ch#>, <ch. title>, <path-to-data-file>, <data-file-encoding>]
const meta = [["9", "Implement PKCS#7 padding", null, null],
              ["10", "Implement CBC mode", "10.txt", 'base64'],
              ["11", "An ECB/CBC detection oracle", null, null],
              ["12", "Byte-at-a-time ECB decryption (Simple)", null, null],
              ["13", "ECB cut-and-paste", null, null],
              ["14", "Byte-at-a-time ECB decryption (Harder)", null, null],
              ["15", "PKCS#7 padding validation", null, null],
              ["16", "CBC bitflipping attacks", null, null]
];

// Make this one a proper class with getters and setters
class ChallengeSet {

  constructor(set_number, meta) {
    this.number = set_number;
    this.challenges = {};
    for (let [num, name, filepath, enc] of meta)
      // Note: func is initially null (defaults to dummy), will be set later
      this.challenges[num] = new Challenge(num, name, null, filepath, enc);
  }

  get_ch(number) {
    return this.challenges[number];
  }

  set_ch_func(number, func) {
    this.challenges[number].func = func;
  }
}

let ch_set = new ChallengeSet(2, meta);


//////// Actual non-bookkeeping code /////////

ch_set.set_ch_func(9, function(){
  /* Pad any block to a specific block length, by appending the number of bytes
    of padding to the end of the block. For instance, "YELLOW SUBMARINE"
    padded to 20 bytes would be: "YELLOW SUBMARINE\x04\x04\x04\x04"
    Wikipedia: Padding is in whole bytes. The value of each added byte is
    the number of bytes that are added, i.e. N bytes, each of value N are added.
    <https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7>
  */
  const buffer = Buffer.from("YELLOW SUBMARINE", 'utf8');
  console.log(" In: " + buffer.toString('hex'));
  for (let i = 17; i < 24; i++) {
    const padded = ct.pad_block(buffer, i);
    console.log("Out: " + padded.toString('hex'));
  }
});

ch_set.set_ch_func(10, function(data){
  const test = function () {
    console.log("Testing the AES encrypt-decrypt first...");
    const key = "Minnie Mouse XXX";

    const cleartext = "Pussy cat, Pussy cat, Where have you been?";
    console.log(`Key: ${key} (len = ${key.length})`);
    console.log("Cleartext src: " + cleartext);
    console.log(`(len = ${cleartext.length} characters)`);

    const clear_buf = Buffer.from(cleartext, 'utf8');
    console.log("Cleartext buffer:");
    console.log(clear_buf);
    console.log(`(len = ${clear_buf.length} bytes)`);

    const clear_pad = ct.pad_block(clear_buf);
    console.log("Padded cleartext buffer:");
    console.log(clear_pad);
    console.log(`(len = ${clear_pad.length} bytes)`);

    const enc = ct.encrypt_AES128ECB(clear_pad, key);
    console.log("Encrypted buffer:");
    console.log(enc);
    console.log(`(len = ${enc.length} bytes)`);

    const dec = ct.decrypt_AES128ECB(enc, key);
    console.log("Decrypted buffer: ");
    console.log(dec);
    console.log(`(len = ${dec.length} bytes)`);
    console.log("Decoded: " + dec.toString('utf8'));
    console.log(`(len = ${dec.toString('utf8').length} characters)`);

    // Test CBC
    console.log("");
    console.log("Testing manual CBC");
    let cbc = ct.encrypt_CBC_manual(clear_buf, key);
    console.log(`CBC-encrypted buffer (len=${cbc.length} bytes):`);
    console.log(cbc);
    let uncbc = ct.decrypt_CBC_manual(cbc, key);
    console.log(`CBC-decrypted buffer (len=${uncbc.length} bytes):`);
    console.log(uncbc);
    console.log("Same in utf8:");
    console.log(uncbc.toString('utf8'));
  };
  //test();

  // Let's do the challenge now
  console.log("");
  const key = "YELLOW SUBMARINE";
  console.log("Data from file:");
  console.log(data);
  const clearbytes = ct.decrypt_CBC_manual(data, key);
  console.log("Cleartext:");
  console.log(clearbytes.toString('utf8'));

});




//////////////
main(ch_set);
