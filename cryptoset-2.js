'use strict';
import * as ct from './cryptotools.mjs';

// Set 2 <https://cryptopals.com/sets/2>

// Learning task: unlike the dumb sequential layout of Set 1,
// organize the code here in some sort of containers which can be executed flexibly
// all at once or individually.
// Each challenge: function/object based on same template (class?)
// Individual execution routine: takes challenge as arg, does pretty printing
// "Main": Runs whatever challenges using calls to the execution routine

// Constructor function for challenges
function Challenge(num, name, func) {
  this.number = num;
  this.name = name;
  this.func = function() {
    console.log(`\n(Challenge #${this.number} not implemented yet.)\n`);
  };
  this.run = function() {
    console.log(`\n---------- Challenge ${this.number}: ${this.name} ----------`);
    this.func();
    console.log('----------------------- (end) -----------------------\n');
  };
}

// Takes an challenge set and runs all, sequentially
function main(ch_set) {
  console.log("================\nChallenge Set #2\n================");
  // Make an iterator for ChallengeSet
  for (let ch_no in ch_set.challenges)
    ch_set.challenges[ch_no].run();
}

//////// Actual non-bookkeeping code ///////
const meta = [["9", "Implement PKCS#7 padding"],
              ["10", "Implement CBC mode"],
              ["11", "An ECB/CBC detection oracle"],
              ["12", "Byte-at-a-time ECB decryption (Simple)"],
              ["13", "ECB cut-and-paste"],
              ["14", "Byte-at-a-time ECB decryption (Harder)"],
              ["15", "PKCS#7 padding validation"],
              ["16", "CBC bitflipping attacks"],
];

// Make this one a proper class with getters and setters
class ChallengeSet {

  constructor(set_number, meta) {
    this.number = set_number;
    this.challenges = {};
    for (let [num, name] of meta)
      this.challenges[num] = new Challenge(num, name, null);
  }

  get_ch(number) {
    return this.challenges[number];
  }

  set_ch_func(number, func) {
    this.challenges[number].func = func;
  }
}

let ch_set = new ChallengeSet(2, meta);

ch_set.set_ch_func(9, function(){
  /* Pad any block to a specific block length, by appending the number of bytes
    of padding to the end of the block. For instance, "YELLOW SUBMARINE"
    padded to 20 bytes would be: "YELLOW SUBMARINE\x04\x04\x04\x04"
    Wikipedia: Padding is in whole bytes. The value of each added byte is
    the number of bytes that are added, i.e. N bytes, each of value N are added.
  */
  const buffer = Buffer.from("YELLOW SUBMARINE", 'utf8');
  console.log(" In: " + buffer.toString('hex'));
  for (let i = 17; i < 24; i++) {
    const padded = ct.pad_block(buffer, i);
    console.log("Out: " + padded.toString('hex'));
  }
});

ch_set.set_ch_func(10, function(){
  
});




//////////////
main(ch_set);
