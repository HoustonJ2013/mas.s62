package main

import (
	"crypto/rand"
	"fmt"
)

/*
A note about the provided keys and signatures:
the provided pubkey and signature, as well as "HexTo___" functions may not work
with all the different implementations people could built.  Specifically, they
are tied to an endian-ness.  If, for example, you decided to encode your public
keys as (according to the diagram in the slides) up to down, then left to right:
<bit 0, row 0> <bit 0, row 1> <bit 1, row 0> <bit 1, row 1> ...

then it won't work with the public key provided here, because it was encoded as
<bit 0, row 0> <bit 1, row 0> <bit 2, row 0> ... <bit 255, row 0> <bit 0, row 1> ...
(left to right, then up to down)

so while in class I said that any decisions like this would work as long as they
were consistent... that's not actually the case!  Because your functions will
need to use the same ordering as the ones I wrote in order to create the signatures
here.  I used what I thought was the most straightforward / simplest encoding, but
endian-ness is something of a tabs-vs-spaces thing that people like to argue
about :).

So for clarity, and since it's not that obvious from the HexTo___ decoding
functions, here's the order used:

secret keys and public keys:
all 256 elements of row 0, most significant bit to least significant bit
(big endian) followed by all 256 elements of row 1.  Total of 512 blocks
of 32 bytes each, for 16384 bytes.
For an efficient check of a bit within a [32]byte array using this ordering,
you can use:
    arr[i/8]>>(7-(i%8)))&0x01
where arr[] is the byte array, and i is the bit number; i=0 is left-most, and
i=255 is right-most.  The above statement will return a 1 or a 0 depending on
what's at that bit location.

Messages: messages are encoded the same way the sha256 function outputs, so
nothing to choose there.

Signatures: Signatures are also read left to right, MSB to LSB, with 256 blocks
of 32 bytes each, for a total of 8192 bytes.  There is no indication of whether
the provided preimage is from the 0-row or the 1-row; the accompanying message
hash can be used instead, or both can be tried.  This again interprets the message
hash in big-endian format, where
    message[i/8]>>(7-(i%8)))&0x01
can be used to determine which preimage block to reveal, where message[] is the
message to be signed, and i is the sequence of bits in the message, and blocks
in the signature.

Hopefully people don't have trouble with different encoding schemes.  If you
really want to use your own method which you find easier to work with or more
intuitive, that's OK!  You will need to re-encode the key and signatures provided
in signatures.go to match your ordering so that they are valid signatures with
your system.  This is probably more work though and I recommend using the big
endian encoding described here.

*/

// Forge is the forgery function, to be filled in and completed.  This is a trickier
// part of the assignment which will require the computer to do a bit of work.
// It's possible for a single core or single thread to complete this in a reasonable
// amount of time, but may be worthwhile to write multithreaded code to take
// advantage of multi-core CPUs.  For programmers familiar with multithreaded code
// in golang, the time spent on parallelizing this code will be more than offset by
// the CPU time speedup.  For programmers with access to 2-core or below CPUs, or
// who are less familiar with multithreaded code, the time taken in programming may
// exceed the CPU time saved.  Still, it's all about learning.
// The Forge() function doesn't take any inputs; the inputs are all hard-coded into
// the function which is a little ugly but works OK in this assigment.
// The input public key and signatures are provided in the "signatures.go" file and
// the code to convert those into the appropriate data structures is filled in
// already.
// Your job is to have this function return two things: A string containing the
// substring "forge" as well as your name or email-address, and a valid signature
// on the hash of that ascii string message, from the pubkey provided in the
// signatures.go file.
// The Forge function is tested by TestForgery() in forge_test.go, so if you
// run "go test" and everything passes, you should be all set.
func Forge() (string, Signature, error) {
	// decode pubkey, all 4 signatures into usable structures from hex strings
	pub, err := HexToPubkey(hexPubkey1)
	if err != nil {
		panic(err)
	}

	sig1, err := HexToSignature(hexSignature1)
	if err != nil {
		panic(err)
	}
	sig2, err := HexToSignature(hexSignature2)
	if err != nil {
		panic(err)
	}
	sig3, err := HexToSignature(hexSignature3)
	if err != nil {
		panic(err)
	}
	sig4, err := HexToSignature(hexSignature4)
	if err != nil {
		panic(err)
	}

	var sigslice []Signature
	sigslice = append(sigslice, sig1)
	sigslice = append(sigslice, sig2)
	sigslice = append(sigslice, sig3)
	sigslice = append(sigslice, sig4)

	var msgslice []Message

	msgslice = append(msgslice, GetMessageFromString("1"))
	msgslice = append(msgslice, GetMessageFromString("2"))
	msgslice = append(msgslice, GetMessageFromString("3"))
	msgslice = append(msgslice, GetMessageFromString("4"))

	fmt.Printf("ok 1: %v\n", Verify(msgslice[0], pub, sig1))
	fmt.Printf("ok 2: %v\n", Verify(msgslice[1], pub, sig2))
	fmt.Printf("ok 3: %v\n", Verify(msgslice[2], pub, sig3))
	fmt.Printf("ok 4: %v\n", Verify(msgslice[3], pub, sig4))

	msgString_pre := "my forge; Jingbo Liu; jingbo.liu2013@gmail.com;"
	var sig Signature

	// your code here!
	// ==
	// Get the secret keys from known signature
	// Randomly guess the unknown secret keys and verify the message and public keys
	// Add nounces into my message as a variance in the random guess

	// get the known screate keys and save in a map; map key from 0 - 511,
	knownblocks := make(map[int]Block)
	si := 0
	for mi, msg_ := range msgslice { // loop signatures
		si = 0
		for _, bk := range msg_ { // loop for all bits
			for j := 7; j >= 0; j-- {
				mask := byte(1 << uint(j))
				if (bk & mask) == 0 {
					// sanity check if the signature is consistent
					_, prs := knownblocks[si]
					if prs && knownblocks[si] != sigslice[mi].Preimage[si] {
						fmt.Printf("The existing sinatures are not consistent")
					} else {
						knownblocks[si] = sigslice[mi].Preimage[si]
					}
				} else {
					_, prs := knownblocks[si+256]
					if prs && knownblocks[si+256] != sigslice[mi].Preimage[si] {
						fmt.Printf("The existing sinatures are not consistent")
					} else {
						knownblocks[si+256] = sigslice[mi].Preimage[si]
					}
				}
				si += 1
			}
		}
	}
	fmt.Printf("There are %v out of 512 signatures known \n", len(knownblocks))

	// Explore the unknown secret keys and messages to forge a signature

	msgString := msgString_pre

	for nounces_i := 0; nounces_i < 1e9; nounces_i++ {
		nounces_s, _ := GenerateRandomString(8)
		msgString = msgString_pre + nounces_s
		// fmt.Printf(msgString, "\n")
		mymsg := GetMessageFromString(msgString)
		si = 0
		for _, bk := range mymsg { // loop for all bits
			for j := 7; j >= 0; j-- {
				mask := byte(1 << uint(j))
				if (bk & mask) == 0 {
					// sanity check if the signature is consistent
					_, prs := knownblocks[si]
					if prs {
						sig.Preimage[si] = knownblocks[si]
					} else {
						_, err := rand.Read(sig.Preimage[si][:])
						// fmt.Printf("%v Generated random block %x \n", si, sig.Preimage[si].ToHex())
						if err != nil {
							return msgString, sig, err
						}
					}
				} else {
					_, prs := knownblocks[si+256]
					if prs {
						sig.Preimage[si] = knownblocks[si+256]
					} else {
						_, err := rand.Read(sig.Preimage[si][:])
						// fmt.Printf("%v Generated random block %x \n", si, sig.Preimage[si].ToHex())
						if err != nil {
							return msgString, sig, err
						}
					}
				}
				si += 1
				// fmt.Printf("Index %v \n", si)
			}
		}
		if Verify(mymsg, pub, sig) {
			return msgString, sig, nil
		}

	}

	return msgString, sig, nil

}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateRandomString returns a securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	bytes, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = letters[b%byte(len(letters))]
	}
	return string(bytes), nil
}

// hint:
// arr[i/8]>>(7-(i%8)))&0x01
