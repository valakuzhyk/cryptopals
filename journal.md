#Cryptopals journey

Here I will be keeping track of all of my notes, starting from challenge 2 and beyond. I had already done Challenge 1 (in python), so I was not really interested in journaling my journey through that. However, from this point forward, I think it would be a good habit to get into.

## Set 1
### Challenges 1-8
Late to the game...


## Set 2
### Challenge 9: Implement PKCS#7 padding
Yeah. So this was pretty easy. The only thing that I found required a little thinking about was how this padding behaves when a message fits into the block size. Thankfully there is a nice example on the spec that indicates how this should be done. 

One thing that was a little unclear to me in the problem was this quote
> One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize

It makes it seem like you can't have an odd multiple of the blocksize after padding, but the spec doesn't seem to approach this topic. We'll see if this causes issues down the road.

### Challenge 10: Implement CBC Mode
After having already implemented ECB mode, this was quite trivial. The wikipedia page's image on how information flows made this a little more straightforward, as the wording for this challenge was not very clear at all.

### Challenge 11: Create a ECB/CBC oracle
Again, this was quite trivial, since we have already talked about how to identify ECB. Especially when you have control over part of the plaintext, you can easily just send a repeating message, which would cause ECB to repeat as well (identical input blocks result in identical output blocks).

### Challenge 12: Byte-at-a-time ECB decrypt
This is the start of what I think is really cool. How multiple pieces of the puzzle come together to completely bypass all of the work that went into making a code secure. To think that all of the math that has gone into AES (from my perspective is an impressive amount), is broken by comparing results for each letter. You are only as strong as your weakest link. Looking forward to implementing this, which again, should be quite straightforward. I'm a little sad they gave away the technique, but I guess that's not really the point of these challenges (at least, not as far as I have seen)

### Challenge 13: ECB cut-and-pastes
At first I was worried that this would be complicated, but then its pretty easy to structure the blocks in a way that you can do this cut-and-paste attack. This is one of the punchlines for ECB based algorithms, which can't protect this "partial reuse" of other ciphertexts, among other things.

I am a bit unsatisified with the lack of generality that is present in this solution though. I'm hoping in subsequent solutions, other requirements will lead me to allow for a more generic implementation of the cut and past attack.

### Challenge 14: Byte-at-a-time ECB Decrypt redux
The first time I read this, since I knew it would be harder, I thought the problem implied that the random prefix was randomized each call. Rereading this, I see that you generate the random bytes, and prepend *that* string to every call. This is almost the same difficulty as the last one.

For the harder case, I think its still doable though, it's just nondeterministic. First you can (likely) identify the block size using the same technique (checking fluctuations in the output). Knowing that its ECB using the same technique, you can then keep a dictionary keyed by the hash ending (which encodes how close to the end of the block you are) and the letter inserted. We know there should be the same number of endings as the blockSize + 1 (changed by the padding), so we can start filling out the map: 

EndingBlock |  18c0adsf... | 9dsf3ji ... | ... 
letter 'a'  |  12y32918... | 1934793 ... | ...
letter 'b'  |  ...
letter 'c'  |

In here, we compare the penultimate block with one of the block_size+1 that we gather from not putting the letter there at all. 

To speed this process up, for long decryptions, you can start understanding the connection between the suffixes, (knowing which suffixes are one character before another one).

This technique is not guaranteed to work of course, there are cases when you could incorrectly identify the string, and you are never guaranteed to get this map of results (you could predict how long it would take, and optimize which lengths to letters to guess), but practically, I think it would be doable! Anyways back to the real problem...

The real trick was just to add a tirck to find the block end right before the start of the suffix. By using the fact that I can tell when I have two complete blocks under my control, I can then identify exactly how much input I used to get to that point, letting me know the size (mod blocksize) of the prefix. After accommodating for this, the problem is the same as before.

### Challenge 15: PKCS #7 Padding Validation
Yeahhhh, so I already did this to do the previous challenges properly. Don't see why you wouldn't have done this earlier. Though while implementing this, I can see a lot of potential for messing up edge cases.

### Challenge 16: CBC Bitflipping
So this one was pretty easy. As long as you control some data, you can essentially write whatever you want into the blocks, as long as you are willing to accept unknown data being written in right before it.

I didn't write the solution to this one generically, since it seems like this was a somewhat specific case. But again, if I find this to be useful, it'll be refactored appropriately.

## Some optimizations
The AES implementation was taking over 10 seconds. I looked into removing some of the extra bytes in the string that were unneeded. Even then they were taking quite a bit of time. Eventually I looked into the AES implementation, and by choosing the appropriate order for parameters to one of my functions (the polynomial multiplication) there was a 50% improvement in the time of the the ECB cracking code.

## Set 3
### Challenge 17: CBC Padding Oracle
As I was writing how this challenge had me unclear on what to do, the solution came to me. It's a slight modification of the previous challenge. Before, knowledge of the plaintext allowed me to modify the ciphertext to change how the message was decoded.
This time, instead, I want to use this knowledge of the decrypted data to solve for the original data.

This is the idea:

Go through all byte modifications of the last byte in the block before the last block. Hopefully, only one of them should result in the padding being correct. The byte you chose XORed with the padding byte "\0x01" results in the original plaintext.

 Now there is a chance that there are two values of this byte that make the padding correct (there can only be two). Now, one of them is definitely xoring to make the value 1, the other, some other value. However, if we mess around with the penultimate byte, only one of them will remain stable. After finding this first byte and controlling its value, the rest of the bytes we won't have to worry about this edge case however.

Notice how padding is irrelevant to this strategy. In fact, you should be able to conclude what the final bytes are for blocks in the middle of the message :) just make it the last block by moving all the rest after it.

## Set 3
### Challenge 18: Introducing CTR Mode
I'm intrigued at this mode, its not something that I have read about before, but I like how it makes a block cipher into a stream cipher, while also (seemingly) nullifying the attacks from earlier. Also, it doesn't need both decrypt and encrypt, which is nice.

That being said, the challenge was fairly straightforward.

## Set 3
### Challenge 19: Break fixed-nonce CTR using substitutions
I really disliked this challenge. I think its because they are telling me to solve this problem in a suboptimal way, when an early challenge kind of introduced this challenge as another challenge altogether. Either way, this clearly indicates that a fixed nonce can be a problem, yet even changing the nonce and making it public seemingly makes this a safer system. 

## Set 3
### Challenge 20: Break fixed-nonce CTR statistically
So I kinda cheated. I used the same solution to challenge 19 as challenge 20. In fact, I tried to use my solution to the XOR challenges earlier, but they were too slow XD In fact, this new strategy that I have of just checking whether the guess transforms characters into valid output outside of the code that scores english seemed to make the solution much easier. I think I very much overthought my XOR solution. However, I think that was because I kept getting the answer wrong because I had forgotten to base64 decode the input :\

All that aside, Since I was able to get the solution to these using the statistical approach using code that I used for the repeating key xor, I don't think that there is any usefulness in structuring the code in a way that it takes the different lines as a single string, rather than a repeating key XOR. The principle has been understood I think though (You can tell how much I want to move on to other kinds of crypto-breakage).

## Set 3
### Challenge 21: Implement MT19937
This was somewhat hard at first, trying to understand what the wikipedia page was communicating. But as I was implementing it, it became much easier to understand the intention of the algorithm, at least on a surface level. I never went into actually learning lie groups and algebras, so I can't say that I understand why they are doing all of these transformations, but I suppose, for now, that isn't the point of this. I have looked ahead in these challenges, and there is more theoretical stuff ahead. I imagine when I get there, deeper understanding will be had.
