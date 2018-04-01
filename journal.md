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

## Set 2
### Challenge 10: Implement CBC Mode
After having already implemented ECB mode, this was quite trivial. The wikipedia page's image on how information flows made this a little more straightforward, as the wording for this challenge was not very clear at all.

## Set 2
### Challenge 11: Create a ECB/CBC oracle
Again, this was quite trivial, since we have already talked about how to identify ECB. Especially when you have control over part of the plaintext, you can easily just send a repeating message, which would cause ECB to repeat as well (identical input blocks result in identical output blocks).

## Set 2
### Challenge 12: Byte-at-a-time ECB decrypt
This is the start of what I think is really cool. How multiple pieces of the puzzle come together to completely bypass all of the work that went into making a code secure. To think that all of the math that has gone into AES (from my perspective is an impressive amount), is broken by comparing results for each letter. You are only as strong as your weakest link. Looking forward to implementing this, which again, should be quite straightforward. I'm a little sad they gave away the technique, but I guess that's not really the point of these challenges (at least, not as far as I have seen)

## Set 2
### Challenge 13: ECB cut-and-pastes
At first I was worried that this would be complicated, but then its pretty easy to structure the blocks in a way that you can do this cut-and-paste attack. This is one of the punchlines for ECB based algorithms, which can't protect this "partial reuse" of other ciphertexts, among other things.

I am a bit unsatisified with the lack of generality that is present in this solution though. I'm hoping in subsequent solutions, other requirements will lead me to allow for a more generic implementation of the cut and past attack.

## Set 2
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