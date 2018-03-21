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
