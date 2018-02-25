# ot.py
RSA based t-out-of-n oblivious transfer (OT) in Python. This was made for fun: I make no claims of real cryptographic security.

OT is used when you have two parties, Alice and Bob. Alice has `n` secrets, and wants to share `t` of them with Bob without revealing any of the other ones. Bob wants to pick a certain subset of Alices secrets of size `t`, but does not want to reveal to Alice which `t` secrets he picks. OT can be used to solve this problem, allowing Alice to "obliviously" transfer `t` secrets to Bob.

My implementation is based on this paper: [Non-Interactive t-out-of-n Oblivious Transfer Based on the RSA Cryptosystem](http://ieeexplore.ieee.org.sci-hub.io/stamp/stamp.jsp?arnumber=4457650)

## Usage

`ot.py` provides two classes, `Alice` and `Bob`. For this example, Let's say Alice has three secrets, `Secret message 1`, `Secret message 2`, and `Secret message 3`, and Bob will grab two of them (2 out of 3 OT).

On Alice's terminal:

```python
> from ot import *
> secrets = [b'Secret message 1', b'Secret message 2', b'Secret message 3']
> alice = Alice(secrets, 2, len(secrets[0]))
```

We can now run `setup` on the `Alice` object, which will begin the OT. By default, it writes json to a file called `alice_setup.json`.
```python
> alice.setup()
Pubkey and hashes published.
```

Now switch to Bob's terminal. To create a `Bob` object, we pass the number of messages Alice has, the number of desired messages, and a list of the IDs of the messages we want. Let's say we want the first and the third secrets Alice has:
```python
> from ot import *
> bob = Bob([0, 2])
> bob.setup()
Polynomial published.
```
By default, `Bob.setup` reads from `alice_setup.json` and writes to `bob_setup.json`.

Now back to Alice's terminal:

```python
> alice.transmit()
G has been published.
```

This by defualt reads from `bob_setup.json` and writes to `alice_dec.json`.

Finally, back to Bob's terminal:
```python
> bob.receive()
[b'Secret message 1', b'Secret message 3']
```

This by default reads from `alice_dec.json`.

We can see we have the secret we asked for. If something goes wrong in transmission or Alice tries to mess with things (i.e. the hashes don't match), we will get something like:
```python
> bob.receive()
Hashes don't match. Either something messed up or Alice is up to something.
[b'messed up secret here']
```
