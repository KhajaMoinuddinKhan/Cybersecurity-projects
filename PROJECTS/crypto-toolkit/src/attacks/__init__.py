"""Four attacks, each against a real weakness in a construction.

Every one of them recovers or forges something and is then checked against the
genuine implementation rather than against a stored answer: the forged MAC is
verified by the MAC function, the forged GCM tag is accepted by ``GCM.decrypt``,
the recovered ECDSA key is compared to the key that signed, and the recovered
plaintext is compared to the plaintext that was encrypted.
"""
