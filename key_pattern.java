package improtant;

import java.math.BigInteger;
import java.security.KeyPair;

public class key_pattern {
    byte[] pre_session_key;
    byte[] client_random;
    byte[] server_random;
    byte[] handshakeKey;
    byte[] applicationKey;
    KeyPair keyPair;
}
