/**
 * Copyright (c) 2010, coalesenses GmbH, Luebeck, Germany, www.coalesenses.com
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 *
 * 	- Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 * 	  disclaimer.
 * 	- Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 * 	  following disclaimer in the documentation and/or other materials provided with the distribution.
 * 	- Neither the name of the University of Luebeck nor the names of its contributors may be used to endorse or promote
 * 	  products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package com.coalesenses.tools;

import java.security.Security;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Preconditions;

/**
 * This class performs Authenticated Encryption with Associated Data (AEAD) according to the IEEE 802.15.4 standard.
 */
public class iSenseAes {

    private static final Logger log = LoggerFactory.getLogger(iSenseAes.class);

    private final static int MESSAGE_AUTHENTICATION_CODE_LENGTH = 4;

    private KeyParameter key = null;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * From Wikipedia: CCM mode (Counter with CBC-MAC - Cipher Block Chaining Message Authentication Code) is a mode of
     * operation for cryptographic block ciphers. It is an authenticated encryption algorithm designed to provide both
     * authentication and confidentiality. CCM mode is only defined for block ciphers with a block length of 128 bits.
     * In RFC 3610, it is defined for use with AES.
     */
    private CCMBlockCipher ccmBlockCipher;

    /** A cryptographic nonce (number used once). */
    private long randomlyIncreasedNonce = (int) (Math.random() * 100);

    
    public iSenseAes() {
        super();
    }
    
    public iSenseAes(iSenseAes128BitKey key) {
        super();
        setKey(key);
    }

    /**
     * Set the 128 Bit (16 byte) AES key to be used for encryption.
     * 
     * @param aesKey
     */
    public void setKey(iSenseAes128BitKey aesKey) {
        Preconditions.checkNotNull(aesKey);

        ccmBlockCipher = new CCMBlockCipher(new AESEngine());
        key = aesKey.getAsKeyParameter();
    }

    /** Encode the payload and choose a random nonce
     * 
     * @param payload
     * @return
     */
    public byte[] encodeWithRandomNonce(byte[] payload) {
        randomlyIncreasedNonce += (int) (Math.random() * 100);
        return encode(payload, randomlyIncreasedNonce);
    }

    /** Encode the payload with the given nonce
     * 
     * @param payload
     * @return
     */
    public byte[] encode(byte[] payload, long currentNonce) {
        Preconditions.checkNotNull(payload, "Payload is null");
        Preconditions.checkNotNull(key, "No key for encryption supplied");

        byte[] buffer = new byte[payload.length + 8];

        byte[] n = new byte[13];
        n[0] = 0;
        n[1] = (byte) ((currentNonce >> 24) & 0xFF);
        n[2] = (byte) ((currentNonce >> 16) & 0xFF);
        n[3] = (byte) ((currentNonce >> 8) & 0xFF);
        n[4] = (byte) ((currentNonce) & 0xFF);
        n[5] = (byte) ((currentNonce >> 24) & 0xFF);
        n[6] = (byte) ((currentNonce >> 16) & 0xFF);
        n[7] = (byte) ((currentNonce >> 8) & 0xFF);
        n[8] = (byte) ((currentNonce) & 0xFF);
        n[9] = (byte) ((currentNonce >> 24) & 0xFF);
        n[10] = (byte) ((currentNonce >> 16) & 0xFF);
        n[11] = (byte) ((currentNonce >> 8) & 0xFF);
        n[12] = (byte) ((currentNonce) & 0xFF);

        // AEAD Parameters are, Key, MAC length in bits, Nonce, and Associated text
        AEADParameters params = new AEADParameters(key, MESSAGE_AUTHENTICATION_CODE_LENGTH * 8, n, null);

        // True for encryption mode
        ccmBlockCipher.init(true, params);

        // Do the encryption and authentication. Parameters:
        // - input
        // - input offset (8 bytes are Authenticated data)
        // - length of text to encrypt
        // - output buffer
        // - output offset
        ccmBlockCipher.processBytes(payload, 0, payload.length, buffer, 0);

        try {
            ccmBlockCipher.doFinal(buffer, 0);
        } catch (IllegalStateException e) {
            log.error("" + e, e);
        } catch (InvalidCipherTextException e) {
            log.error("" + e, e);
        }

        buffer[buffer.length - 4] = n[1];
        buffer[buffer.length - 3] = n[2];
        buffer[buffer.length - 2] = n[3];
        buffer[buffer.length - 1] = n[4];

        return buffer;
    }

    /** Decode the buffer
     * 
     * @param cypherText
     * @return
     */
    public byte[] decode(byte[] cypherText) {
        byte[] n = new byte[13];
        byte[] buffer = new byte[cypherText.length - 4 - MESSAGE_AUTHENTICATION_CODE_LENGTH];

        n[0] = 0;

        System.arraycopy(cypherText, cypherText.length - 4, n, 1, 4);
        System.arraycopy(cypherText, cypherText.length - 4, n, 5, 4);
        System.arraycopy(cypherText, cypherText.length - 4, n, 9, 4);

        AEADParameters params = new AEADParameters(key, MESSAGE_AUTHENTICATION_CODE_LENGTH * 8, n, null);

        // true for encryption mode
        ccmBlockCipher.init(false, params);
        ccmBlockCipher.processBytes(cypherText, 0, cypherText.length - 4, buffer, 0);

        try {
            ccmBlockCipher.doFinal(buffer, 0);
            return buffer;

        } catch (IllegalStateException e) {
            log.warn("Illegal state, resetting: " + e, e);
            ccmBlockCipher.reset();
            return null;

        } catch (InvalidCipherTextException e) {
            log.warn("Invalid cipher, resetting: " + e, e);
            ccmBlockCipher.reset();
            return null;
        }

    }
}
