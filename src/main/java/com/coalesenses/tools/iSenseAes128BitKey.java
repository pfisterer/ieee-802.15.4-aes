package com.coalesenses.tools;

import org.bouncycastle.crypto.params.KeyParameter;

import com.google.common.base.Preconditions;

public class iSenseAes128BitKey {
    byte[] aes128BitKey;

    public iSenseAes128BitKey(byte[] aes128BitKey) {
        Preconditions.checkNotNull(aes128BitKey);
        Preconditions.checkArgument(aes128BitKey.length == 16, "Key length must be 16");

        this.aes128BitKey = aes128BitKey;
    }

    public KeyParameter getAsKeyParameter() {
        return new KeyParameter(aes128BitKey);
    }

    /**
     * @return the aes128BitKey
     */
    public byte[] getAes128BitKey() {
        return aes128BitKey;
    }

    /**
     * @param aes128BitKey
     *            the aes128BitKey to set
     */
    public void setAes128BitKey(byte[] aes128BitKey) {
        this.aes128BitKey = aes128BitKey;
    }

}
