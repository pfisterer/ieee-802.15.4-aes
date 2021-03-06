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

import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Arrays;

public class iSenseAes128BitKey {

	byte[] aes128BitKey;

	public iSenseAes128BitKey(byte[] aes128BitKey) {

		if (aes128BitKey == null) {
			throw new IllegalArgumentException("AES key is null!");
		}

		if (aes128BitKey.length != 16) {
			throw new IllegalArgumentException("AES key length must be 16");
		}

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
	 * 		the aes128BitKey to set
	 */
	public void setAes128BitKey(byte[] aes128BitKey) {
		this.aes128BitKey = aes128BitKey;
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}

		final iSenseAes128BitKey that = (iSenseAes128BitKey) o;

		if (!Arrays.equals(aes128BitKey, that.aes128BitKey)) {
			return false;
		}

		return true;
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(aes128BitKey);
	}
}
