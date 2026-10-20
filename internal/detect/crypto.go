package detect

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// aesCCMDecrypt entschlüsselt AES-CCM (Tag 16 Byte, Nonce 12 Byte, keine
// zusätzlichen Daten) wie es BitLocker für VMK und FVEK verwendet. Das
// verschlüsselte Tag (mac) ist dabei wie im CCM-Standard mit S0 verschlüsselt.
func aesCCMDecrypt(key, nonce, mac, ct []byte) ([]byte, error) {
	if len(nonce) != 12 || len(mac) != 16 {
		return nil, errors.New("ungültige CCM-Parameter")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	const L = 3 // 15 - len(nonce)
	ctr := func(i uint32) []byte {
		a := make([]byte, 16)
		a[0] = L - 1
		copy(a[1:13], nonce)
		a[13], a[14], a[15] = byte(i>>16), byte(i>>8), byte(i)
		s := make([]byte, 16)
		blk.Encrypt(s, a)
		return s
	}
	pt := make([]byte, len(ct))
	for i := 0; i < len(ct); i += 16 {
		s := ctr(uint32(i/16 + 1))
		for j := 0; j < 16 && i+j < len(ct); j++ {
			pt[i+j] = ct[i+j] ^ s[j]
		}
	}
	s0 := ctr(0)
	tag := make([]byte, 16)
	for j := range tag {
		tag[j] = mac[j] ^ s0[j]
	}

	// CBC-MAC über B0 || Klartext
	b0 := make([]byte, 16)
	b0[0] = byte(((16-2)/2)<<3) | (L - 1)
	copy(b0[1:13], nonce)
	n := len(pt)
	b0[13], b0[14], b0[15] = byte(n>>16), byte(n>>8), byte(n)
	x := make([]byte, 16)
	blk.Encrypt(x, b0)
	for i := 0; i < len(pt); i += 16 {
		for j := 0; j < 16 && i+j < len(pt); j++ {
			x[j] ^= pt[i+j]
		}
		blk.Encrypt(x, x)
	}
	if subtle.ConstantTimeCompare(x, tag) != 1 {
		return nil, errors.New("CCM-Authentifizierung fehlgeschlagen")
	}
	return pt, nil
}

// xtsDecrypt entschlüsselt eine Dateneinheit mit AES-XTS. key enthält
// Schlüssel 1 und Schlüssel 2 hintereinander, unit ist die Sektornummer
// (Tweak, little endian). len(data) muss ein Vielfaches von 16 sein.
func xtsDecrypt(key []byte, unit uint64, data []byte) ([]byte, error) {
	if len(key)%2 != 0 || len(data)%16 != 0 {
		return nil, errors.New("ungültige XTS-Parameter")
	}
	k1, err := aes.NewCipher(key[:len(key)/2])
	if err != nil {
		return nil, err
	}
	k2, err := aes.NewCipher(key[len(key)/2:])
	if err != nil {
		return nil, err
	}
	t := make([]byte, 16)
	binary.LittleEndian.PutUint64(t, unit)
	k2.Encrypt(t, t)
	out := make([]byte, len(data))
	buf := make([]byte, 16)
	for i := 0; i < len(data); i += 16 {
		for j := 0; j < 16; j++ {
			buf[j] = data[i+j] ^ t[j]
		}
		k1.Decrypt(buf, buf)
		for j := 0; j < 16; j++ {
			out[i+j] = buf[j] ^ t[j]
		}
		// t = t * alpha in GF(2^128)
		carry := t[15] >> 7
		for j := 15; j > 0; j-- {
			t[j] = t[j]<<1 | t[j-1]>>7
		}
		t[0] <<= 1
		if carry != 0 {
			t[0] ^= 0x87
		}
	}
	return out, nil
}

// cbcEboivDecrypt entschlüsselt einen Sektor im BitLocker-Modus AES-CBC ohne
// Diffuser: IV = AES(FVEK, Byte-Offset als 128-Bit little endian).
func cbcEboivDecrypt(key []byte, byteOffset uint64, data []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 16)
	binary.LittleEndian.PutUint64(iv, byteOffset)
	blk.Encrypt(iv, iv)
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, data)
	return out, nil
}
