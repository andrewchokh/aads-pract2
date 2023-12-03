console.log("RSA script has been connected.")

async function generateRSAKeyPair() {
    return await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );
}

async function encryptRSA(publicKey, plaintext) {
    const encodedText = new TextEncoder().encode(plaintext);
    return await crypto.subtle.encrypt(
        {
            name: "RSA-OAEP",
        },
        publicKey,
        encodedText
    );
}

async function decryptRSA(privateKey, ciphertext) {
    const decryptedBuffer = await crypto.subtle.decrypt(
        {
            name: "RSA-OAEP",
        },
        privateKey,
        ciphertext
    );

    return new TextDecoder().decode(decryptedBuffer);
}

async function testEncryption() {
    try {
        const keyPair = await generateRSAKeyPair();

        const plaintext = document.getElementById("plainText").value;
        const ciphertext = await encryptRSA(keyPair.publicKey, plaintext);

        console.log("Ciphertext:", new Uint8Array(ciphertext));

        const decryptedText = await decryptRSA(keyPair.privateKey, ciphertext);
        console.log("Decrypted text:", decryptedText);
    } catch (error) {
        console.error("Error:", error);
    }
}
