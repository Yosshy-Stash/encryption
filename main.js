const enc = new TextEncoder();
async function sha256Bytes(message) {
	const msgBytes = enc.encode(message);
	const hash = await crypto.subtle.digest('SHA-256', msgBytes);
	return new Uint8Array(hash);
}

function bytesToBase64(bytes) {
	let binary = '';
	const chunk = 0x8000;
	for (let i = 0; i < bytes.length; i += chunk) {
		binary += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, i + chunk)));
	}
	return btoa(binary);
}

function base64ToBytes(base64) {
	const binary = atob(base64);
	const len = binary.length;
	const bytes = new Uint8Array(len);
	for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
	return bytes;
}

async function encryptText(plainText, password) {
	if (!password) throw new Error('Please enter a password');
	const keyBytes = await sha256Bytes(password);
	const iv = new Uint8Array(16);
	crypto.getRandomValues(iv);
	const textBytes = aesjs.utils.utf8.toBytes(plainText);
	const padded = aesjs.padding.pkcs7.pad(textBytes);
	const aesCbc = new aesjs.ModeOfOperation.cbc(keyBytes, iv);
	const encryptedBytes = aesCbc.encrypt(padded);
	const combined = new Uint8Array(iv.length + encryptedBytes.length);
	combined.set(iv, 0);
	combined.set(encryptedBytes, iv.length);
	return bytesToBase64(combined);
}

async function decryptText(base64IvCipher, password) {
	if (!password) throw new Error('Please enter a password');
	const allBytes = base64ToBytes(base64IvCipher);
	if (allBytes.length < 16) throw new Error('Input is too short');
	const iv = allBytes.slice(0, 16);
	const cipherBytes = allBytes.slice(16);
	const keyBytes = await sha256Bytes(password);
	const aesCbc = new aesjs.ModeOfOperation.cbc(keyBytes, iv);
	const decryptedPadded = aesCbc.decrypt(cipherBytes);
	const decryptedBytes = aesjs.padding.pkcs7.strip(decryptedPadded);
	return aesjs.utils.utf8.fromBytes(decryptedBytes);
}

document.getElementById('encryptBtn').addEventListener('click', async () => {
	const txt = document.getElementById('text');
	const pw = document.getElementById('password').value || '';
	const prev = txt.value;
	try {
		txt.value = 'Processing...';
		const res = await encryptText(prev, pw);
		txt.value = res;
	} catch (e) {
		txt.value = prev;
		alert('Error: ' + e.message);
	}
});

document.getElementById('decryptBtn').addEventListener('click', async () => {
	const txt = document.getElementById('text');
	const pw = document.getElementById('password').value || '';
	const prev = txt.value;
	try {
		txt.value = 'Processing...';
		const res = await decryptText(prev, pw);
		txt.value = res;
	} catch (e) {
		txt.value = prev;
		alert('Error: ' + e.message);
	}
});
