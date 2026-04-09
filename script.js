let currentSymKey = null;
let currentUsername = null;
let userContacts = [];
let pinataJwt = '';

function loadConfig() {
    if (!currentSymKey || !currentUsername) return;

    const storedConfig = localStorage.getItem(getStorageKey(currentUsername) + "_config");
    
    if (storedConfig) {
        try {
            const parsed = JSON.parse(storedConfig);
            const nonce = nacl.util.decodeBase64(parsed.nonce);
            const encJwt = nacl.util.decodeBase64(parsed.encJwt);
            
            
            const decryptedBytes = nacl.secretbox.open(encJwt, nonce, currentSymKey);
            
            if (decryptedBytes) {
                pinataJwt = nacl.util.encodeUTF8(decryptedBytes);
                document.getElementById('config-status').innerText = "CONFIG_ACTIVE";
                log("System configuration securely loaded.");
            } else {
                log("ERR: Failed to decrypt system configuration.");
            }
        } catch (e) {
            console.error("Config load error:", e);
            log("ERR: Config data corrupted.");
        }
    } else {
        document.getElementById('config-status').innerText = "NO_CONFIG";
    }
}
function saveConfig() {
    const input = document.getElementById('pinata-jwt-input');
    
    
    if (!currentSymKey) {
        return log("ERR: Load your ID first to encrypt the System Config.");
    }

    if (input.value.trim() === '') return log("ERR: JWT required.");

       const jwtBytes = nacl.util.decodeUTF8(input.value.trim());
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const encryptedJwt = nacl.secretbox(jwtBytes, nonce, currentSymKey);

    const storageData = {
        encJwt: nacl.util.encodeBase64(encryptedJwt),
        nonce: nacl.util.encodeBase64(nonce)
    };

    
    localStorage.setItem(getStorageKey(currentUsername) + "_config", JSON.stringify(storageData));
    
    
    pinataJwt = input.value.trim();
    
    input.value = ''; 
    log("System configuration encrypted and locked.");
    document.getElementById('config-status').innerText = "CONFIG_ENCRYPTED";
}



async function dropFile() {
    if (!pinataJwt) return log("ERR: No Pinata JWT found. Check System Config.");
    if (!myKeyPair) return log("ERR: Please generate a local identity first.");

    const fileInput = document.getElementById('file-input');
    const recipientBase64 = document.getElementById('recipient-pub-key').value.trim();

    if (!fileInput.files[0] || !recipientBase64) return log("ERR: Missing file or key.");

    const file = fileInput.files[0];
    let recipientPubKey;
    try {
        recipientPubKey = nacl.util.decodeBase64(recipientBase64);
    } catch (e) {
        return log("ERR: Invalid recipient public key format.");
    }

    log(`Reading file: ${file.name}...`);
    const fileBuffer = await file.arrayBuffer();
    const fileData = new Uint8Array(fileBuffer);

    log("Packaging metadata...");
    const metadata = {
        name: file.name,
        type: file.type || "application/octet-stream",
        size: file.size,
        timestamp: Date.now()
    };

    const metaString = JSON.stringify(metadata);
    const metaBytes = new TextEncoder().encode(metaString);

    const payloadLength = 4 + metaBytes.length + fileData.length;
    const combinedData = new Uint8Array(payloadLength);

    const dataView = new DataView(combinedData.buffer);
    dataView.setUint32(0, metaBytes.length, true);

    combinedData.set(metaBytes, 4);
    combinedData.set(fileData, 4 + metaBytes.length);

    log("Encrypting payload with Curve25519...");
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const encrypted = nacl.box(combinedData, nonce, recipientPubKey, myKeyPair.secretKey);

    if (!encrypted) return log("ERR: Encryption failed.");

    const finalPayload = new Uint8Array(nonce.length + encrypted.length);
    finalPayload.set(nonce);
    finalPayload.set(encrypted, nonce.length);

    let finalUploadBlob;
    let fileName = "secret_drop.enc";
    const useStego = document.getElementById('use-stego-toggle')?.checked;

    if (useStego) {
        const carrierFile = document.getElementById('carrier-input').files[0];
        if (!carrierFile) return log("ERR: Carrier image required for stego mode.");
        
        log("Embedding encrypted payload into image pixels...");
        try {
            finalUploadBlob = await embedDataInImage(finalPayload, carrierFile);
            fileName = "innocent_image.png"; 
        } catch (e) {
            return log(`ERR: ${e.message}`);
        }
    } else {
        finalUploadBlob = new Blob([finalPayload], { type: "application/octet-stream" });
    }

    log("Uploading to IPFS via Pinata...");
    const formData = new FormData();
    formData.append('file', finalUploadBlob, fileName);

    try {
        const res = await fetch('https://api.pinata.cloud/pinning/pinFileToIPFS', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${pinataJwt}` },
            body: formData
        });

        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        
        const data = await res.json();
        log(`SUCCESS! CID: ${data.IpfsHash}`);

        const cidInput = document.getElementById('last-cid');
        const cidBtn = document.getElementById('copy-cid-btn');
        
        if (cidInput && cidBtn) {
            cidInput.value = data.IpfsHash;
            cidInput.style.display = 'block';
            cidBtn.style.display = 'inline-block';
        }
    } catch (e) { 
        console.error(e);
        log("UPLOAD_FAILED. Check network or console.");
    }
}


let myKeyPair = null;

const log = (msg) => {
    const statusBar = document.getElementById('status-bar');
    if (statusBar) {
        statusBar.innerText = msg;
    }
    console.log(`> ${msg}`);
};

function initIdentity() {
    log("Generating Curve25519 Keypair...");
    myKeyPair = nacl.box.keyPair();
    
    
    const pubKeyBase64 = nacl.util.encodeBase64(myKeyPair.publicKey);
    const secKeyBase64 = nacl.util.encodeBase64(myKeyPair.secretKey);
    
    
    document.getElementById('pub-key-display').value = pubKeyBase64; 
    document.getElementById('sec-key-display').value = secKeyBase64;
    log("Keys ready. Identity stored in volatile memory.");
}

const ipfsGateways = [
    "https://ipfs.io/ipfs/",
    "https://cloudflare-ipfs.com/ipfs/",
    "https://dweb.link/ipfs/",
    "https://gateway.pinata.cloud/ipfs/",
    "https://4everland.io/ipfs/"
];

async function pickupFile() {
    if (!myKeyPair) return log("ERR: Please generate a local identity first.");
    const cid = document.getElementById('cid-input').value.trim();
    const senderBase64 = document.getElementById('sender-pub-key').value.trim(); 
    
    if (!cid || !senderBase64) return log("ERR: Need CID and SENDER_PUB_KEY.");

    let senderPubKey;
    try {
        senderPubKey = nacl.util.decodeBase64(senderBase64);
    } catch (e) {
        return log("ERR: Invalid sender public key format.");
    }

    log("Searching for data across IPFS gateways...");
    
    let arrayBuffer = null;
    let contentType = null;
    let successGateway = null;

    
    for (const gateway of ipfsGateways) {
        try {
            log(`Probing: ${gateway}${cid.substring(0,8)}...`);
            const res = await fetch(`${gateway}${cid}`, { signal: AbortSignal.timeout(5000) }); 
            
            if (res.ok) {
                arrayBuffer = await res.arrayBuffer();
                contentType = res.headers.get('content-type');
                successGateway = gateway;
                break; 
            }
        } catch (e) {
            console.warn(`Gateway ${gateway} failed or timed out.`);
        }
    }

    if (!arrayBuffer) {
        return log("ERR: File not found on any known public gateways.");
    }

    log(`Success! Data retrieved via ${new URL(successGateway).hostname}`);

    try {
        let data;
        
        if (contentType && contentType.includes('image/png')) {
            log("Image detected. Scanning for steganographic payload...");
            try {
                const imageBlob = new Blob([arrayBuffer], { type: 'image/png' });
                data = await extractDataFromImage(imageBlob);
                log("Hidden payload extracted successfully.");
            } catch (e) {
                data = new Uint8Array(arrayBuffer);
            }
        } else {
            data = new Uint8Array(arrayBuffer);
        }

        log("Decrypting...");
        if (data.length <= nacl.box.nonceLength) throw new Error("File data too small.");
        
        const nonce = data.slice(0, nacl.box.nonceLength);
        const encrypted = data.slice(nacl.box.nonceLength);

        
        const decrypted = nacl.box.open(encrypted, nonce, senderPubKey, myKeyPair.secretKey);
        
        if (!decrypted) throw new Error("Decryption failed. Key mismatch or corrupt data.");

        log("Unpacking metadata...");
        const dataView = new DataView(decrypted.buffer, decrypted.byteOffset, decrypted.byteLength);
        const metaLength = dataView.getUint32(0, true); 

        const metaBytes = decrypted.slice(4, 4 + metaLength);
        const metaString = new TextDecoder().decode(metaBytes);
        const metadata = JSON.parse(metaString);

        const fileData = decrypted.slice(4 + metaLength);
        log(`Decrypted: ${metadata.name}. Creating download...`);
        
        const blob = new Blob([fileData], { type: metadata.type });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = metadata.name;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url); 
        
        log("File saved successfully.");
    } catch (e) {
        console.error(e);
        log(`ERR: ${e.message || "Processing failed."}`);
    }
}

async function getSymmetricKey(username, password) {
    const enc = new TextEncoder();

    
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
    );

    
    const salt = enc.encode(username.toLowerCase() + "_EtCAN_Secure_Salt_v1");

    
    const derivedBuffer = await window.crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 600000, 
            hash: "SHA-256"
        },
        keyMaterial,
        256 
    );

    return new Uint8Array(derivedBuffer);
}

function getStorageKey(username) {
    const userBytes = nacl.util.decodeUTF8(username.toLowerCase());
    return "shadowDrop_" + nacl.util.encodeBase64(nacl.hash(userBytes).slice(0, 16));
}

async function registerUser() {
    const user = document.getElementById('username').value.trim();
    const pass = document.getElementById('master-password').value.trim();
    
    if (!user || !pass) return log("ERR: Username and password required to save.");
    if (!myKeyPair) return log("ERR: Generate a keypair first before saving.");

    log("Deriving secure key... (this may take a moment)");
    
    
    const symKey = await getSymmetricKey(user, pass);
    
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const encryptedSecretKey = nacl.secretbox(myKeyPair.secretKey, nonce, symKey);
    
    const storageData = {
        pubKey: nacl.util.encodeBase64(myKeyPair.publicKey), 
        encSecKey: nacl.util.encodeBase64(encryptedSecretKey),
        nonce: nacl.util.encodeBase64(nonce)
    };

    localStorage.setItem(getStorageKey(user), JSON.stringify(storageData));
    log(`Identity encrypted and safely stored for: ${user}`);

    currentSymKey = symKey;
    currentUsername = user;
    document.getElementById('address-book-fieldset').style.display = 'block';
    saveContacts();
    renderContacts();
}



async function loginUser() {
    const user = document.getElementById('username').value.trim();
    const pass = document.getElementById('master-password').value.trim();
    
    if (!user || !pass) return log("ERR: Username and password required to load.");

    const storedData = localStorage.getItem(getStorageKey(user));

    if (storedData) {
        const parsed = JSON.parse(storedData);
        
        log("Decrypting identity... stand by.");
        
        
        const symKey = await getSymmetricKey(user, pass);
        const nonce = nacl.util.decodeBase64(parsed.nonce);
        const encryptedSecKey = nacl.util.decodeBase64(parsed.encSecKey);
        
        const decryptedSecKey = nacl.secretbox.open(encryptedSecKey, nonce, symKey);
        
        if (!decryptedSecKey) {
            return log("ERR: Decryption failed. Wrong master password?");
        }
        
        myKeyPair = {
            publicKey: nacl.util.decodeBase64(parsed.pubKey),
            secretKey: decryptedSecKey
        };
        
        document.getElementById('pub-key-display').value = parsed.pubKey;
        document.getElementById('sec-key-display').value = nacl.util.encodeBase64(decryptedSecKey);
        
        log(`Identity unlocked and loaded for: ${user}.`);
        currentSymKey = symKey;
        currentUsername = user;
        document.getElementById('address-book-fieldset').style.display = 'block';
        loadContacts();
        loadConfig();
    } else {
        log("ERR: User not found in local storage.");
    }
}


function addContact() {
    if (!currentSymKey) return log("ERR: Must load Identity to save contacts.");
    
    const nick = document.getElementById('contact-nick').value.trim();
    const pub = document.getElementById('contact-pub').value.trim();
    
    if (!nick || !pub) return log("ERR: Nickname and PUB Key required.");
    
    try {
        nacl.util.decodeBase64(pub);
    } catch (e) {
        return log("ERR: Invalid Public Key format.");
    }

    userContacts.push({ nick, pub });
    saveContacts();
    renderContacts();
    
    
    document.getElementById('contact-nick').value = '';
    document.getElementById('contact-pub').value = '';
    log(`Contact '${nick}' securely saved.`);
}

function saveContacts() {
    if (!currentSymKey || !currentUsername) return;
    
    
    const contactsString = JSON.stringify(userContacts);
    const contactsBytes = nacl.util.decodeUTF8(contactsString);
    
    
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const encryptedContacts = nacl.secretbox(contactsBytes, nonce, currentSymKey);
    
    const storageData = {
        encData: nacl.util.encodeBase64(encryptedContacts),
        nonce: nacl.util.encodeBase64(nonce)
    };
    
    
    localStorage.setItem(getStorageKey(currentUsername) + "_contacts", JSON.stringify(storageData));
}

function loadContacts() {
    userContacts = []; 
    const storedData = localStorage.getItem(getStorageKey(currentUsername) + "_contacts");
    
    if (storedData) {
        try {
            const parsed = JSON.parse(storedData);
            const nonce = nacl.util.decodeBase64(parsed.nonce);
            const encData = nacl.util.decodeBase64(parsed.encData);
            
            
            const decryptedBytes = nacl.secretbox.open(encData, nonce, currentSymKey);
            
            if (decryptedBytes) {
                const contactsString = nacl.util.encodeUTF8(decryptedBytes);
                userContacts = JSON.parse(contactsString);
                log(`Loaded ${userContacts.length} secure contacts.`);
            } else {
                log("ERR: Failed to decrypt contacts.");
            }
        } catch (e) {
            console.error("Contact load error:", e);
            log("ERR: Contact book data corrupted.");
        }
    }
    renderContacts();
}

function renderContacts() {
    const select = document.getElementById('contact-list');
    select.innerHTML = '<option value="">-- Select Contact --</option>';
    
    userContacts.forEach(contact => {
        const opt = document.createElement('option');
        opt.value = contact.pub;
        opt.innerText = `> ${contact.nick} [${contact.pub.substring(0,8)}...]`;
        select.appendChild(opt);
    });
}

function autofillContactKeys(pubKey) {
    if (!pubKey) return;
    
    document.getElementById('recipient-pub-key').value = pubKey;
    document.getElementById('sender-pub-key').value = pubKey;
    log("PUB key loaded into terminal targeting sequences.");
}
if (pinataJwt) {
    document.getElementById('config-status').innerText = "CONFIG_ACTIVE";
}
function copyField(elementId) {
    const copyText = document.getElementById(elementId);
    if (!copyText || copyText.value === "Offline..." || copyText.value === "") {
        return log("ERR: Nothing to copy.");
    }
    
    copyText.select();
    copyText.setSelectionRange(0, 99999);
    navigator.clipboard.writeText(copyText.value);
    
    log(`Copied to clipboard.`);
}

function createPRNG(seed) {
    let a = seed;
    return function() {
        let t = a += 0x6D2B79F5;
        t = Math.imul(t ^ t >>> 15, t | 1);
        t ^= t + Math.imul(t ^ t >>> 7, t | 61);
        return ((t ^ t >>> 14) >>> 0) / 4294967296;
    };
}


function getValidChannels(pixels, startPixelIndex = 0) {
    const valid = [];
    for (let i = startPixelIndex; i < pixels.length; i++) {
        if ((i + 1) % 4 !== 0) { 
            valid.push(i);
        }
    }
    return new Uint32Array(valid);
}


function getScatteredIndices(seed, validChannels, neededBits) {
    const random = createPRNG(seed);

    for (let i = 0; i < neededBits; i++) {
        const j = i + Math.floor(random() * (validChannels.length - i));
        const temp = validChannels[i];
        validChannels[i] = validChannels[j];
        validChannels[j] = temp;
    }
    return validChannels.subarray(0, neededBits);
}

async function embedDataInImage(payloadBytes, imageFile) {
    return new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = () => {
            const canvas = document.createElement('canvas');
            canvas.width = img.width;
            canvas.height = img.height;
     
            const ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0);

            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const pixels = imageData.data;

            const totalBits = (4 + payloadBytes.length) * 8; 
            const usableChannels = getValidChannels(pixels, 0);


            if (totalBits + 32 > usableChannels.length) {
                return reject(new Error("Carrier image is too small for this payload."));
            }

            
            const seed = Math.floor(Math.random() * 4294967296);
            for (let i = 0; i < 32; i++) {
                const bitVal = (seed >> i) & 1;
                const pixelIdx = usableChannels[i];
                pixels[pixelIdx] = (pixels[pixelIdx] & 0xFE) | bitVal; 
            }


            const dataToHide = new Uint8Array(4 + payloadBytes.length);
            const view = new DataView(dataToHide.buffer);
            view.setUint32(0, payloadBytes.length, true); 
            dataToHide.set(payloadBytes, 4);


            const remainingChannels = usableChannels.subarray(32); 
            const scatteredIndices = getScatteredIndices(seed, remainingChannels, totalBits);


            let bitCount = 0;
            for (let i = 0; i < dataToHide.length; i++) {
                let byte = dataToHide[i];
                for (let bit = 0; bit < 8; bit++) {
                    const bitVal = (byte >> bit) & 1;
                    const pixelIdx = scatteredIndices[bitCount];
                    pixels[pixelIdx] = (pixels[pixelIdx] & 0xFE) | bitVal;
                    bitCount++;
                }
            }

            
            for (let i = 3; i < pixels.length; i += 4) {
                pixels[i] = 255; 
            }

            ctx.putImageData(imageData, 0, 0);
            canvas.toBlob(blob => resolve(blob), 'image/png');
        };
        img.onerror = () => reject(new Error("Failed to load carrier image."));
        img.src = URL.createObjectURL(imageFile);
    });
}

async function extractDataFromImage(imageBlob) {
    return new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = () => {
            const canvas = document.createElement('canvas');
            canvas.width = img.width;
            canvas.height = img.height;
            
            const ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0);

            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const pixels = imageData.data;
            const usableChannels = getValidChannels(pixels, 0);

            
            let seed = 0;
            for (let i = 0; i < 32; i++) {
                const bitVal = pixels[usableChannels[i]] & 1;
                seed = seed | (bitVal << i);
            }
            
            seed = seed >>> 0; 

            const remainingChannels = usableChannels.subarray(32);

            
            const lengthIndices = getScatteredIndices(seed, remainingChannels, 32);
            const lengthBytes = new Uint8Array(4);
            let bitCount = 0;
            
            for (let i = 0; i < 4; i++) {
                let byte = 0;
                for (let bit = 0; bit < 8; bit++) {
                    const bitVal = pixels[lengthIndices[bitCount]] & 1;
                    byte = byte | (bitVal << bit);
                    bitCount++;
                }
                lengthBytes[i] = byte;
            }
            
            const view = new DataView(lengthBytes.buffer);
            const payloadLength = view.getUint32(0, true);

            
            if (payloadLength === 0 || (payloadLength * 8) + 32 > remainingChannels.length) {
                return reject(new Error("No valid steganographic payload found or data is corrupt."));
            }

            
            const totalBits = (4 + payloadLength) * 8;
            const fullScatteredIndices = getScatteredIndices(seed, remainingChannels, totalBits);

            
            const payloadBytes = new Uint8Array(payloadLength);
            bitCount = 32; 

            for (let i = 0; i < payloadLength; i++) {
                let byte = 0;
                for (let bit = 0; bit < 8; bit++) {
                    const bitVal = pixels[fullScatteredIndices[bitCount]] & 1;
                    byte = byte | (bitVal << bit);
                    bitCount++;
                }
                payloadBytes[i] = byte;
            }
            
            resolve(payloadBytes);
        };
        img.onerror = () => reject(new Error("Failed to load image for extraction."));
        img.src = URL.createObjectURL(imageBlob);
    });
}
 
function updateFolderStatus(input) {
    const count = input.files.length;
    document.getElementById('folder-status').innerText = count > 0 
        ? `${count} files detected in "${input.files[0].webkitRelativePath.split('/')[0]}"` 
        : 'No folder selected';
}

async function deploySite() {
    if (!pinataJwt) return log("ERR: No Pinata JWT found.");
    
    const folderInput = document.getElementById('folder-input');
    const files = folderInput.files;

    if (files.length === 0) return log("ERR: No folder selected.");

    log(`Preparing ${files.length} files for deployment...`);

    const formData = new FormData();

    
    for (let i = 0; i < files.length; i++) {
        const file = files[i];

        formData.append('file', file, file.webkitRelativePath);
    }

    
    const pinataOptions = JSON.stringify({ cidVersion: 1 });
    formData.append('pinataOptions', pinataOptions);

    
    const rootFolderName = files[0].webkitRelativePath.split('/')[0];
    const pinataMetadata = JSON.stringify({ name: rootFolderName });
    formData.append('pinataMetadata', pinataMetadata);

    try {
        log("Uploading directory to IPFS...");
        const res = await fetch('https://api.pinata.cloud/pinning/pinFileToIPFS', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${pinataJwt}` },
            body: formData
        });

        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        
        const data = await res.json();
        log(`SITE DEPLOYED! Root CID: ${data.IpfsHash}`);

        const display = document.getElementById('site-cid-display');
        const btn = document.getElementById('copy-site-btn');
        
        if (display && btn) {
            
            display.value = `https://dweb.link/ipfs/${data.IpfsHash}/`;
            display.style.display = 'block';
            btn.style.display = 'inline-block';
        }
    } catch (e) {
        console.error(e);
        log("DEPLOY_FAILED. See console for details.");
    }
}