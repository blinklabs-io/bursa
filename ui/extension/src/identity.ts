type StoredIdentity = {
  privateKey: CryptoKey;
  publicKey: string;
};

const databaseName = 'bursa-connector';
const storeName = 'identity';
const identityKey = 'p256';

let identityPromise: Promise<StoredIdentity> | undefined;

function base64URL(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(databaseName, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(storeName)) {
        request.result.createObjectStore(storeName);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('Unable to open identity store'));
  });
}

async function readIdentity(): Promise<StoredIdentity | undefined> {
  const database = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const request = database.transaction(storeName, 'readonly').objectStore(storeName).get(identityKey);
      request.onsuccess = () => resolve(request.result as StoredIdentity | undefined);
      request.onerror = () => reject(request.error ?? new Error('Unable to read identity'));
    });
  } finally {
    database.close();
  }
}

async function writeIdentity(identity: StoredIdentity): Promise<StoredIdentity> {
  const database = await openDatabase();
  try {
    return await new Promise<StoredIdentity>((resolve, reject) => {
      const transaction = database.transaction(storeName, 'readwrite');
      const store = transaction.objectStore(storeName);
      const request = store.get(identityKey);
      let stored = identity;
      request.onsuccess = () => {
        if (request.result) stored = request.result as StoredIdentity;
        else store.add(identity, identityKey);
      };
      transaction.oncomplete = () => resolve(stored);
      transaction.onerror = () => reject(transaction.error ?? new Error('Unable to store identity'));
      transaction.onabort = () => reject(transaction.error ?? new Error('Unable to store identity'));
    });
  } finally {
    database.close();
  }
}

async function createIdentity(): Promise<StoredIdentity> {
  const generated = (await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  const [privateBytes, publicBytes] = await Promise.all([
    crypto.subtle.exportKey('pkcs8', generated.privateKey),
    crypto.subtle.exportKey('spki', generated.publicKey),
  ]);
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    privateBytes,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );
  new Uint8Array(privateBytes).fill(0);
  return { privateKey, publicKey: base64URL(new Uint8Array(publicBytes)) };
}

export async function loadIdentity(): Promise<StoredIdentity | undefined> {
  return readIdentity();
}

export async function loadOrCreateIdentity(): Promise<StoredIdentity> {
  identityPromise ??= (async () => {
    const existing = await readIdentity();
    if (existing) return existing;
    const created = await createIdentity();
    return writeIdentity(created);
  })();
  return identityPromise;
}

export async function signRequest(
  identity: StoredIdentity,
  challenge: string,
  method: string,
  path: string,
  body: string,
): Promise<string> {
  const bodyDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body)));
  const payload = [
    'bursa-connector-v1',
    challenge,
    method,
    path,
    base64URL(bodyDigest),
  ].join('\n');
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    identity.privateKey,
    new TextEncoder().encode(payload),
  );
  return base64URL(new Uint8Array(signature));
}

export async function pairingCode(publicKey: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('bursa-pair-v1\n' + publicKey)));
  return Array.from(digest.slice(0, 16), byte => byte.toString(16).padStart(2, '0')).join('');
}

export async function challengeHeaders(identity: StoredIdentity): Promise<Record<string, string>> {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  new DataView(bytes.buffer).setBigUint64(0, BigInt(Date.now()));
  const nonce = base64URL(bytes);
  return {
    'X-Bursa-Challenge': nonce,
    'X-Bursa-Signature': await signRequest(identity, nonce, 'POST', '/connector/challenge', ''),
  };
}
