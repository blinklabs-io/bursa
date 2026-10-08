// Synthetic, in-memory preview. Transaction and persistent-settings writes are refused.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, extname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
const scenario = process.env.BURSA_PREVIEW_SCENARIO;
const port = Number(process.env.BURSA_PREVIEW_PORT ?? 4174);
const root = fileURLToPath(new URL('./dist/', import.meta.url));
const fixtures = fileURLToPath(new URL('../../docs/design/fixtures/', import.meta.url));
const names = ['Minswap', 'Snek', 'Indigo', 'Djed'];
const tickers = ['MIN', 'SNEK', 'INDY', 'DJED'];
const units = names.map((name, i) => String(i + 1).repeat(56) + Buffer.from(name).toString('hex'));
const assets = units.map((unit, i) => ({ unit, quantity: ['2450000000', '18000', '325500000', '1200000000'][i] }));
const account = (index, label, amount) => ({ index, label, active: index === 0, stake_address: `stake1_sample_${index}`, first_address: `addr1_sample_${index}`, balance: { lovelace: amount, assets } });
const wallets = [
  { id: 'demo', name: 'Everyday wallet', network: 'mainnet', type: 'full', accounts: [account(0, 'Main account', '24850640000'), account(1, 'Travel account', '8420000000')], active_account_index: 0 },
  { id: 'hardware-demo', name: 'Hardware savings', network: 'mainnet', type: 'hardware', accounts: [account(0, 'Savings account', '52000000000')], active_account_index: 0 },
];
let activeId = 'demo';
let mediaEnabled = true;
const activeWallet = () => wallets.find(w => w.id === activeId);
const view = w => ({ ...w, active: w.id === activeId, addresses: [w.accounts[w.active_account_index].first_address], stake_address: w.accounts[w.active_account_index].stake_address, accounts: w.accounts.map(a => ({ ...a, active: a.index === w.active_account_index })) });
const poolId = 'pool1' + 'a7c9d2'.repeat(8);
const pools = [0, 1, 2].map(i => ({ pool_id: i === 0 ? poolId : `pool1${String(i).repeat(50)}`, hex: String(i).repeat(56), vrf_key: '', active_stake: String((22400000 + i * 3100000) * 1e6), live_stake: String((24800000 + i * 2900000) * 1e6), declared_pledge: String((500000 + i * 125000) * 1e6), fixed_cost: '170000000', margin_cost: [0.02,0.015,0.025][i], live_saturation: [0.412,0.62,1.04][i] }));
const dexPools = assets.slice(0,3).map((a,i) => ({ protocol: ['minswap-v2','sundaeswap','wingriders'][i], pool_id: `demo-pool-${i}`, asset_x: 'lovelace', asset_y: a.unit, reserve_x: '500000000000', reserve_y: '22000000000000', price_xy: 44 + i * 3, price_yx: 1 / (44 + i * 3), effective_fee: 0.003, tx_hash: 'a'.repeat(64), tx_index: 0 }));
const nfts = [
  { unit: 'a'.repeat(56) + '44756e65', name: 'Dune study #014', description: 'Sample collectible for the design preview. Photo by Peter Thomas on Unsplash.', image_cid: 'demo-dunes', cached: true },
  { unit: 'b'.repeat(56) + '436f617374', name: 'Coastline #008', description: 'Sample collectible for the design preview. Photography from Unsplash.', image_cid: 'demo-coast', cached: true },
];
const logos = await Promise.all(['min','snek'].map(async name => { try { return (await readFile(resolve(fixtures, `${name}.png`))).toString('base64'); } catch { return undefined; } }));
const data = {
  '/status': { state: 'ready', tip: 12408962, caughtUp: true, network: 'mainnet' },
  '/vault/status': { exists: scenario !== 'vault-create', locked: true, wallet_count: scenario === 'vault-create' ? 0 : 2 },
  '/wallet/settings/auto-lock': { minutes: 0 },
  '/wallet/settings/notifications': { enabled: false },
  '/wallet/delegation': { pool_id: poolId, active: true, rewards_sum: '284750000', withdrawable_amount: '42380000', provisional: false, note: '' },
  '/wallet/transactions': [
    { tx_hash: 'a1'.repeat(32), tx_index: 0, block_height: 12408220, block_time: 1790870400, direction: 'received', net_lovelace: '1500000000', asset_deltas: [], fee: '170000', confirmations: 742, pending: false },
    { tx_hash: 'b2'.repeat(32), tx_index: 0, block_height: 12407110, block_time: 1790784000, direction: 'sent', net_lovelace: '-250180000', asset_deltas: [], fee: '180000', confirmations: 1852, pending: false },
    { tx_hash: 'c3'.repeat(32), tx_index: 0, block_height: 12406880, block_time: 1790697600, direction: 'received', net_lovelace: '750000000', asset_deltas: [], fee: '170000', confirmations: 2082, pending: false },
  ],
  '/wallet/contacts': [],
  '/wallet/settings/history-expiry': { enabled: false, restart_required: false },
  '/vault/tpm/status': { available: false, reason: 'TPM is unavailable in this design preview.', enabled: false, pcrBound: false },
  '/wallet/rewards': { rewards: [], provisional: false, note: '' },
  '/connector/grants': { paired: false, extension_id: '', origins: [] },
  '/wallet/dex/pools': { pools: dexPools },
};
const mime = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.ttf': 'font/ttf', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.wasm': 'application/wasm' };
createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  let path;
  const json = (value, status = 200) => { res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(value)); };
  try { path = decodeURIComponent(url.pathname); } catch { return json({ error: 'Invalid URL.' }, 400); }
  let body;
  if (req.method === 'POST' || req.method === 'PUT') {
    const chunks = [];
    let size = 0;
    for await (const chunk of req) { size += chunk.length; if (size > 16384) return json({ error: 'Request too large.' }, 413); chunks.push(chunk); }
    try { body = JSON.parse(Buffer.concat(chunks).toString() || '{}'); } catch { return json({ error: 'Invalid JSON.' }, 400); }
  }
  if (path === '/connector/events' && req.method === 'GET') { res.writeHead(200, { 'Content-Type': 'text/event-stream' }); res.write('data: {"type":"snapshot","pending":[]}\n\n'); return; }
  if (req.method === 'POST' && path === '/vault' && scenario === 'vault-create') return json({ exists: true, locked: false, wallet_count: 0 });
  if (req.method === 'POST' && path === '/vault/unlock') return json(wallets.map(view));
  if (req.method === 'POST' && path === '/vault/lock') return json({});
  if (req.method === 'POST' && path === '/connector/pending-pairings') return json([]);
  const activation = path.match(/^\/wallet\/([^/]+)\/activate$/);
  if (req.method === 'POST' && activation) {
    if (!wallets.some(w => w.id === activation[1])) return json({ error: 'Unknown preview wallet.' }, 404);
    activeId = activation[1]; return json(view(activeWallet()));
  }
  if (req.method === 'POST' && path === '/wallet/account/select') {
    if (!activeWallet().accounts.some(a => a.index === body.account_index)) return json({ error: 'Unknown preview account.' }, 404);
    activeWallet().active_account_index = body.account_index; return json(view(activeWallet()));
  }
  if (req.method === 'PUT' && path === '/wallet/settings/nft-media') { mediaEnabled = body.enabled === true; return json({ enabled: mediaEnabled, available: true }); }
  if (req.method === 'POST' && path === '/wallet/dex/quote') {
    const p = dexPools.find(p => (p.asset_x === body.asset_in && p.asset_y === body.asset_out) || (p.asset_y === body.asset_in && p.asset_x === body.asset_out));
    if (!p || !/^\d+$/.test(body.amount_in ?? '') || body.amount_in.length > 20) return json({ error: 'No sample quote for this pair.' }, 404);
    const amount = BigInt(body.amount_in);
    const output = body.asset_in === 'lovelace' ? amount * 44n : amount / 44n;
    return json({ protocol: p.protocol, pool_id: p.pool_id, asset_in: body.asset_in, asset_out: body.asset_out, amount_in: body.amount_in, amount_out: output.toString(), price_impact_pct: 0.12, effective_fee: 0.003, route: `${p.protocol} ${body.asset_in}→${body.asset_out}` });
  }
  if (req.method !== 'GET') return json({ error: 'Design preview: transactions and persistent changes are disabled.' }, 403);
  // Invalid placeholder words exercise the phrase layout without creating key material.
  if (path === '/wallet/mnemonic/generate') return json({ mnemonic: Array(24).fill('preview').join(' ') });
  if (path === '/wallet/settings/nft-media') return json({ available: true, enabled: mediaEnabled });
  if (path === '/wallet/nft') return json(nfts);
  const nftIndex = nfts.findIndex(n => path === `/wallet/nft/${n.unit}/image`);
  if (nftIndex >= 0) {
    if (!mediaEnabled) return json({ error: 'Media off.' }, 403);
    try { const bytes = await readFile(resolve(fixtures, nftIndex === 0 ? 'dunes.jpg' : 'coast.jpg')); res.writeHead(200, { 'Content-Type': 'image/jpeg' }); return res.end(bytes); } catch { return json({ error: 'Image unavailable.' }, 404); }
  }
  if (path === '/wallet/balance') return json(activeWallet().accounts[activeWallet().active_account_index].balance);
  if (path === '/wallet/accounts') return json({ accounts: view(activeWallet()).accounts, active_account_index: activeWallet().active_account_index });
  if (path === '/wallet/addresses') return json({ usage_known: scenario !== 'receive-unknown', receive: view(activeWallet()).addresses, used: [], next_unused: scenario === 'receive-unknown' ? '' : view(activeWallet()).addresses[0] });
  if (path === '/wallet/pools') { const found = pools.filter(p => p.pool_id.includes(url.searchParams.get('q') || '')); return json({ pools: found, total: found.length, page: 1, count: 50 }); }
  if (path.startsWith('/wallet/pool/')) return json(pools.find(p => p.pool_id === path.slice('/wallet/pool/'.length)) || pools[0]);
  if (Object.hasOwn(data, path)) return json(data[path]);
  if (path.startsWith('/wallet/assets/')) {
    const unit = path.slice('/wallet/assets/'.length);
    const index = units.indexOf(unit);
    if (index >= 0) return json({ asset: unit, policy_id: unit.slice(0,56), asset_name: unit.slice(56), asset_name_ascii: names[index], fingerprint: 'asset1_sample', quantity: '1000000000000', onchain_metadata: null, metadata: { name: names[index], ticker: tickers[index], decimals: index === 1 ? 0 : 6, logo: logos[index] } });
  }
  if (/^\/(wallet|vault|connector)\//.test(path)) return json({ error: 'This screen has no sample data yet.' }, 404);
  const file = resolve(root, '.' + (path === '/' ? '/index.html' : path));
  if (!file.startsWith(root.endsWith(sep) ? root : root + sep)) return json({ error: 'Not found' }, 404);
  try {
    let content = await readFile(file);
    if (extname(file) === '.html') content = content.toString().replace('<body>', '<body><div style="position:sticky;top:0;z-index:120;background:#272218;color:#ecd09a;text-align:center;padding:7px 12px;font:11px sans-serif">Design preview · Synthetic assets · Transactions disabled</div>');
    res.writeHead(200, { 'Content-Type': mime[extname(file)] ?? 'application/octet-stream', 'Cache-Control': 'no-store' }); res.end(content);
  } catch { res.writeHead(404); res.end('Not found'); }
}).listen(port, '127.0.0.1', function () { console.log(`Bursa design preview: http://127.0.0.1:${this.address().port} (use any demo password)`); });
