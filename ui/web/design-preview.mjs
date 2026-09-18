// Isolated visual fixture server. Never connects to a node or handles real funds.
// Run `npm run build && node design-preview.mjs`, then enter any demo password.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('./dist/', import.meta.url));
const wallet = { id: 'demo', name: 'Personal wallet', network: 'preview', active: true, type: 'full', addresses: ['addr_test1_sample_address_for_design_preview_only'], stake_address: 'stake_test1_sample', accounts: [], active_account_index: 0 };
const names = ['MIN', 'SNEK', 'Indigo', 'DJED'];
const assets = names.map((name, i) => ({ unit: String(i + 1).repeat(56) + Buffer.from(name).toString('hex'), quantity: ['2450000000', '18000000000', '325500000', '1200000000'][i] }));
const data = {
  '/status': { state: 'ready', tip: 12408962, caughtUp: true, network: 'preview' },
  '/vault/status': { exists: true, locked: true, wallet_count: 1 },
  '/wallet/settings/auto-lock': { minutes: 0 },
  '/wallet/settings/notifications': { enabled: false },
  '/wallet/settings/nft-media': { enabled: false },
  '/wallet/balance': { lovelace: '24850640000', assets },
  '/wallet/delegation': { pool_id: 'pool1_sample_design_preview', active: true, rewards_sum: '284750000', withdrawable_amount: '42380000', provisional: false, note: '' },
  '/wallet/accounts': { accounts: [] },
  '/wallet/addresses': { usage_known: true, receive: wallet.addresses, used: [], next_unused: wallet.addresses[0] },
  '/wallet/transactions': [
    { tx_hash: 'a1'.repeat(32), tx_index: 0, block_height: 12408220, block_time: 1789647600, direction: 'received', net_lovelace: '1500000000', asset_deltas: [], fee: '170000', confirmations: 742, pending: false },
    { tx_hash: 'b2'.repeat(32), tx_index: 0, block_height: 12407110, block_time: 1789561200, direction: 'sent', net_lovelace: '-250180000', asset_deltas: [], fee: '180000', confirmations: 1852, pending: false },
    { tx_hash: 'c3'.repeat(32), tx_index: 0, block_height: 12406880, block_time: 1789474800, direction: 'received', net_lovelace: '750000000', asset_deltas: [], fee: '170000', confirmations: 2082, pending: false },
  ],
  '/wallet/contacts': [],
  '/wallet/settings/history-expiry': { enabled: false, restart_required: false },
  '/vault/tpm/status': { available: false, reason: 'Hardware security is unavailable in this design preview.', enabled: false, pcrBound: false },
  '/wallet/rewards': { rewards: [], provisional: false, note: '' },
  '/connector/grants': { paired: false, extension_id: '', origins: [] },
};
const mime = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.ttf': 'font/ttf', '.svg': 'image/svg+xml' };
createServer(async (req, res) => {
  const path = new URL(req.url, 'http://localhost').pathname;
  const json = (value, status = 200) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
  if (path === '/connector/events') { res.writeHead(200, { 'Content-Type': 'text/event-stream' }); res.write('data: {"type":"snapshot","pending":[]}\n\n'); return; }
  if (req.method === 'POST' && path === '/vault/unlock') return json([wallet]);
  if (req.method === 'POST' && path === '/vault/lock') return json({});
  if (req.method === 'POST' && path === '/connector/pending-pairings') return json([]);
  if (req.method !== 'GET') return json({ error: 'Design preview: transactions and changes are disabled.' }, 403);
  if (Object.hasOwn(data, path)) return json(data[path]);
  if (path.startsWith('/wallet/assets/')) {
    const unit = decodeURIComponent(path.slice('/wallet/assets/'.length));
    const index = assets.findIndex(asset => asset.unit === unit);
    if (index >= 0) return json({ asset: unit, onchain_metadata: { name: names[index], ticker: names[index], decimals: 6 } });
  }
  if (/^\/(wallet|vault|connector)\//.test(path)) return json({ error: 'This screen has no sample data yet.' }, 404);
  const file = resolve(root, '.' + (path === '/' ? '/index.html' : path));
  if (!file.startsWith(root)) return json({ error: 'Not found' }, 404);
  try {
    let body = await readFile(file);
    if (extname(file) === '.html') body = body.toString().replace('<body>', '<body><div style="background:#30291e;color:#ecc079;text-align:center;padding:7px 12px;font:11px sans-serif;letter-spacing:.02em">Design preview · Sample data · Transactions disabled</div>');
    res.writeHead(200, { 'Content-Type': mime[extname(file)] ?? 'application/octet-stream' }); res.end(body);
  } catch { res.writeHead(404); res.end('Not found'); }
}).listen(4174, '127.0.0.1', () => console.log('Bursa design preview: http://127.0.0.1:4174 (use any demo password)'));
