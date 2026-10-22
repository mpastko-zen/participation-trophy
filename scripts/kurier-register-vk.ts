// Registers a Groth16 verification key with Kurier and prints its vkHash.
// Usage: npm run kurier:register-vk -- path/to/verification_key.json
import { readFile } from 'node:fs/promises';
import { loadConfig } from '../src/config.js';
import { registerVk } from '../src/zk/kurier.js';

const path = process.argv[2];
if (!path) {
  console.error('usage: kurier-register-vk <verification_key.json>');
  process.exit(2);
}
const config = loadConfig();
if (!config.kurier.apiKey) {
  console.error('KURIER_API_KEY is not set');
  process.exit(2);
}
const vk = JSON.parse(await readFile(path, 'utf8'));
const hash = await registerVk(config.kurier, vk);
console.log(JSON.stringify({ vkHash: hash, next: `set VFY_VK_HASH=${hash} (or GATEKEEPER_VK_HASH) in your environment` }, null, 2));
