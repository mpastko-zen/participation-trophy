// Prints the strategy commitment to register under Dashboard -> My Agents -> Edit agent.
import { loadConfig } from '../src/config.js';
import { deriveSalt, strategyCommitment } from '../src/vfy/commitment.js';
import type { StrategyParams } from '../src/vfy/strategy.js';

const config = loadConfig();
const params: StrategyParams = {
  extractAmount: Math.max(1, Math.min(10, config.vfy.extractAmount)),
  holdWhenOpponentEmpty: config.vfy.holdWhenOpponentEmpty ? 1 : 0,
};
const salt = deriveSalt(config.vfy.strategySalt || config.hmacSecret || 'dev');
const commitment = await strategyCommitment(params, salt);
console.log(JSON.stringify({
  circuitVersion: config.vfy.circuitVersion,
  strategyCommitment: commitment,
  params,
  saltSource: config.vfy.strategySalt ? 'VFY_STRATEGY_SALT' : 'AGENT_GAMES_HMAC_SECRET (set VFY_STRATEGY_SALT so rotating the secret does not change the commitment)',
  note: 'Register strategyCommitment before Swiss Round 1 opens. Re-run after changing strategy params or salt.',
}, null, 2));
