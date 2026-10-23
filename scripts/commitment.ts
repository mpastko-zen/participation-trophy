// Prints the strategy commitment to register under Dashboard -> My Agents -> Edit agent.
import { loadConfig } from '../src/config.js';
import { deriveSalt, strategyCommitment } from '../src/vfy/commitment.js';
import { strategyParamsFromConfig, strategyParamsToSignals } from '../src/vfy/strategy.js';

const config = loadConfig();
const params = strategyParamsFromConfig(config.vfy);
const salt = deriveSalt(config.vfy.strategySalt || config.hmacSecret || 'dev');
const commitment = await strategyCommitment(params, salt);
console.log(JSON.stringify({
  circuitVersion: config.vfy.circuitVersion,
  strategyCommitment: commitment,
  params,
  strategyParams: strategyParamsToSignals(params).map(String), // the circuit's private strategyParams[8]
  saltSource: config.vfy.strategySalt ? 'VFY_STRATEGY_SALT' : 'AGENT_GAMES_HMAC_SECRET (set VFY_STRATEGY_SALT so rotating the secret does not change the commitment)',
  note: 'Register strategyCommitment before Swiss Round 1 opens. Re-run (and re-register) after changing any VFY_* strategy variable or the salt.',
}, null, 2));
