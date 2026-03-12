(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
    return;
  }
  root.CrashlyProvablyFairVerifier = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var nodeCrypto = null;
  try {
    if (typeof require === 'function') {
      nodeCrypto = require('crypto');
    }
  } catch (e) { }

  function toBytes(input) {
    var value = String(input == null ? '' : input);
    if (typeof TextEncoder !== 'undefined') {
      return new TextEncoder().encode(value);
    }
    if (nodeCrypto && nodeCrypto.Buffer) {
      return nodeCrypto.Buffer.from(value, 'utf8');
    }
    var out = [];
    for (var i = 0; i < value.length; i++) out.push(value.charCodeAt(i) & 255);
    return new Uint8Array(out);
  }

  function bytesToHex(bytes) {
    var hex = '';
    for (var i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
  }

  async function sha256Hex(input) {
    var value = String(input == null ? '' : input);
    if (nodeCrypto) {
      return nodeCrypto.createHash('sha256').update(value).digest('hex');
    }
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      var digest = await crypto.subtle.digest('SHA-256', toBytes(value));
      return bytesToHex(new Uint8Array(digest));
    }
    throw new Error('No crypto backend available');
  }

  async function hmacSha256Hex(key, message) {
    var safeKey = String(key == null ? '' : key);
    var safeMessage = String(message == null ? '' : message);
    if (nodeCrypto) {
      return nodeCrypto.createHmac('sha256', safeKey).update(safeMessage).digest('hex');
    }
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      var cryptoKey = await crypto.subtle.importKey(
        'raw',
        toBytes(safeKey),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );
      var signature = await crypto.subtle.sign('HMAC', cryptoKey, toBytes(safeMessage));
      return bytesToHex(new Uint8Array(signature));
    }
    throw new Error('No crypto backend available');
  }

  function clamp(value, min, max) {
    var num = Number(value);
    if (!Number.isFinite(num)) return min;
    return Math.min(max, Math.max(min, num));
  }

  function clamp01(value) {
    return clamp(value, 0, 1);
  }

  function roundTo(value, digits) {
    var num = Number(value);
    if (!Number.isFinite(num)) return 0;
    var safeDigits = Math.max(0, Number(digits) || 0);
    var factor = Math.pow(10, safeDigits);
    return Math.round(num * factor) / factor;
  }

  function normalizeRtpPercent(raw, fallback) {
    var pct = Number(raw);
    if (!Number.isFinite(pct)) return Number.isFinite(Number(fallback)) ? Number(fallback) : 100;
    return clamp(pct, 0, 300);
  }

  function getRtpRatio(raw, fallback) {
    return roundTo(normalizeRtpPercent(raw, fallback) / 100, 9);
  }

  function hashSegmentToUnitInterval(hex, start, length) {
    var safeLength = Math.max(1, Number(length) || 13);
    var safeStart = Math.max(0, Number(start) || 0);
    var src = String(hex || '').slice(safeStart, safeStart + safeLength).padEnd(safeLength, '0');
    var intVal = parseInt(src, 16);
    var maxInt = Math.pow(16, safeLength) - 1;
    if (!Number.isFinite(intVal) || maxInt <= 0) return 0;
    return clamp01(intVal / maxInt);
  }

  function planDiscreteOutcome(rawRtpPercent, basePayoutMultiplier) {
    var targetRatio = getRtpRatio(rawRtpPercent);
    var baseMultiplier = Math.max(0, Number(basePayoutMultiplier) || 0);
    if (targetRatio <= 0 || baseMultiplier <= 0) {
      return {
        targetRatio: targetRatio,
        winChance: 0,
        payoutMultiplier: 0
      };
    }
    var winChance = clamp01(targetRatio / baseMultiplier);
    var payoutMultiplier = winChance >= 0.999999999
      ? roundTo(Math.max(baseMultiplier, targetRatio), 6)
      : roundTo(baseMultiplier, 6);
    return {
      targetRatio: targetRatio,
      winChance: roundTo(winChance, 9),
      payoutMultiplier: payoutMultiplier
    };
  }

  function adjustCrashPointByRtp(baseCrashPoint, rawRtpPercent, gateRoll) {
    var crashBaseRatio = 32 / 33;
    var targetRatio = getRtpRatio(rawRtpPercent) / crashBaseRatio;
    var crashPoint = Math.max(1, Number(baseCrashPoint) || 1);
    var gate = clamp01(gateRoll);
    if (targetRatio <= 0) return 1;
    if (targetRatio < 1) {
      return gate < targetRatio ? roundTo(crashPoint, 2) : 1;
    }
    return roundTo(crashPoint * targetRatio, 2);
  }

  function calculateDicePayout(betType, diceResult, betAmount, rangeBounds) {
    var total = Number(diceResult && diceResult.total || 0);
    var d1 = Number(diceResult && diceResult.dice && diceResult.dice[0] || 0);
    var d2 = Number(diceResult && diceResult.dice && diceResult.dice[1] || 0);
    var won = false;
    var multiplier = 0;

    switch (String(betType || '')) {
      case 'high':
        won = total >= 8;
        multiplier = won ? 1.75 : 0;
        break;
      case 'low':
        won = total <= 6;
        multiplier = won ? 1.75 : 0;
        break;
      case 'seven':
        won = total === 7;
        multiplier = won ? 3.2 : 0;
        break;
      case 'even':
        won = total % 2 === 0;
        multiplier = won ? 1.7 : 0;
        break;
      case 'odd':
        won = total % 2 !== 0;
        multiplier = won ? 1.7 : 0;
        break;
      case 'doubles':
        won = d1 === d2;
        multiplier = won ? 4.5 : 0;
        break;
      case 'range':
        if (rangeBounds) {
          won = total >= Number(rangeBounds.min) && total <= Number(rangeBounds.max);
          var combos = 0;
          for (var a = 1; a <= 6; a++) {
            for (var b = 1; b <= 6; b++) {
              if (a + b >= Number(rangeBounds.min) && a + b <= Number(rangeBounds.max)) {
                combos++;
              }
            }
          }
          var prob = combos / 36;
          multiplier = won && prob > 0 ? parseFloat((0.85 / prob).toFixed(2)) : 0;
        }
        break;
      default:
        if (/^exact_\d+$/.test(String(betType || ''))) {
          var target = parseInt(String(betType).split('_')[1], 10);
          if (Number.isFinite(target) && target >= 2 && target <= 12) {
            won = total === target;
            var mults = { 2: 32, 3: 15, 4: 10, 5: 7.7, 6: 6.3, 7: 5.2, 8: 6.3, 9: 7.7, 10: 10, 11: 15, 12: 32 };
            multiplier = won ? (mults[target] || 0) : 0;
          }
        }
        break;
    }

    var payout = won ? Number(betAmount || 0) * multiplier : 0;
    return {
      won: won,
      multiplier: multiplier,
      payout: payout,
      profit: payout - Number(betAmount || 0)
    };
  }

  function encodeDiceChoice(resolvedType, rangeBounds) {
    if (resolvedType === 'range' && rangeBounds) {
      return 'range_' + Number(rangeBounds.min) + '_' + Number(rangeBounds.max);
    }
    return String(resolvedType || '').trim().toLowerCase();
  }

  function parseDiceChoice(choice) {
    var raw = String(choice || '').trim().toLowerCase();
    if (!raw) return null;
    var rangeMatch = raw.match(/^range_(\d+)_(\d+)$/);
    if (rangeMatch) {
      var min = parseInt(rangeMatch[1], 10);
      var max = parseInt(rangeMatch[2], 10);
      if (Number.isFinite(min) && Number.isFinite(max) && min >= 2 && max <= 12 && min < max) {
        return { resolvedType: 'range', rangeBounds: { min: min, max: max } };
      }
    }
    if (/^exact_\d+$/.test(raw)) {
      return { resolvedType: raw, rangeBounds: null };
    }
    if (['high', 'low', 'seven', 'even', 'odd', 'doubles'].indexOf(raw) >= 0) {
      return { resolvedType: raw, rangeBounds: null };
    }
    return null;
  }

  function listDiceOutcomeBuckets(resolvedType, rangeBounds) {
    var wins = [];
    var losses = [];
    var baseMultiplier = 0;
    for (var die1 = 1; die1 <= 6; die1++) {
      for (var die2 = 1; die2 <= 6; die2++) {
        var total = die1 + die2;
        var probe = calculateDicePayout(
          resolvedType,
          { dice: [die1, die2], total: total },
          1,
          rangeBounds
        );
        var bucket = probe.won ? wins : losses;
        bucket.push({ dice: [die1, die2], total: total });
        if (probe.won && !baseMultiplier) {
          baseMultiplier = Number(probe.multiplier || 0);
        }
      }
    }
    return { wins: wins, losses: losses, baseMultiplier: baseMultiplier };
  }

  async function hashServerSeed(serverSeed) {
    return sha256Hex(String(serverSeed || ''));
  }

  async function verifySimpleDice(serverSeed, clientSeed, nonce) {
    var safeNonce = Number(nonce || 0);
    var hex = await hmacSha256Hex(String(serverSeed || ''), String(clientSeed || '') + ':' + String(safeNonce));
    var maxUnbiased = 4294967292;
    var die1Raw = parseInt(hex.substr(0, 8), 16);
    var die2Raw = parseInt(hex.substr(8, 8), 16);
    if (die1Raw >= maxUnbiased) die1Raw = parseInt(hex.substr(16, 8), 16);
    if (die2Raw >= maxUnbiased) die2Raw = parseInt(hex.substr(24, 8), 16);
    var die1 = (die1Raw % 6) + 1;
    var die2 = (die2Raw % 6) + 1;
    return {
      gameType: 'dice',
      dice: [die1, die2],
      total: die1 + die2,
      hash: hex,
      serverSeedHash: await hashServerSeed(serverSeed)
    };
  }

  async function verifyDiceByChoice(options) {
    var serverSeed = String(options && options.serverSeed || '');
    var clientSeed = String(options && options.clientSeed || '');
    var nonce = Number(options && options.nonce || 0);
    var betAmount = Number(options && options.betAmount || 1);
    var rtpPercent = normalizeRtpPercent(options && options.rtpPercent, 100);
    var choice = parseDiceChoice(options && options.playerChoice || '');
    if (!choice) {
      return verifySimpleDice(serverSeed, clientSeed, nonce);
    }

    var choiceKey = encodeDiceChoice(choice.resolvedType, choice.rangeBounds);
    var hash = await hmacSha256Hex(serverSeed, clientSeed + ':' + nonce + ':dice:' + choiceKey);
    var buckets = listDiceOutcomeBuckets(choice.resolvedType, choice.rangeBounds);
    var targetRatio = getRtpRatio(rtpPercent);
    var allWin = buckets.losses.length === 0;
    var plan = allWin
      ? { targetRatio: targetRatio, winChance: 1, payoutMultiplier: roundTo(Math.max(0, targetRatio), 6) }
      : planDiscreteOutcome(rtpPercent, buckets.baseMultiplier);
    var gateRoll = hashSegmentToUnitInterval(hash, 0, 13);
    var won = allWin ? true : (buckets.wins.length > 0 && gateRoll < Number(plan.winChance || 0));
    var sourcePool = won ? buckets.wins : (buckets.losses.length ? buckets.losses : buckets.wins);
    var pickRoll = hashSegmentToUnitInterval(hash, 13, 13);
    var pickedIdx = sourcePool.length > 1
      ? Math.min(sourcePool.length - 1, Math.floor(pickRoll * sourcePool.length))
      : 0;
    var picked = sourcePool[pickedIdx] || { dice: [1, 1], total: 2 };
    var multiplier = won ? roundTo(Number(plan.payoutMultiplier || 0), 6) : 0;
    var payout = won ? roundTo(betAmount * multiplier, 9) : 0;
    var profit = roundTo(payout - betAmount, 9);
    return {
      gameType: 'dice',
      dice: picked.dice,
      total: picked.total,
      won: won,
      multiplier: multiplier,
      payout: payout,
      profit: profit,
      winChancePct: roundTo(Number(plan.winChance || 0) * 100, 3),
      rtpPercent: rtpPercent,
      hash: hash,
      serverSeedHash: await hashServerSeed(serverSeed)
    };
  }

  async function verifyUpgrade(options) {
    var serverSeed = String(options && options.serverSeed || '');
    var clientSeed = String(options && options.clientSeed || '');
    var nonce = Number(options && options.nonce || 0);
    var chancePct = Math.max(0, Number(options && (options.chancePct != null ? options.chancePct : options.chance) || 0));
    var hash = await hmacSha256Hex(serverSeed, clientSeed + ':' + nonce + ':upgrade');
    var rollInt = parseInt(hash.substring(0, 13), 16);
    var maxInt = Math.pow(16, 13) - 1;
    var roll = maxInt > 0 ? (rollInt / maxInt) : 0;
    var rollClamped = Math.max(0, Math.min(0.999999999, Number(roll || 0)));
    return {
      gameType: 'upgrade',
      chancePct: roundTo(chancePct, 3),
      rollPct: roundTo(rollClamped * 100, 3),
      won: rollClamped <= (chancePct / 100),
      hash: hash,
      serverSeedHash: await hashServerSeed(serverSeed)
    };
  }

  async function verifyCrash(options) {
    var serverSeed = String(options && options.serverSeed || '');
    var clientSeed = String(options && options.clientSeed || '');
    var nonce = Number(options && options.nonce || 0);
    var rtpPercent = normalizeRtpPercent(options && options.rtpPercent, 100);
    var hex = await hmacSha256Hex(serverSeed, clientSeed + ':' + nonce);
    var h = parseInt(hex.slice(0, 8), 16);
    var e = Math.pow(2, 32);
    var baseCrashPoint = (h % 33 === 0)
      ? 1
      : (Math.floor((100 * e - h) / (e - h)) / 100);
    var gateRoll = hashSegmentToUnitInterval(hex, 8, 13);
    return {
      gameType: 'crash',
      crashPoint: adjustCrashPointByRtp(baseCrashPoint, rtpPercent, gateRoll),
      rtpPercent: rtpPercent,
      hash: hex,
      serverSeedHash: await hashServerSeed(serverSeed)
    };
  }

  async function verifyGame(options) {
    var gameType = String(options && options.gameType || 'dice').toLowerCase();
    if (gameType === 'crash') return verifyCrash(options);
    if (gameType === 'upgrade') return verifyUpgrade(options);
    return verifyDiceByChoice(options);
  }

  return {
    version: '1.0.0',
    hashServerSeed: hashServerSeed,
    sha256Hex: sha256Hex,
    hmacSha256Hex: hmacSha256Hex,
    parseDiceChoice: parseDiceChoice,
    verifySimpleDice: verifySimpleDice,
    verifyDice: verifyDiceByChoice,
    verifyCrash: verifyCrash,
    verifyUpgrade: verifyUpgrade,
    verifyGame: verifyGame
  };
});
