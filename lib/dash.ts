import Dashcore from "@dashevo/dashcore-lib";
import { IDash, IdashApi, CoreUtxo, InsightUtxo } from "../types/dash";

let Dash = <IDash>{};

const DUFFS = 100000000;
const DUST = 10000;
const FEE = 1000;

let Transaction = Dashcore.Transaction;

Dash.create = function ({
  //@ts-ignore TODO
  insightApi,
}) {
  let dashApi = <IdashApi>{};

  dashApi.getInstantBalance = async function (address) {
    let body = await insightApi.getUtxos(address);
    let utxos = await getUtxos(body);
    let balance = utxos.reduce(function (total, utxo) {
      return total + utxo.satoshis;
    }, 0);
    // because 0.1 + 0.2 = 0.30000000000000004,
    // but we would only want 0.30000000
    let floatBalance = parseFloat((balance / DUFFS).toFixed(8));

    return {
      addrStr: address,
      balance: floatBalance,
      balanceSat: balance,
      _utxoCount: utxos.length,
      _utxoAmounts: utxos.map(function (utxo) {
        return utxo.satoshis;
      }),
    };
  };
  /** Full Send! */
  dashApi.createBalanceTransfer = async function (privKey, pub) {
    let pk = new Dashcore.PrivateKey(privKey);
    let changeAddr = pk.toPublicKey().toAddress().toString();

    let body = await insightApi.getUtxos(changeAddr);
    let utxos = await getUtxos(body);
    let balance = utxos.reduce(function (total, utxo) {
      return total + utxo.satoshis;
    }, 0);

    //@ts-ignore - no input required, actually
    let tmpTx = new Transaction()
      //@ts-ignore - allows single value or array
      .from(utxos);
    tmpTx.to(pub, balance - 1000);
    tmpTx.sign(pk);

    // TODO getsmartfeeestimate??
    // fee = 1duff/byte (2 chars hex is 1 byte)
    //       +10 to be safe (the tmpTx may be a few bytes off)
    let fee = 10 + tmpTx.toString().length / 2;

    //@ts-ignore - no input required, actually
    let tx = new Transaction()
      //@ts-ignore - allows single value or array
      .from(utxos);
    tx.to(pub, balance - fee);
    tx.fee(fee);
    tx.sign(pk);

    return tx;
  };

  /**
   * Send with change back
   */
  dashApi.createPayment = async function (
    privKey,
    payAddr,
    amount,
    changeAddr,
  ) {
    let pk = new Dashcore.PrivateKey(privKey);
    let utxoAddr = pk.toPublicKey().toAddress().toString();
    if (!changeAddr) {
      changeAddr = utxoAddr;
    }

    // TODO make more accurate?
    let feePreEstimate = 1000;
    let utxos = await getOptimalUtxos(utxoAddr, amount + feePreEstimate);
    let balance = getBalance(utxos);

    if (!utxos.length) {
      throw new Error(`not enough funds available in utxos for ${utxoAddr}`);
    }

    // (estimate) don't send dust back as change
    if (balance - amount <= DUST + FEE) {
      amount = balance;
    }

    //@ts-ignore - no input required, actually
    let tmpTx = new Transaction()
      //@ts-ignore - allows single value or array
      .from(utxos);
    tmpTx.to(payAddr, amount);
    //@ts-ignore - the JSDoc is wrong in dashcore-lib/lib/transaction/transaction.js
    tmpTx.change(changeAddr);
    tmpTx.sign(pk);

    // TODO getsmartfeeestimate??
    // fee = 1duff/byte (2 chars hex is 1 byte)
    //       +10 to be safe (the tmpTx may be a few bytes off - probably only 4 -
    //       due to how small numbers are encoded)
    let fee = 10 + tmpTx.toString().length / 2;

    // (adjusted) don't send dust back as change
    if (balance + -amount + -fee <= DUST) {
      amount = balance - fee;
    }

    //@ts-ignore - no input required, actually
    let tx = new Transaction()
      //@ts-ignore - allows single value or array
      .from(utxos);
    tx.to(payAddr, amount);
    tx.fee(fee);
    //@ts-ignore - see above
    tx.change(changeAddr);
    tx.sign(pk);

    return tx;
  };

  // TODO make more optimal
  /**
   * @param fullAmount - including fee estimate
   */
  async function getOptimalUtxos(utxoAddr: string, fullAmount: number) {
    // get smallest coin larger than transaction
    // if that would create dust, donate it as tx fee
    let body = await insightApi.getUtxos(utxoAddr);
    let utxos = await getUtxos(body);
    let balance = getBalance(utxos);

    if (balance < fullAmount) {
      return [];
    }

    // from largest to smallest
    utxos.sort(function (a, b) {
      return b.satoshis - a.satoshis;
    });

    let included = <Array<CoreUtxo>>[];
    let total = 0;

    // try to get just one
    utxos.every(function (utxo) {
      if (utxo.satoshis > fullAmount) {
        included[0] = utxo;
        total = utxo.satoshis;
        return true;
      }
      return false;
    });
    if (total) {
      return included;
    }

    // try to use as few coins as possible
    utxos.some(function (utxo) {
      included.push(utxo);
      total += utxo.satoshis;
      return total >= fullAmount;
    });
    return included;
  }

  function getBalance(utxos: Array<CoreUtxo>) {
    return utxos.reduce(function (total, utxo) {
      return total + utxo.satoshis;
    }, 0);
  }

  async function getUtxos(body: Array<InsightUtxo>) {
    let utxos = <Array<CoreUtxo>>[];

    await body.reduce(async function (promise, utxo) {
      await promise;

      let data = await insightApi.getTx(utxo.txid);

      // TODO the ideal would be the smallest amount that is greater than the required amount

      let utxoIndex = -1;
      data.vout.some(function (vout: InsightTxVout, index: number) {
        if (!vout.scriptPubKey?.addresses?.includes(utxo.address)) {
          return false;
        }

        let satoshis = Math.round(parseFloat(vout.value) * DUFFS);
        if (utxo.satoshis !== satoshis) {
          return false;
        }

        utxoIndex = index;
        return true;
      });

      utxos.push({
        txId: utxo.txid,
        outputIndex: utxoIndex,
        address: utxo.address,
        script: utxo.scriptPubKey,
        satoshis: utxo.satoshis,
      });
    }, Promise.resolve());

    return utxos;
  }

  return dashApi;
};

export default Dash;
