import { I_insight, I_Insight, InsightTxResponse } from "../types/insight";

var Insight = <I_Insight>{};

Insight.create = function ({ baseUrl }) {
  let insight = <I_insight>{};

  insight.getBalance = async function (address) {
    console.warn(`warn: getBalance(pubkey) doesn't account for instantSend,`);
    console.warn(`      consider (await getUtxos()).reduce(countSatoshis)`);
    let txUrl = `${baseUrl}/insight-api/addr/${address}/?noTxList=1`;
    let txResp = await fetch(txUrl);

    let data = txResp.json();
    return data;
  };

  insight.getUtxos = async function (address) {
    let utxoUrl = `${baseUrl}/insight-api/addr/${address}/utxo`;
    let utxoResp = await fetch(utxoUrl);

    let utxos = utxoResp.json();
    return utxos;
  };

  insight.getTx = async function (txid) {
    let txUrl = `${baseUrl}/insight-api/tx/${txid}`;
    let txResp = await fetch(txUrl);

    let data = txResp.json();
    return data;
  };

  insight.getTxs = async function (addr, maxPages) {
    let txUrl = `${baseUrl}/insight-api/txs?address=${addr}&pageNum=0`;
    let txResp = await fetch(txUrl);

    let body: InsightTxResponse = await txResp.json();

    let data = await getAllPages(body, addr, maxPages);
    return data;
  };

  async function getAllPages(
    body: InsightTxResponse,
    addr: string,
    maxPages: number,
  ) {
    let pagesTotal = Math.min(body.pagesTotal, maxPages);
    for (let cursor = 1; cursor < pagesTotal; cursor += 1) {
      let nextResp = await fetch(
        `${baseUrl}/insight-api/txs?address=${addr}&pageNum=${cursor}`,
      );
      // Note: this could still be wrong, but I don't think we have
      // a better way to page so... whatever
      body.txs = body.txs.concat((await nextResp.json()).txs);
    }
    return body;
  }

  insight.instantSend = async function (hexTx) {
    let instUrl = `${baseUrl}/insight-api-dash/tx/sendix`;
    let reqObj = {
      method: "POST",
      form: {
        rawtx: hexTx,
      },
    };
    let txResp = await fetch(instUrl, reqObj);
    if (!txResp.ok) {
      // TODO better error check
      throw new Error(JSON.stringify(await txResp.text(), null, 2));
    }
    return txResp.json();
  };

  return insight;
};

export default Insight;
