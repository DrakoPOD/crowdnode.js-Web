import Dashcore from "@dashevo/dashcore-lib";
import Transaction from "@dashevo/dashcore-lib/lib/transaction/transaction";

export interface IDash {
  create(insightApi): any;
}

export interface IdashApi {
  getInstantBalance(address: string): Promise<InstantBalance>;

  createBalanceTransfer(privKey: string, pub: string): Promise<Transaction>;
  createPayment(
    pivKey: string,
    payAddr: string | Dashcore.Address,
    amount: number,
    changeAddr?: string | Dashcore.Address,
  ): Promise<Transaction>;
}

interface InstantBalance {
  addrStr: string;
  balance: number;
  balanceSat: number;
  _utxoCount: number;
  _utxoAmounts: number[];
}

export interface CoreUtxo {
  txId: string;
  outputIndex: number;
  address: string;
  script: string;
  satoshis: number;
}

export interface InsightUtxo {
  address: string;
  txid: string;
  vout: number;
  scriptPubKey: string;
  amount: number;
  satoshis: number;
  height: number;
  confirmations: number;
}
