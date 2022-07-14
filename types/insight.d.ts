export interface I_Insight {
  create(opts: { baseUrl: string }): any;
}

export interface I_insight {
  getBalance(address: string): Promise<InsightBalance>;
  getUtxos(address: string): Promise<InsightUtxo[]>;
  getTx(txid: string): Promise<InsightTx>;
  getTxs(addr: string, maxPages: number): Promise<InsightTxResponse>;
  instantSend(hexTx: string): any;
}

export interface InsightBalance {
  balance: number;
  unconfirmedBalance: number;
  immatureBalance: number;
  txCount: number;
  txids: string[];
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
  isRBF: boolean;
  txlock: boolean;
}

export interface InsightTx {
  txid: string;
  version: number;
  locktime: number;
  vin: InsightTxVin[];
  vout: InsightTxVout[];
  blockhash: string;
  blockheight: number;
  confirmations: number;
  time: number;
  blocktime: number;
  isRBF: boolean;
  txlock: boolean;
}

export interface InsightTxVin {
  txid: string;
  vout: number;
  scriptSig: { hex: string };
  sequence: number;
}

export interface InsightTxVout {
  value: number;
  n: number;
  scriptPubKey: {
    hex: string;
    addresses: string[];
    type: string;
  };
}

export interface InsightBalance {
  addrStr: string;
  balance: number;
  balanceSat: number;
  totalReceived: number;
  totalReceivedSat: number;
  totalSent: number;
  totalSentSat: number;
  unconfirmedBalance: number;
  unconfirmedBalanceSat: number;
  unconfirmedAppearances: number;
  txApperances: number;
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

interface InsightTxVin {
  addr: string;
}

interface InsightTxVout {
  value: number;
  scriptPubKey: object;
  scriptPubKey: { addresses: string[] };
}

export interface InsightTx {
  confirmations: number;
  time: number;
  txlock: boolean;
  version: number;
  vinds: InsightTxVin[];
  vouts: InsightTxVout[];
}

export interface InsightTxResponse {
  pagesTotal: number;
  txs: InsightTx[];
}
