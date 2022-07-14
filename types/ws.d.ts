interface Iopts {
  baseUrl: string;
  cookieStore: any;
  debug: boolean;
  onClose: Function;
  onError: Function;
  onMessage: Function;
}

export interface Iws {
  create(opts: Iopts): any;
  listen(baseUrl: string, find: Function): any;
  waitForVout(
    baseUrl: string,
    addr: string,
    amount: number = 0,
    maxTxLockWait: number = 3000,
  ): Promise<SocketPayment>;
}

export interface iEio3 {
  connect(): Promise<SocketIoHello>;
  subscribe(sid: string, eventName: string): Promise<string>;
  /** @param sid - session id (associated with AWS ALB cookie) */
  connectWs(sid: string): any;
}

export interface SocketIoHello {
  sid: string;
  upgrades: string[];
  pingTimeout: number;
  pingInterval: number;
}

export interface I_ws {
  _ws: any;
  init(): void;
  close(): void;
}

type Base58CheckAddr = number;

/**
 *
 * @example
 * ```JSON
 *   {
 *     txid: 'd2cc7cb8e8d2149f8c4475aee6797b4732eab020f8eb24e8912d0054787b0966',
 *     valueOut: 0.00099775,
 *     vout: [
 *       { XcacUoyPYLokA1fZjc9ZfpV7hvALrDrERA: 40000 },
 *       { Xo6M4MxnHWzrksja6JnFjHuSa35SMLQ9J3: 59775 }
 *     ],
 *     isRBF: false,
 *     txlock: true
 *   }
 * ```
 */
export interface InsightSocketEventData {
  /** hex */
  txid: string;
  /** float */
  valueOut: number;
  isRBF: boolean;
  txlock: boolean;
  /** addr and duffs */
  vout: Array<Record<Base58CheckAddr>>;
}

export interface SocketPayment {
  /** Base58check pay-to address */
  address: string;
  /** duffs, duh */
  satoshis: number;
  /** in milliseconds since epoch */
  timestamp: number;
  /** in hex */
  txid: string;
  txlock: boolean;
}
