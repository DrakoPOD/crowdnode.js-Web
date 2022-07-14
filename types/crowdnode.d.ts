export interface ICrowdNode {
  _insightBaseUrl: string;
  _insightApi: any;
  _dashApi: string;
  main: { baseUrl: string; hotWallet: string };
  test: { baseUrl: string; hotWallet: string };
  _baseUrl: string;
  offset: number;
  duffs: number;
  depositMinimum: number;
  stakeMinimum: number;
  requests: Record<string, number>;
  _responses: Record<number, string>;
  responses: Record<string, number>;

  init(opts: { baseUrl: string; insightBaseUrl: string }): any;
  status(signupAddr: string, hotWallet: string);
}
