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
}

export interface iEio3 {
  connect(): Object;
}
