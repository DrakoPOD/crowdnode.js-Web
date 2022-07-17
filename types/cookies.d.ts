import * as http from "http";

export interface ICookies {
  set: (url: string, resp: http.IncomingMessage) => Promise<void>;
  get: (url: string) => Promise<string>;
}
