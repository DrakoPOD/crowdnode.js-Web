import {
  Iws,
  iEio3,
  SocketIoHello,
  I_ws,
  InsightSocketEventData,
  SocketPayment,
} from "../types/ws";
import * as pkg from "../package.json";

//let Cookies = require("../lib/cookies.js");
let WSClient = require("ws");

var Ws = <Iws>{};
let httpAgent = `${pkg.name}/${pkg.version}`;

Ws.create = function ({
  baseUrl,
  cookieStore,
  debug,
  onClose,
  onError,
  onMessage,
}) {
  let wsc = <I_ws>{};

  let defaultHeaders = {
    /*
    //'Accept-Encoding': gzip, deflate, br
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    Origin: "https://insight.dash.org",
    referer: "https://insight.dash.org/insight/",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
    "sec-gpc": "1",
    */
  };

  let Eio3 = <iEio3>{};
  /*
  let httpAgent = new Https.Agent({
    keepAlive: true,
    maxSockets: 2,
  });
  */

  // Get `sid` (session id) and ping/pong params
  Eio3.connect = async function () {
    let now = Date.now();
    let sidUrl = `${baseUrl}/socket.io/?EIO=3&transport=polling&t=${now}`;

    //let cookies = await cookieStore.get(sidUrl);

    let sidResp = await fetch(sidUrl, {
      credentials: "include",
      headers: {
        //Cookie: cookies,
        userAgent: httpAgent,
        ...defaultHeaders,
      },
    });
    if (!sidResp.ok) {
      console.error(await sidResp.text());
      throw new Error("bad response");
    }
    //await Cookies.set(sidUrl, sidResp);

    // ex: `97:0{"sid":"xxxx",...}`
    let msg = await sidResp.text();
    let colonIndex = msg.indexOf(":");
    // 0 is CONNECT, which will always follow our first message
    let start = colonIndex + ":0".length;
    let len = parseInt(msg.slice(0, colonIndex), 10);
    let json = msg.slice(start, start + (len - 1));

    //console.log("Socket.io Connect:");
    //console.log(msg);
    //console.log(json);

    // @type {SocketIoHello}
    let session = <SocketIoHello>JSON.parse(json);
    return session;
  };

  Eio3.subscribe = async function (sid, eventName) {
    let now = Date.now();
    let subUrl = `${baseUrl}/socket.io/?EIO=3&transport=polling&t=${now}&sid=${sid}`;
    let sub = JSON.stringify(["subscribe", eventName]);
    // not really sure what this is, couldn't find documentation for it
    let typ = 422; // 4 = MESSAGE, 2 = EVENT, 2 = ???
    let msg = `${typ}${sub}`;
    let len = msg.length;
    let Body = `${len}:${msg}`;

    //let cookies = await cookieStore.get(subUrl);
    let subResp = await fetch(
      //agent: httpAgent,
      subUrl,
      {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "text/plain;charset=UTF-8",
          //Cookie: cookies,
          ...defaultHeaders,
        },
        body: Body,
      },
    );
    if (!subResp.ok) {
      console.error(await subResp.text());
      throw new Error("bad response");
    }
    await cookieStore.set(subUrl, subResp);

    return subResp.text();
  };

  /*
  Eio3.poll = async function (sid) {
    let now = Date.now();
    let pollUrl = `${baseUrl}/socket.io/?EIO=3&transport=polling&t=${now}&sid=${sid}`;

    let cookies = await cookieStore.get(pollUrl);
    let pollResp = await request({
      //agent: httpAgent,
      method: "GET",
      url: pollUrl,
      headers: Object.assign(
        {
          Cookie: cookies,
        },
        defaultHeaders,
      ),
    });
    if (!pollResp.ok) {
      console.error(pollResp.toJSON());
      throw new Error("bad response");
    }
    await cookieStore.set(pollUrl, pollResp);

    return pollResp.body;
  };
  */

  Eio3.connectWs = async function (sid) {
    baseUrl = baseUrl.slice(4); // trim leading 'http'
    let url =
      `ws${baseUrl}/socket.io/?EIO=3&transport=websocket&sid=${sid}`.replace(
        "http",
        "ws",
      );

    //let cookies = await cookieStore.get(`${baseUrl}/`);
    let ws = new WSClient(url, {
      //agent: httpAgent,
      //perMessageDeflate: false,
      //@ts-ignore - type info is wrong
      headers: Object.assign(
        {
          //Cookie: cookies,
        },
        defaultHeaders,
      ),
    });

    let promise = new Promise(function (resolve) {
      ws.on("open", function open() {
        if (debug) {
          console.debug("=> Socket.io Hello ('2probe')");
        }
        ws.send("2probe");
      });

      ws.once("error", function (err: Error) {
        if (onError) {
          onError(err);
        } else {
          console.error("WebSocket Error:");
          console.error(err);
        }
      });

      ws.once("message", function message(data: Buffer) {
        if ("3probe" === data.toString()) {
          if (debug) {
            console.debug("<= Socket.io Welcome ('3probe')");
          }
          ws.send("5"); // no idea, but necessary
          if (debug) {
            console.debug("=> Socket.io ACK? ('5')");
          }
        } else {
          console.error("Unrecognized WebSocket Hello:");
          console.error(data.toString());
          // reject()
          process.exit(1);
        }
        resolve(ws);
      });
    });

    return await promise;
  };

  /** @type import('ws')? */
  wsc._ws = null;

  wsc.init = async function () {
    let session = await Eio3.connect();
    if (debug) {
      console.debug("Socket.io Session:");
      console.debug(session);
      console.debug();
    }

    let sub = await Eio3.subscribe(session.sid, "inv");
    if (debug) {
      console.debug("Socket.io Subscription:");
      console.debug(sub);
      console.debug();
    }

    /*
    let poll = await Eio3.poll(session.sid);
    if (debug) {
      console.debug("Socket.io Confirm:");
      console.debug(poll);
      console.debug();
    }
    */

    let ws = await Eio3.connectWs(session.sid);
    wsc._ws = ws;

    setPing();
    ws.on("message", _onMessage);
    ws.once("close", _onClose);

    function setPing() {
      setTimeout(function () {
        //ws.ping(); // standard
        ws.send("2"); // socket.io
        if (debug) {
          console.debug("=> Socket.io Ping");
        }
      }, session.pingInterval);
    }

    /**
     * @param {Buffer} buf
     */
    function _onMessage(buf: Buffer) {
      let msg = buf.toString();
      if ("3" === msg.toString()) {
        if (debug) {
          console.debug("<= Socket.io Pong");
          console.debug();
        }
        setPing();
        return;
      }

      if ("42" !== msg.slice(0, 2)) {
        console.warn("Unknown message:");
        console.warn(msg);
        return;
      }

      /** @type {InsightPush} */
      let [evname, data] = JSON.parse(msg.slice(2));
      if (onMessage) {
        onMessage(evname, data);
      }
      switch (evname) {
        case "tx":
        /* falls through */
        case "txlock":
        /* falls through */
        case "block":
        /* falls through */
        default:
          // TODO put check function here
          if (debug) {
            console.debug(`Received '${evname}':`);
            console.debug(data);
            console.debug();
          }
      }
    }

    function _onClose() {
      if (debug) {
        console.debug("WebSocket Close");
      }
      if (onClose) {
        onClose();
      }
    }
  };

  wsc.close = function () {
    wsc._ws?.close();
  };

  return wsc;
};

Ws.listen = async function (baseUrl, find) {
  let ws;
  let p = new Promise(async function (resolve, reject) {
    //@ts-ignore
    ws = Ws.create({
      baseUrl: baseUrl,
      cookieStore: "", //Cookies,
      //debug: true,
      onClose: resolve,
      onError: reject,
      onMessage:
        /**
         * @param {String} evname
         * @param {InsightSocketEventData} data
         */
        async function (evname: string, data: InsightSocketEventData) {
          let result;
          try {
            result = await find(evname, data);
          } catch (e) {
            reject(e);
            return;
          }

          if (result) {
            resolve(result);
          }
        },
    });

    await ws.init().catch(reject);
  });
  let result = await p;
  //@ts-ignore
  ws.close();
  return result;
};

// TODO waitForVouts(baseUrl, [{ address, satoshis }])

Ws.waitForVout = async function (
  baseUrl,
  addr,
  amount = 0,
  maxTxLockWait = 3000,
) {
  // Listen for Response
  let mempoolTx: SocketPayment;
  return await Ws.listen(baseUrl, findResponse);

  function findResponse(evname: string, data: InsightSocketEventData) {
    if (!["tx", "txlock"].includes(evname)) {
      return;
    }

    let now = Date.now();
    if (mempoolTx?.timestamp) {
      // don't wait longer than 3s for a txlock
      if (now - mempoolTx.timestamp > maxTxLockWait) {
        return mempoolTx;
      }
    }

    let result;
    // TODO should fetch tx and match hotwallet as vin
    data.vout.some(function (vout) {
      if (!(addr in vout)) {
        return false;
      }

      let duffs = vout[addr];
      if (amount && duffs !== amount) {
        return false;
      }

      let newTx = {
        address: addr,
        timestamp: now,
        txid: data.txid,
        satoshis: duffs,
        txlock: data.txlock,
      };

      if ("txlock" !== evname) {
        if (!mempoolTx) {
          mempoolTx = newTx;
        }
        return false;
      }

      result = newTx;
      return true;
    });

    return result;
  }
};

/*
async function sleep(ms) {
  return await new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}
*/

export default Ws;
