(function (require$$0$5, require$$0$4, require$$2$1, require$$0, require$$1, require$$0$1, require$$0$2, require$$1$1, require$$2, require$$0$3, require$$1$2) {
  'use strict';

  function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

  var require$$0__default$5 = /*#__PURE__*/_interopDefaultLegacy(require$$0$5);
  var require$$0__default$4 = /*#__PURE__*/_interopDefaultLegacy(require$$0$4);
  var require$$2__default$1 = /*#__PURE__*/_interopDefaultLegacy(require$$2$1);
  var require$$0__default = /*#__PURE__*/_interopDefaultLegacy(require$$0);
  var require$$1__default = /*#__PURE__*/_interopDefaultLegacy(require$$1);
  var require$$0__default$1 = /*#__PURE__*/_interopDefaultLegacy(require$$0$1);
  var require$$0__default$2 = /*#__PURE__*/_interopDefaultLegacy(require$$0$2);
  var require$$1__default$1 = /*#__PURE__*/_interopDefaultLegacy(require$$1$1);
  var require$$2__default = /*#__PURE__*/_interopDefaultLegacy(require$$2);
  var require$$0__default$3 = /*#__PURE__*/_interopDefaultLegacy(require$$0$3);
  var require$$1__default$2 = /*#__PURE__*/_interopDefaultLegacy(require$$1$2);

  var crowdnode$1 = {};

  var require$$3 = {name:"crowdnode",version:"1.6.0",description:"Manage your stake in Đash with the CrowdNode Blockchain API",main:"./lib/crowdnode.js",bin:{crowdnode:"./bin/crowdnode.js"},scripts:{test:"echo \"Error: no test specified\" && exit 1"},files:["bin","lib","tsconfig.json","types.js"],repository:{type:"git",url:"git+https://github.com/dashhive/crowdnode.js.git"},keywords:["Dash","CrowdNode","Blockchain","Stake","Staking"],author:"AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)",license:"SEE LICENSE IN LICENSE",bugs:{url:"https://github.com/dashhive/crowdnode.js/issues"},homepage:"https://github.com/dashhive/crowdnode.js#readme",dependencies:{"@dashevo/dashcore-lib":"^0.19.38","@root/request":"^1.8.1",dotenv:"^16.0.1","qrcode-svg":"^1.1.0","tough-cookie":"^4.0.0",ws:"^8.8.0"},devDependencies:{"@babel/core":"^7.18.6","@rollup/plugin-babel":"^5.3.1","@rollup/plugin-commonjs":"^22.0.1","@rollup/plugin-json":"^4.1.0","@rollup/plugin-replace":"^4.0.0","@types/tough-cookie":"^4.0.2","rollup-plugin-hashbang":"^3.0.0","rollup-plugin-polyfill-node":"^0.10.1"}};

  var _cipher = {exports: {}};

  (function (module) {

  	let Crypto = require$$0__default["default"];

  	let Cipher = module.exports;

  	const ALG = "aes-128-cbc";
  	const IV_SIZE = 16;

  	/**
  	 * @param {String} passphrase - what the human entered
  	 * @param {String} shadow - encrypted, hashed, key-expanded passphrase
  	 */
  	Cipher.checkPassphrase = async function (passphrase, shadow) {
  	  let key128 = await Cipher.deriveKey(passphrase);
  	  let cipher = Cipher.create(key128);

  	  let plainShadow;
  	  try {
  	    plainShadow = cipher.decrypt(shadow);
  	  } catch (e) {
  	    //@ts-ignore
  	    let msg = e.message;
  	    if (!msg.includes("decrypt")) {
  	      throw e;
  	    }
  	    return false;
  	  }

  	  let untrustedShadow = Crypto.createHash("sha512")
  	    .update(key128)
  	    .digest("base64");
  	  return Cipher.secureCompare(plainShadow, untrustedShadow);
  	};

  	/**
  	 * @param {String} passphrase - what the human entered
  	 */
  	Cipher.shadowPassphrase = async function (passphrase) {
  	  let key128 = await Cipher.deriveKey(passphrase);
  	  let plainShadow = Crypto.createHash("sha512").update(key128).digest("base64");
  	  let cipher = Cipher.create(key128);
  	  let shadow = cipher.encrypt(plainShadow);

  	  return shadow;
  	};

  	/**
  	 * @param {String} passphrase
  	 */
  	Cipher.deriveKey = async function (passphrase) {
  	  // See https://crypto.stackexchange.com/a/6557
  	  // and https://nodejs.org/api/crypto.html#cryptohkdfdigest-ikm-salt-info-keylen-callback
  	  const DIGEST = "sha512";
  	  const SALT = Buffer.from("crowdnode-cli", "utf8");
  	  // 'info' is a string describing a sub-context
  	  const INFO = Buffer.from("staking-keys", "utf8");
  	  const SIZE = 16;

  	  let ikm = Buffer.from(passphrase, "utf8");
  	  let key128 = await new Promise(function (resolve, reject) {
  	    //@ts-ignore
  	    Crypto.hkdf(DIGEST, ikm, SALT, INFO, SIZE, function (err, key128) {
  	      if (err) {
  	        reject(err);
  	        return;
  	      }
  	      resolve(Buffer.from(key128));
  	    });
  	  });

  	  return key128;
  	};

  	/**
  	 * @param {String} shadow
  	 * @param {Buffer} key128
  	 */
  	Cipher.checkShadow = function (shadow, key128) {
  	  let untrustedShadow = Crypto.createHash("sha512")
  	    .update(key128)
  	    .digest("base64");
  	  return Cipher.secureCompare(shadow, untrustedShadow);
  	};

  	/**
  	 * @param {String} a
  	 * @param {String} b
  	 */
  	Cipher.secureCompare = function (a, b) {
  	  if (!a && !b) {
  	    throw new Error("[secure compare] reference string should not be empty");
  	  }

  	  if (a.length !== b.length) {
  	    return false;
  	  }

  	  return Crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  	};

  	/**
  	 * @param {Buffer} key128
  	 */
  	Cipher.create = function (key128) {
  	  //let sharedSecret = Buffer.from(key128, "base64");

  	  let cipher = {};

  	  /**
  	   * @param {String} plaintext
  	   */
  	  cipher.encrypt = function (plaintext) {
  	    let initializationVector = Crypto.randomBytes(IV_SIZE); // IV is always 16-bytes
  	    let encrypted = "";

  	    let _cipher = Crypto.createCipheriv(ALG, key128, initializationVector);
  	    encrypted += _cipher.update(plaintext, "utf8", "base64");
  	    encrypted += _cipher.final("base64");

  	    return (
  	      toWeb64(initializationVector.toString("base64")) +
  	      ":" +
  	      toWeb64(encrypted) +
  	      ":" +
  	      // as a backup
  	      toWeb64(initializationVector.toString("base64"))
  	    );
  	  };

  	  /**
  	   * @param {String} parts
  	   */
  	  cipher.decrypt = function (parts) {
  	    let [initializationVector, encrypted, initializationVectorBak] =
  	      parts.split(":");
  	    let plaintext = "";
  	    if (initializationVector !== initializationVectorBak) {
  	      console.error("corrupt (but possibly recoverable) initialization vector");
  	    }

  	    let iv = Buffer.from(initializationVector, "base64");
  	    let _cipher = Crypto.createDecipheriv(ALG, key128, iv);
  	    plaintext += _cipher.update(encrypted, "base64", "utf8");
  	    plaintext += _cipher.final("utf8");

  	    return plaintext;
  	  };

  	  return cipher;
  	};

  	/**
  	 * @param {String} x
  	 */
  	function toWeb64(x) {
  	  return x.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  	}
  } (_cipher));

  var crowdnode = {exports: {}};

  let pkg$1 = require$$3;

  // provide a standards-compliant user-agent
  var request = require$$1__default["default"].defaults({
    userAgent: `${pkg$1.name}/${pkg$1.version}`,
  });

  var dash = {exports: {}};

  (function (module) {

  	let Dash = module.exports;

  	const DUFFS = 100000000;
  	const DUST = 10000;
  	const FEE = 1000;

  	let Dashcore = require$$0__default$1["default"];
  	let Transaction = Dashcore.Transaction;

  	Dash.create = function ({
  	  //@ts-ignore TODO
  	  insightApi,
  	}) {
  	  let dashApi = {};

  	  /**
  	   * Instant Balance is accurate with Instant Send
  	   * @param {String} address
  	   * @returns {Promise<InstantBalance>}
  	   */
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

  	  /**
  	   * Full Send!
  	   * @param {String} privKey
  	   * @param {String} pub
  	   */
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
  	   * @param {String} privKey
  	   * @param {(String|import('@dashevo/dashcore-lib').Address)} payAddr
  	   * @param {Number} amount
  	   * @param {(String|import('@dashevo/dashcore-lib').Address)} [changeAddr]
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
  	   * @param {String} utxoAddr
  	   * @param {Number} fullAmount - including fee estimate
  	   */
  	  async function getOptimalUtxos(utxoAddr, fullAmount) {
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

  	    /** @type Array<CoreUtxo> */
  	    let included = [];
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

  	  /**
  	   * @param {Array<CoreUtxo>} utxos
  	   */
  	  function getBalance(utxos) {
  	    return utxos.reduce(function (total, utxo) {
  	      return total + utxo.satoshis;
  	    }, 0);
  	  }

  	  /**
  	   * @param {Array<InsightUtxo>} body
  	   */
  	  async function getUtxos(body) {
  	    /** @type Array<CoreUtxo> */
  	    let utxos = [];

  	    await body.reduce(async function (promise, utxo) {
  	      await promise;

  	      let data = await insightApi.getTx(utxo.txid);

  	      // TODO the ideal would be the smallest amount that is greater than the required amount

  	      let utxoIndex = -1;
  	      data.vout.some(function (vout, index) {
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
  } (dash));

  var insight = {exports: {}};

  (function (module) {

  	let Insight = module.exports;

  	let request$1 = request;

  	/**
  	 * @param {Object} opts
  	 * @param {String} opts.baseUrl
  	 */
  	Insight.create = function ({ baseUrl }) {
  	  let insight = {};

  	  /**
  	   * Don't use this with instantSend
  	   * @param {String} address
  	   * @returns {Promise<InsightBalance>}
  	   */
  	  insight.getBalance = async function (address) {
  	    console.warn(`warn: getBalance(pubkey) doesn't account for instantSend,`);
  	    console.warn(`      consider (await getUtxos()).reduce(countSatoshis)`);
  	    let txUrl = `${baseUrl}/insight-api/addr/${address}/?noTxList=1`;
  	    let txResp = await request$1({ url: txUrl, json: true });

  	    /** @type {InsightBalance} */
  	    let data = txResp.body;
  	    return data;
  	  };

  	  /**
  	   * @param {String} address
  	   * @returns {Promise<Array<InsightUtxo>>}
  	   */
  	  insight.getUtxos = async function (address) {
  	    let utxoUrl = `${baseUrl}/insight-api/addr/${address}/utxo`;
  	    let utxoResp = await request$1({ url: utxoUrl, json: true });

  	    /** @type Array<InsightUtxo> */
  	    let utxos = utxoResp.body;
  	    return utxos;
  	  };

  	  /**
  	   * @param {String} txid
  	   * @returns {Promise<InsightTx>}
  	   */
  	  insight.getTx = async function (txid) {
  	    let txUrl = `${baseUrl}/insight-api/tx/${txid}`;
  	    let txResp = await request$1({ url: txUrl, json: true });

  	    /** @type InsightTx */
  	    let data = txResp.body;
  	    return data;
  	  };

  	  /**
  	   * @param {String} addr
  	   * @param {Number} maxPages
  	   * @returns {Promise<InsightTxResponse>}
  	   */
  	  insight.getTxs = async function (addr, maxPages) {
  	    let txUrl = `${baseUrl}/insight-api/txs?address=${addr}&pageNum=0`;
  	    let txResp = await request$1({ url: txUrl, json: true });

  	    /** @type {InsightTxResponse} */
  	    let body = txResp.body;

  	    let data = await getAllPages(body, addr, maxPages);
  	    return data;
  	  };

  	  /**
  	   * @param {InsightTxResponse} body
  	   * @param {String} addr
  	   * @param {Number} maxPages
  	   */
  	  async function getAllPages(body, addr, maxPages) {
  	    let pagesTotal = Math.min(body.pagesTotal, maxPages);
  	    for (let cursor = 1; cursor < pagesTotal; cursor += 1) {
  	      let nextResp = await request$1({
  	        url: `${baseUrl}/insight-api/txs?address=${addr}&pageNum=${cursor}`,
  	        json: true,
  	      });
  	      // Note: this could still be wrong, but I don't think we have
  	      // a better way to page so... whatever
  	      body.txs = body.txs.concat(nextResp.body.txs);
  	    }
  	    return body;
  	  }

  	  /**
  	   * @param {String} hexTx
  	   */
  	  insight.instantSend = async function (hexTx) {
  	    let instUrl = `${baseUrl}/insight-api-dash/tx/sendix`;
  	    let reqObj = {
  	      method: "POST",
  	      url: instUrl,
  	      form: {
  	        rawtx: hexTx,
  	      },
  	    };
  	    let txResp = await request$1(reqObj);
  	    if (!txResp.ok) {
  	      // TODO better error check
  	      throw new Error(JSON.stringify(txResp.body, null, 2));
  	    }
  	    return txResp.toJSON();
  	  };

  	  return insight;
  	};
  } (insight));

  var ws = {exports: {}};

  var cookies = {exports: {}};

  (function (module) {

  	/** @type CookieStore */
  	let Cookies = module.exports;

  	let Cookie = require$$0__default$2["default"];
  	//@ts-ignore TODO
  	//let FileCookieStore = require("@root/file-cookie-store");
  	//let cookies_store = new FileCookieStore("./cookie.txt", { auto_sync: false });
  	let jar = new Cookie.CookieJar(/*cookies_store*/);
  	jar.setCookieAsync = require$$1__default$1["default"].promisify(jar.setCookie);
  	jar.getCookiesAsync = require$$1__default$1["default"].promisify(jar.getCookies);
  	//cookies_store.saveAsync = require("util").promisify(cookies_store.save);

  	/**
  	 * @param {String} url
  	 * @param {import('http').IncomingMessage} resp
  	 * @returns {Promise<void>}
  	 */
  	Cookies.set = async function _setCookie(url, resp) {
  	  let cookies;
  	  if (resp.headers["set-cookie"]) {
  	    if (Array.isArray(resp.headers["set-cookie"])) {
  	      cookies = resp.headers["set-cookie"].map(Cookie.parse);
  	    } else {
  	      cookies = [Cookie.parse(resp.headers["set-cookie"])];
  	    }
  	  }

  	  // let Cookie = //require('set-cookie-parser');
  	  // Cookie.parse(resp, { decodeValues: true });
  	  await Promise.all(
  	    cookies.map(async function (cookie) {
  	      //console.log('DEBUG cookie:', cookie.toJSON());
  	      await jar.setCookieAsync(cookie, url, { now: new Date() });
  	    }),
  	  );
  	  //await cookies_store.saveAsync();
  	};

  	/**
  	 * @param {String} url
  	 * @returns {Promise<String>}
  	 */
  	Cookies.get = async function _getCookie(url) {
  	  return (await jar.getCookiesAsync(url)).toString();
  	};
  } (cookies));

  (function (module) {

  	let Ws = module.exports;

  	let Cookies = cookies.exports;
  	let request$1 = request;

  	let WSClient = require$$2__default["default"];

  	/**
  	 * @param {Object} opts
  	 * @param {String} opts.baseUrl
  	 * @param {CookieStore} opts.cookieStore
  	 * @param {Boolean} opts.debug
  	 * @param {Function} opts.onClose
  	 * @param {Function} opts.onError
  	 * @param {Function} opts.onMessage
  	 */
  	Ws.create = function ({
  	  baseUrl,
  	  cookieStore,
  	  debug,
  	  onClose,
  	  onError,
  	  onMessage,
  	}) {
  	  let wsc = {};

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

  	  let Eio3 = {};
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

  	    let cookies = await cookieStore.get(sidUrl);
  	    let sidResp = await request$1({
  	      //agent: httpAgent,
  	      url: sidUrl,
  	      headers: Object.assign(
  	        {
  	          Cookie: cookies,
  	        },
  	        defaultHeaders,
  	      ),
  	      json: false,
  	    });
  	    if (!sidResp.ok) {
  	      console.error(sidResp.toJSON());
  	      throw new Error("bad response");
  	    }
  	    await cookieStore.set(sidUrl, sidResp);

  	    // ex: `97:0{"sid":"xxxx",...}`
  	    let msg = sidResp.body;
  	    let colonIndex = msg.indexOf(":");
  	    // 0 is CONNECT, which will always follow our first message
  	    let start = colonIndex + ":0".length;
  	    let len = parseInt(msg.slice(0, colonIndex), 10);
  	    let json = msg.slice(start, start + (len - 1));

  	    //console.log("Socket.io Connect:");
  	    //console.log(msg);
  	    //console.log(json);

  	    // @type {SocketIoHello}
  	    let session = JSON.parse(json);
  	    return session;
  	  };

  	  /**
  	   * @param {String} sid
  	   * @param {String} eventname
  	   */
  	  Eio3.subscribe = async function (sid, eventname) {
  	    let now = Date.now();
  	    let subUrl = `${baseUrl}/socket.io/?EIO=3&transport=polling&t=${now}&sid=${sid}`;
  	    let sub = JSON.stringify(["subscribe", eventname]);
  	    // not really sure what this is, couldn't find documentation for it
  	    let typ = 422; // 4 = MESSAGE, 2 = EVENT, 2 = ???
  	    let msg = `${typ}${sub}`;
  	    let len = msg.length;
  	    let body = `${len}:${msg}`;

  	    let cookies = await cookieStore.get(subUrl);
  	    let subResp = await request$1({
  	      //agent: httpAgent,
  	      method: "POST",
  	      url: subUrl,
  	      headers: Object.assign(
  	        {
  	          "Content-Type": "text/plain;charset=UTF-8",
  	          Cookie: cookies,
  	        },
  	        defaultHeaders,
  	      ),
  	      body: body,
  	    });
  	    if (!subResp.ok) {
  	      console.error(subResp.toJSON());
  	      throw new Error("bad response");
  	    }
  	    await cookieStore.set(subUrl, subResp);

  	    return subResp.body;
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

  	  /**
  	   * @param {String} sid - session id (associated with AWS ALB cookie)
  	   */
  	  Eio3.connectWs = async function (sid) {
  	    baseUrl = baseUrl.slice(4); // trim leading 'http'
  	    let url =
  	      `ws${baseUrl}/socket.io/?EIO=3&transport=websocket&sid=${sid}`.replace(
  	        "http",
  	        "ws",
  	      );

  	    let cookies = await cookieStore.get(`${baseUrl}/`);
  	    let ws = new WSClient(url, {
  	      //agent: httpAgent,
  	      //perMessageDeflate: false,
  	      //@ts-ignore - type info is wrong
  	      headers: Object.assign(
  	        {
  	          Cookie: cookies,
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

  	      ws.once("error", function (err) {
  	        if (onError) {
  	          onError(err);
  	        } else {
  	          console.error("WebSocket Error:");
  	          console.error(err);
  	        }
  	      });

  	      ws.once("message", function message(data) {
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
  	    function _onMessage(buf) {
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

  	/**
  	 * @param {String} baseUrl
  	 * @param {Function} find
  	 */
  	Ws.listen = async function (baseUrl, find) {
  	  let ws;
  	  let p = new Promise(async function (resolve, reject) {
  	    //@ts-ignore
  	    ws = Ws.create({
  	      baseUrl: baseUrl,
  	      cookieStore: Cookies,
  	      //debug: true,
  	      onClose: resolve,
  	      onError: reject,
  	      onMessage:
  	        /**
  	         * @param {String} evname
  	         * @param {InsightSocketEventData} data
  	         */
  	        async function (evname, data) {
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

  	/**
  	 * @param {String} baseUrl
  	 * @param {String} addr
  	 * @param {Number} [amount]
  	 * @param {Number} [maxTxLockWait]
  	 * @returns {Promise<SocketPayment>}
  	 */
  	Ws.waitForVout = async function (
  	  baseUrl,
  	  addr,
  	  amount = 0,
  	  maxTxLockWait = 3000,
  	) {
  	  // Listen for Response
  	  /** @type SocketPayment */
  	  let mempoolTx;
  	  return await Ws.listen(baseUrl, findResponse);

  	  /**
  	   * @param {String} evname
  	   * @param {InsightSocketEventData} data
  	   */
  	  function findResponse(evname, data) {
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
  } (ws));

  (function (module) {

  	let request$1 = request;

  	let CrowdNode = module.exports;

  	const DUFFS = 100000000;

  	let Dash = dash.exports;
  	let Dashcore = require$$0__default$1["default"];
  	let Insight = insight.exports;
  	let Ws = ws.exports;

  	CrowdNode._insightBaseUrl = "";
  	// TODO don't require these shims
  	CrowdNode._insightApi = Insight.create({ baseUrl: "" });
  	CrowdNode._dashApi = Dash.create({ insightApi: CrowdNode._insightApi });

  	CrowdNode.main = {
  	  baseUrl: "https://app.crowdnode.io",
  	  hotwallet: "",
  	};

  	CrowdNode.test = {
  	  baseUrl: "https://test.crowdnode.io",
  	  hotwallet: "",
  	};

  	CrowdNode._baseUrl = CrowdNode.main.baseUrl;

  	CrowdNode.offset = 20000;
  	CrowdNode.duffs = 100000000;
  	CrowdNode.depositMinimum = 10000;
  	CrowdNode.stakeMinimum = toDuff(0.5);

  	/**
  	 * @type {Record<String, Number>}
  	 */
  	CrowdNode.requests = {
  	  acceptTerms: 65536,
  	  offset: 20000,
  	  signupForApi: 131072,
  	  toggleInstantPayout: 4096,
  	  withdrawMin: 1,
  	  withdrawMax: 1000,
  	};

  	/**
  	 * @type {Record<Number, String>}
  	 */
  	CrowdNode._responses = {
  	  2: "PleaseAcceptTerms",
  	  4: "WelcomeToCrowdNodeBlockChainAPI",
  	  8: "DepositReceived",
  	  16: "WithdrawalQueued",
  	  32: "WithdrawalFailed", // Most likely too small amount requested for withdrawal.
  	  64: "AutoWithdrawalEnabled",
  	  128: "AutoWithdrawalDisabled",
  	};
  	/**
  	 * @type {Record<String, Number>}
  	 */
  	CrowdNode.responses = {
  	  PleaseAcceptTerms: 2,
  	  WelcomeToCrowdNodeBlockChainAPI: 4,
  	  DepositReceived: 8,
  	  WithdrawalQueued: 16,
  	  WithdrawalFailed: 32,
  	  AutoWithdrawalEnabled: 64,
  	  AutoWithdrawalDisabled: 128,
  	};

  	/**
  	 * @param {Object} opts
  	 * @param {String} opts.baseUrl
  	 * @param {String} opts.insightBaseUrl
  	 */
  	CrowdNode.init = async function ({ baseUrl, insightBaseUrl }) {
  	  // TODO use API
  	  // See https://github.com/dashhive/crowdnode.js/issues/3

  	  CrowdNode._baseUrl = baseUrl;

  	  //hotwallet in Mainnet is XjbaGWaGnvEtuQAUoBgDxJWe8ZNv45upG2
  	  CrowdNode.main.hotwallet = await request$1({
  	    // TODO https://app.crowdnode.io/odata/apifundings/HotWallet
  	    url: "https://knowledge.crowdnode.io/en/articles/5963880-blockchain-api-guide",
  	  }).then(createAddrParser("hotwallet in Main"));

  	  //hotwallet in Test is yMY5bqWcknGy5xYBHSsh2xvHZiJsRucjuy
  	  CrowdNode.test.hotwallet = await request$1({
  	    // TODO https://test.crowdnode.io/odata/apifundings/HotWallet
  	    url: "https://knowledge.crowdnode.io/en/articles/5963880-blockchain-api-guide",
  	  }).then(createAddrParser("hotwallet in Test"));

  	  CrowdNode._insightBaseUrl = insightBaseUrl;
  	  CrowdNode._insightApi = Insight.create({
  	    baseUrl: insightBaseUrl,
  	  });
  	  CrowdNode._dashApi = Dash.create({ insightApi: CrowdNode._insightApi });
  	};

  	/**
  	 * @param {String} signupAddr
  	 * @param {String} hotwallet
  	 */
  	CrowdNode.status = async function (signupAddr, hotwallet) {
  	  let maxPages = 10;
  	  let data = await CrowdNode._insightApi.getTxs(signupAddr, maxPages);
  	  let status = {
  	    signup: 0,
  	    accept: 0,
  	    deposit: 0,
  	  };

  	  data.txs.forEach(function (tx) {
  	    // all inputs (utxos) must come from hotwallet
  	    let fromHotwallet = tx.vin.every(function (vin) {
  	      return vin.addr === hotwallet;
  	    });
  	    if (!fromHotwallet) {
  	      return;
  	    }

  	    // must have one output matching the "welcome" value to the signupAddr
  	    tx.vout.forEach(function (vout) {
  	      if (vout.scriptPubKey.addresses[0] !== signupAddr) {
  	        return;
  	      }
  	      let amount = Math.round(parseFloat(vout.value) * DUFFS);
  	      let msg = amount - CrowdNode.offset;

  	      if (CrowdNode.responses.DepositReceived === msg) {
  	        status.deposit = tx.time;
  	        status.signup = status.signup || 1;
  	        status.accept = status.accept || 1;
  	        return;
  	      }

  	      if (CrowdNode.responses.WelcomeToCrowdNodeBlockChainAPI === msg) {
  	        status.signup = status.signup || 1;
  	        status.accept = tx.time || 1;
  	        return;
  	      }

  	      if (CrowdNode.responses.PleaseAcceptTerms === msg) {
  	        status.signup = tx.time;
  	        return;
  	      }
  	    });
  	  });

  	  if (!status.signup) {
  	    return null;
  	  }
  	  return status;
  	};

  	/**
  	 * @param {String} wif
  	 * @param {String} hotwallet
  	 */
  	CrowdNode.signup = async function (wif, hotwallet) {
  	  // Send Request Message
  	  let pk = new Dashcore.PrivateKey(wif);
  	  let msg = CrowdNode.offset + CrowdNode.requests.signupForApi;
  	  let changeAddr = pk.toPublicKey().toAddress().toString();
  	  let tx = await CrowdNode._dashApi.createPayment(
  	    wif,
  	    hotwallet,
  	    msg,
  	    changeAddr,
  	  );
  	  await CrowdNode._insightApi.instantSend(tx.serialize());

  	  let reply = CrowdNode.offset + CrowdNode.responses.PleaseAcceptTerms;
  	  return await Ws.waitForVout(CrowdNode._insightBaseUrl, changeAddr, reply);
  	};

  	/**
  	 * @param {String} wif
  	 * @param {String} hotwallet
  	 */
  	CrowdNode.accept = async function (wif, hotwallet) {
  	  // Send Request Message
  	  let pk = new Dashcore.PrivateKey(wif);
  	  let msg = CrowdNode.offset + CrowdNode.requests.acceptTerms;
  	  let changeAddr = pk.toPublicKey().toAddress().toString();
  	  let tx = await CrowdNode._dashApi.createPayment(
  	    wif,
  	    hotwallet,
  	    msg,
  	    changeAddr,
  	  );
  	  await CrowdNode._insightApi.instantSend(tx.serialize());

  	  let reply =
  	    CrowdNode.offset + CrowdNode.responses.WelcomeToCrowdNodeBlockChainAPI;
  	  return await Ws.waitForVout(CrowdNode._insightBaseUrl, changeAddr, reply);
  	};

  	/**
  	 * @param {String} wif
  	 * @param {String} hotwallet
  	 * @param {Number} amount - Duffs (1/100000000 Dash)
  	 */
  	CrowdNode.deposit = async function (wif, hotwallet, amount) {
  	  // Send Request Message
  	  let pk = new Dashcore.PrivateKey(wif);
  	  let changeAddr = pk.toPublicKey().toAddress().toString();

  	  // TODO reserve a balance
  	  let tx;
  	  if (amount) {
  	    tx = await CrowdNode._dashApi.createPayment(
  	      wif,
  	      hotwallet,
  	      amount,
  	      changeAddr,
  	    );
  	  } else {
  	    tx = await CrowdNode._dashApi.createBalanceTransfer(wif, hotwallet);
  	  }
  	  await CrowdNode._insightApi.instantSend(tx.serialize());

  	  let reply = CrowdNode.offset + CrowdNode.responses.DepositReceived;
  	  return await Ws.waitForVout(CrowdNode._insightBaseUrl, changeAddr, reply);
  	};

  	/**
  	 * @param {String} wif
  	 * @param {String} hotwallet
  	 * @param {Number} permil - 1/1000 (1/10 of a percent) 500 permille = 50.0 percent
  	 */
  	CrowdNode.withdrawal = async function (wif, hotwallet, permil) {
  	  let valid = permil > 0 && permil <= 1000;
  	  valid = valid && Math.round(permil) === permil;
  	  if (!valid) {
  	    throw new Error(`'permil' must be between 1 and 1000, not '${permil}'`);
  	  }

  	  // Send Request Message
  	  let pk = new Dashcore.PrivateKey(wif);
  	  let msg = CrowdNode.offset + permil;
  	  let changeAddr = pk.toPublicKey().toAddress().toString();
  	  let tx = await CrowdNode._dashApi.createPayment(
  	    wif,
  	    hotwallet,
  	    msg,
  	    changeAddr,
  	  );
  	  await CrowdNode._insightApi.instantSend(tx.serialize());

  	  // Listen for Response
  	  let mempoolTx = {
  	    address: "",
  	    api: "",
  	    at: 0,
  	    txid: "",
  	    satoshis: 0,
  	    txlock: false,
  	  };
  	  return await Ws.listen(CrowdNode._insightBaseUrl, findResponse);

  	  /**
  	   * @param {String} evname
  	   * @param {InsightSocketEventData} data
  	   */
  	  function findResponse(evname, data) {
  	    if (!["tx", "txlock"].includes(evname)) {
  	      return;
  	    }

  	    let now = Date.now();
  	    if (mempoolTx.at) {
  	      // don't wait longer than 3s for a txlock
  	      if (now - mempoolTx.at > 3000) {
  	        return mempoolTx;
  	      }
  	    }

  	    let result;
  	    // TODO should fetch tx and match hotwallet as vin
  	    data.vout.some(function (vout) {
  	      return Object.keys(vout).some(function (addr) {
  	        if (addr !== changeAddr) {
  	          return false;
  	        }

  	        let duffs = vout[addr];
  	        let msg = duffs - CrowdNode.offset;
  	        let api = CrowdNode._responses[msg];
  	        if (!api) {
  	          // the withdrawal often happens before the queued message
  	          console.warn(`  => received '${duffs}' (${evname})`);
  	          return false;
  	        }

  	        let newTx = {
  	          address: addr,
  	          api: api.toString(),
  	          at: now,
  	          txid: data.txid,
  	          satoshis: duffs,
  	          txlock: data.txlock,
  	        };

  	        if ("txlock" !== evname) {
  	          // wait up to 3s for a txlock
  	          if (!mempoolTx) {
  	            mempoolTx = newTx;
  	          }
  	          return false;
  	        }

  	        result = newTx;
  	        return true;
  	      });
  	    });

  	    return result;
  	  }
  	};

  	// See ./bin/crowdnode-list-apis.sh
  	CrowdNode.http = {};

  	/**
  	 * @param {String} baseUrl
  	 * @param {String} pub
  	 */
  	CrowdNode.http.FundsOpen = async function (pub) {
  	  return `Open <${CrowdNode._baseUrl}/FundsOpen/${pub}> in your browser.`;
  	};

  	/**
  	 * @param {String} baseUrl
  	 * @param {String} pub
  	 */
  	CrowdNode.http.VotingOpen = async function (pub) {
  	  return `Open <${CrowdNode._baseUrl}/VotingOpen/${pub}> in your browser.`;
  	};

  	/**
  	 * @param {String} baseUrl
  	 * @param {String} pub
  	 */
  	CrowdNode.http.GetFunds = createApi(
  	  `/odata/apifundings/GetFunds(address='{1}')`,
  	);

  	/**
  	 * @param {String} baseUrl
  	 * @param {String} pub
  	 * @param {String} secondsSinceEpoch
  	 */
  	CrowdNode.http.GetFundsFrom = createApi(
  	  `/odata/apifundings/GetFundsFrom(address='{1}',fromUnixTime={2})`,
  	);

  	/**
  	 * @param {String} baseUrl
  	 * @param {String} pub
  	 * @returns {CrowdNodeBalance}
  	 */
  	CrowdNode.http.GetBalance = createApi(
  	  `/odata/apifundings/GetBalance(address='{1}')`,
  	);

  	/**
  	 * @param {String} baseUrl
  	 * @param {String} pub
  	 */
  	CrowdNode.http.GetMessages = createApi(
  	  `/odata/apimessages/GetMessages(address='{1}')`,
  	);

  	/**
  	 * @param {String} baseUrl
  	 * @param {String} pub
  	 */
  	CrowdNode.http.IsAddressInUse = createApi(
  	  `/odata/apiaddresses/IsAddressInUse(address='{1}')`,
  	);

  	/**
  	 * Set Email Address: messagetype=1
  	 * @param {String} baseUrl
  	 * @param {String} pub - pay to pubkey base58check address
  	 * @param {String} email
  	 * @param {String} signature
  	 */
  	CrowdNode.http.SetEmail = createApi(
  	  `/odata/apimessages/SendMessage(address='{1}',message='{2}',signature='{3}',messagetype=1)`,
  	);

  	/**
  	 * Vote on Governance Objects: messagetype=2
  	 * @param {String} baseUrl
  	 * @param {String} pub - pay to pubkey base58check address
  	 * @param {String} gobject-hash
  	 * @param {String} choice - Yes|No|Abstain|Delegate|DoNothing
  	 * @param {String} signature
  	 */
  	CrowdNode.http.Vote = createApi(
  	  `/odata/apimessages/SendMessage(address='{1}',message='{2},{3}',signature={4}',messagetype=2)`,
  	);

  	/**
  	 * Set Referral: messagetype=3
  	 * @param {String} baseUrl
  	 * @param {String} pub - pay to pubkey base58check address
  	 * @param {String} referralId
  	 * @param {String} signature
  	 */
  	CrowdNode.http.SetReferral = createApi(
  	  `/odata/apimessages/SendMessage(address='{1}',message='{2}',signature='{3}',messagetype=3)`,
  	);

  	/**
  	 * @param {String} tmplUrl
  	 */
  	function createApi(tmplUrl) {
  	  /**
  	   * @param {Array<String>} arguments - typically just 'pub', unless SendMessage
  	   */
  	  return async function () {
  	    /** @type Array<String> */
  	    //@ts-ignore - arguments
  	    let args = [].slice.call(arguments, 0);

  	    // ex:
  	    let url = `${CrowdNode._baseUrl}${tmplUrl}`;
  	    args.forEach(function (arg, i) {
  	      let n = i + 1;
  	      url = url.replace(new RegExp(`\\{${n}\\}`, "g"), arg);
  	    });

  	    let resp = await request$1({
  	      // TODO https://app.crowdnode.io/odata/apifundings/HotWallet
  	      method: "GET",
  	      url: url,
  	      json: true,
  	    });
  	    if (!resp.ok) {
  	      let err = new Error(
  	        `http error: ${resp.statusCode} ${resp.body.message}`,
  	      );
  	      //@ts-ignore
  	      err.response = resp.toJSON();
  	      throw err;
  	    }

  	    return resp.body;
  	  };
  	}

  	/**
  	 * @param {String} prefix
  	 */
  	function createAddrParser(prefix) {
  	  /**
  	   * @param {import('http').IncomingMessage} resp
  	   */
  	  return function (resp) {
  	    //@ts-ignore
  	    let html = resp.body;
  	    return parseAddr(prefix, html);
  	  };
  	}

  	/**
  	 * @param {String} prefix
  	 * @param {String} html
  	 */
  	function parseAddr(prefix, html) {
  	  // TODO escape prefix
  	  // TODO restrict to true base58 (not base62)
  	  let addrRe = new RegExp(prefix + "[^X]+\\b([Xy][a-z0-9]{33})\\b", "i");

  	  let m = html.match(addrRe);
  	  if (!m) {
  	    throw new Error("could not find hotwallet address");
  	  }

  	  let hotwallet = m[1];
  	  return hotwallet;
  	}

  	if (require.main === module) {
  	  (async function main() {
  	    //@ts-ignore
  	    await CrowdNode.init({
  	      //@ts-ignore
  	      baseUrl: CrowdNode.main.baseUrl,
  	      insightBaseUrl: "https://insight.dash.org",
  	    });
  	    console.info(CrowdNode);
  	  })().catch(function (err) {
  	    console.error(err);
  	  });
  	}

  	function toDuff(dash) {
  	  return Math.round(parseFloat(dash) * DUFFS);
  	}
  } (crowdnode));

  var _prompt = {exports: {}};

  (function (module) {

  	let Prompt = module.exports;

  	/**
  	 * @param {String} query
  	 * @param {Object} [options]
  	 * @param {Array<String>} [options.choices]
  	 * @param {Boolean} [options.mask]
  	 */
  	Prompt.prompt = async function (query, options) {
  	  let Readline = require$$0__default$3["default"];

  	  let completer;
  	  if (options?.choices) {
  	    /**
  	     * @param {String} line
  	     */
  	    completer = function (line) {
  	      let completions = options.choices || [];
  	      let hits = completions.filter(function (c) {
  	        return c.startsWith(line);
  	      });
  	      if (!hits.length) {
  	        hits = completions;
  	      }
  	      return [hits, line];
  	    };
  	  }

  	  let rl = Readline.createInterface({
  	    input: process.stdin,
  	    output: process.stdout,
  	    completer,
  	  });

  	  if (options?.mask) {
  	    //@ts-ignore
  	    rl.input.on("keypress", function (_char, _modifiers) {
  	      // _char = "e"
  	      // _modifiers = { sequence: 'e', name: 'e', ctrl: false, meta: false, shift: false }
  	      let len = rl.line.length;
  	      // place cursor at the beginning of the prompt
  	      //@ts-ignore
  	      Readline.moveCursor(rl.output, -len, 0);
  	      // clear right of the cursor / prompt
  	      //@ts-ignore
  	      Readline.clearLine(rl.output, 1);
  	      // mask with "*"
  	      //@ts-ignore
  	      rl.output.write("*".repeat(len));
  	    });
  	  }

  	  let answer = await new Promise(function (resolve) {
  	    return rl.question(query ?? "", resolve);
  	  });

  	  // TODO what if we need control over closing?
  	  // ex: Promise.race([getPrompt, getFsEvent, getSocketEvent]);
  	  rl.close();
  	  return answer;
  	};
  } (_prompt));

  var qr = {exports: {}};

  (function (module) {

  	let Qr = module.exports;

  	let Fs = require$$0__default$4["default"].promises;

  	let QrCode = require$$1__default$2["default"];

  	let isBrowser = typeof window !== "undefined";

  	/**
  	 * @typedef QrOpts
  	 * @property {String} [background]
  	 * @property {String} [color]
  	 * @property {String} [ecl]
  	 * @property {Number} [height]
  	 * @property {Number} [indent]
  	 * @property {Number} [padding]
  	 * @property {"mini" | "micro"} [size]
  	 * @property {Number} [width]
  	 */

  	/**
  	 * @param {String} data
  	 * @param {QrOpts} opts
  	 */
  	Qr._create = function (data, opts) {
  	  return new QrCode({
  	    content: data,
  	    padding: opts?.padding || 4,
  	    width: opts?.width || 256,
  	    height: opts?.height || 256,
  	    color: opts?.color || "#000000",
  	    background: opts?.background || "#ffffff",
  	    ecl: opts?.ecl || "M",
  	  });
  	};

  	/**
  	 * @typedef {Object.<String, String>} BlockMap
  	 */

  	/**
  	 * Encoded as top-left, top-right, bottom-left, bottom-right
  	 * @type {Object.<"mini" | "micro", BlockMap>}
  	 */
  	let charMaps = {
  	  micro: {
  	    0b0000: " ",
  	    0b0001: "▗",
  	    0b0010: "▖",
  	    0b0011: "▄",
  	    0b0100: "▝",
  	    0b0101: "▐",
  	    0b0110: "▞",
  	    0b0111: "▟",
  	    0b1000: "▘",
  	    0b1001: "▚",
  	    0b1010: "▌",
  	    0b1011: "▙",
  	    0b1100: "▀",
  	    0b1101: "▜",
  	    0b1110: "▛",
  	    0b1111: "█",
  	  },
  	  mini: {
  	    0b0000: "  ",
  	    0b0001: " ▄",
  	    0b0010: "▄ ",
  	    0b0011: "▄▄",
  	    0b0100: " ▀",
  	    0b0101: " █",
  	    0b0110: "▄▀",
  	    0b0111: "▄█",
  	    0b1000: "▀ ",
  	    0b1001: "▀▄",
  	    0b1010: "█ ",
  	    0b1011: "█▄",
  	    0b1100: "▀▀",
  	    0b1101: "▀█",
  	    0b1110: "█▀",
  	    0b1111: "██",
  	  },
  	};

  	/**
  	 * @param {String} data
  	 * @param {QrOpts} opts
  	 */
  	Qr.quadAscii = function (data, opts) {
  	  let charMap = charMaps[opts.size || "mini"];
  	  let qrcode = Qr._create(data, opts);
  	  let indent = opts?.indent ?? 4;
  	  let modules = qrcode.qrcode.modules;

  	  let ascii = ``.padStart(indent - 1, " ");
  	  let length = modules.length;
  	  for (let y = 0; y < length; y += 2) {
  	    for (let x = 0; x < length; x += 2) {
  	      let count = 0;
  	      // qr codes can be odd numbers
  	      if (x >= length) {
  	        ascii += charMap[count];
  	        continue;
  	      }
  	      if (modules[x][y]) {
  	        count += 8;
  	      }
  	      if (modules[x][y + 1]) {
  	        count += 2;
  	      }

  	      if (x + 1 >= length) {
  	        ascii += charMap[count];
  	        continue;
  	      }
  	      if (modules[x + 1][y]) {
  	        count += 4;
  	      }
  	      if (modules[x + 1][y + 1]) {
  	        count += 1;
  	      }
  	      ascii += charMap[count];
  	    }
  	    ascii += `\n`.padEnd(indent, " ");
  	  }
  	  return ascii.replace(/\s+$/, "");
  	};

  	/**
  	 * @param {String} data
  	 * @param {QrOpts} opts
  	 */
  	Qr.ascii = function (data, opts) {
  	  if (opts.size) {
  	    return Qr.quadAscii(data, opts);
  	  }

  	  let qrcode = Qr._create(data, opts);
  	  let indent = opts?.indent ?? 4;
  	  let modules = qrcode.qrcode.modules;

  	  let ascii = ``.padStart(indent - 1, " ");
  	  let length = modules.length;
  	  for (let y = 0; y < length; y += 1) {
  	    for (let x = 0; x < length; x += 1) {
  	      let block = "  ";
  	      if (modules[x][y]) {
  	        block = "██";
  	      }
  	      ascii += block;
  	    }
  	    ascii += `\n`.padEnd(indent, " ");
  	  }
  	  return ascii;
  	};

  	/**
  	 * @param {String} data
  	 * @param {QrOpts} opts
  	 */
  	Qr.svg = function (data, opts) {
  	  let qrcode = Qr._create(data, opts);
  	  return qrcode.svg();
  	};

  	/**
  	 * @param {String} filepath
  	 * @param {String} data
  	 * @param {QrOpts} opts
  	 */
  	Qr.save = async function (filepath, data, opts) {
  	  let qrcode = Qr.svg(data, opts);
  	  if (!isBrowser) {
  	    await Fs.Fs.writeFile(filepath, qrcode, "utf8");
  	  }
  	};
  } (qr));

  /*jshint maxcomplexity:25 */

  require$$0__default$5["default"].config({ path: ".env" }) || "";
  require$$0__default$5["default"].config({ path: ".env.secret" }) || "";

  let isBrowser = typeof window !== "undefined";

  var HOME = process.env.HOME || "";

  let Fs = require$$0__default$4["default"].promises;
  let Path = require$$2__default$1["default"];

  //@ts-ignore
  let pkg = require$$3;

  let Cipher = _cipher.exports;
  let CrowdNode = crowdnode.exports;
  let Dash = dash.exports;
  let Insight = insight.exports;
  let Prompt = _prompt.exports;
  let Qr = qr.exports;
  let Ws = ws.exports;

  let Dashcore = require$$0__default$1["default"];

  const DONE = "✅";
  const TODO = "ℹ️";
  const NO_SHADOW = "NONE";
  const DUFFS = 100000000;

  let shownDefault = false;
  let qrWidth = 2 + 33 + 2;
  // Sign Up Fees:
  //   0.00236608 // required for signup
  //   0.00002000 // TX fee estimate
  //   0.00238608 // minimum recommended amount
  // Target:
  //   0.01000000
  let signupOnly = CrowdNode.requests.signupForApi + CrowdNode.requests.offset;
  let acceptOnly = CrowdNode.requests.acceptTerms + CrowdNode.requests.offset;
  let signupFees = signupOnly + acceptOnly;
  let feeEstimate = 500;
  let signupTotal = signupFees + 2 * feeEstimate;

  //let paths = {};
  let configdir = `.config/crowdnode`;
  let keysDir = Path.join(HOME, `${configdir}/keys`);
  let keysDirRel = `~/${configdir}/keys`;
  let shadowPath = Path.join(HOME, `${configdir}/shadow`);
  let defaultWifPath = Path.join(HOME, `${configdir}/default`);

  function debug() {
    //@ts-ignore
    console.error.apply(console, arguments);
  }

  function showVersion() {
    console.info(`${pkg.name} v${pkg.version} - ${pkg.description}`);
    console.info();
  }

  function showHelp() {
    showVersion();

    console.info("Quick Start:");
    // technically this also has [--no-reserve]
    console.info("    crowdnode stake [addr-or-import-key | --create-new]");

    console.info("");
    console.info("Usage:");
    console.info("    crowdnode help");
    console.info("    crowdnode status [keyfile-or-addr]");
    console.info("    crowdnode signup [keyfile-or-addr]");
    console.info("    crowdnode accept [keyfile-or-addr]");
    console.info(
      "    crowdnode deposit [keyfile-or-addr] [dash-amount] [--no-reserve]",
    );
    console.info(
      "    crowdnode withdrawal [keyfile-or-addr] <percent> # 1.0-100.0 (steps by 0.1)",
    );
    console.info("");

    console.info("Helpful Extras:");
    console.info("    crowdnode balance [keyfile-or-addr]"); // addr
    console.info("    crowdnode load [keyfile-or-addr] [dash-amount]"); // addr
    console.info(
      "    crowdnode transfer <from-keyfile-or-addr> <to-keyfile-or-addr> [dash-amount]",
    ); // custom
    console.info("");

    console.info("Key Management & Encryption:");
    console.info("    crowdnode init");
    console.info("    crowdnode generate [--plain-text] [./privkey.wif]");
    console.info("    crowdnode encrypt"); // TODO allow encrypting one-by-one?
    console.info("    crowdnode list");
    console.info("    crowdnode use <addr>");
    console.info("    crowdnode import <keyfile>");
    //console.info("    crowdnode import <(dash-cli dumpprivkey <addr>)"); // TODO
    //console.info("    crowdnode export <addr> <keyfile>"); // TODO
    console.info("    crowdnode passphrase # set or change passphrase");
    console.info("    crowdnode decrypt"); // TODO allow decrypting one-by-one?
    console.info("    crowdnode delete <addr>");
    console.info("");

    console.info("CrowdNode HTTP RPC:");
    console.info("    crowdnode http FundsOpen <addr>");
    console.info("    crowdnode http VotingOpen <addr>");
    console.info("    crowdnode http GetFunds <addr>");
    console.info("    crowdnode http GetFundsFrom <addr> <seconds-since-epoch>");
    console.info("    crowdnode http GetBalance <addr>");
    console.info("    crowdnode http GetMessages <addr>");
    console.info("    crowdnode http IsAddressInUse <addr>");
    // TODO create signature rather than requiring it
    console.info("    crowdnode http SetEmail ./privkey.wif <email> <signature>");
    console.info("    crowdnode http Vote ./privkey.wif <gobject-hash> ");
    console.info("        <Yes|No|Abstain|Delegate|DoNothing> <signature>");
    console.info(
      "    crowdnode http SetReferral ./privkey.wif <referral-id> <signature>",
    );
    console.info("");
    console.info("Official CrowdNode Resources");
    console.info("");
    console.info("Homepage:");
    console.info("    https://crowdnode.io/");
    console.info("");
    console.info("Terms of Service:");
    console.info("    https://crowdnode.io/terms/");
    console.info("");
    console.info("BlockChain API Guide:");
    console.info(
      "    https://knowledge.crowdnode.io/en/articles/5963880-blockchain-api-guide",
    );
    console.info("");
  }

  let cmds = {};

  const button = document.getElementById("enter");

  button?.addEventListener("click", function () {
    main();
  });

  /**
   * @param {string} filePath
   */
  async function readFile(filePath) {
    return Fs.readFile(filePath, "utf8").catch(emptyStringOnErrEnoent);
  }

  /**
   * @param {string} filePath
   * @param {string} data
   */
  async function Fs.writeFile(filePath, data) {
    if (isBrowser) {
      const file = new File([data], filePath, { type: "text/plain" });
      const element = document.createElement("a");
      const url = URL.createObjectURL(file);
      element.href = url;
      //@ts-ignore
      element.download = file.name;

      element.style.display = "none";

      document.body.appendChild(element);

      element.click();
      document.body.removeChild(element);
      window.URL.revokeObjectURL(url);

      return Promise.resolve(true);
    }
    return Fs.Fs.writeFile(filePath, data, "utf8");
  }

  async function main() {
    /*jshint maxcomplexity:40 */
    /*jshint maxstatements:500 */

    // Usage:
    //    crowdnode <subcommand> [flags] <privkey> [options]
    // Example:
    //    crowdnode withdrawal ./Xxxxpubaddr.wif 100.0
    let args;
    if (isBrowser) {
      //@ts-ignore
      args = await document.getElementById("entry").value.slice(2);
    } else {
      args = process.argv.slice(2);
    }

    // flags
    let forceGenerate = removeItem(args, "--create-new");
    let forceConfirm = removeItem(args, "--unconfirmed");
    let plainText = removeItem(args, "--plain-text");
    let noReserve = removeItem(args, "--no-reserve");

    let subcommand = args.shift();

    if (!subcommand || ["--help", "-h", "help"].includes(subcommand)) {
      showHelp();
      process.exit(0);
      return;
    }

    if (["--version", "-V", "version"].includes(subcommand)) {
      showVersion();
      process.exit(0);
      return;
    }

    //
    //
    // find addr by name or by file or by string
    if (isBrowser) {
      await Fs.mkdir(keysDir, {
        recursive: true,
      });
    }

    let defaultAddr = await readFile(defaultWifPath);
    defaultAddr = defaultAddr.trim();

    let insightBaseUrl =
      process.env.INSIGHT_BASE_URL || "https://insight.dash.org";
    let insightApi = Insight.create({ baseUrl: insightBaseUrl });
    let dashApi = Dash.create({ insightApi: insightApi });

    if ("stake" === subcommand) {
      await stakeDash(
        {
          dashApi,
          insightApi,
          insightBaseUrl,
          defaultAddr,
          forceGenerate,
          noReserve,
        },
        args,
      );

      process.exit(0);
      return;
    }

    if ("list" === subcommand) {
      await listKeys({ dashApi, defaultAddr }, args);
      process.exit(0);
      return;
    }

    if ("init" === subcommand) {
      await initKeystore({ defaultAddr });
      process.exit(0);
      return;
    }

    if ("generate" === subcommand) {
      await generateKey({ defaultKey: defaultAddr, plainText }, args);
      process.exit(0);
      return;
    }

    if ("passphrase" === subcommand) {
      await setPassphrase({});
      process.exit(0);
      return;
    }

    if ("import" === subcommand) {
      let keypath = args.shift() || "";
      await importKey({ keypath });
      process.exit(0);
      return;
    }

    if ("encrypt" === subcommand) {
      let addr = args.shift() || "";
      if (!addr) {
        await encryptAll(null);

        process.exit(0);

        return;
      }

      let keypath = await findWif(addr);
      if (!keypath) {
        console.error(`no managed key matches '${addr}'`);

        process.exit(1);
        return;
      }
      let key = await maybeReadKeyFileRaw(keypath);
      if (!key) {
        throw new Error("impossible error");
      }
      await encryptAll([key]);
      process.exit(0);
      return;
    }

    if ("decrypt" === subcommand) {
      let addr = args.shift() || "";
      if (!addr) {
        await decryptAll(null);
        await Fs.writeFile(shadowPath, NO_SHADOW);

        process.exit(0);

        return;
      }
      let keypath = await findWif(addr);
      if (!keypath) {
        console.error(`no managed key matches '${addr}'`);
        process.exit(1);
        return;
      }
      let key = await maybeReadKeyFileRaw(keypath);
      if (!key) {
        throw new Error("impossible error");
      }
      await decryptAll([key]);
      process.exit(0);
      return;
    }

    // use or select or default... ?
    if ("use" === subcommand) {
      await setDefault(null, args);
      process.exit(0);
      return;
    }

    // helper for debugging
    if ("transfer" === subcommand) {
      await transferBalance(
        { dashApi, defaultAddr, forceConfirm, insightBaseUrl, insightApi },
        args,
      );
      process.exit(0);
      return;
    }

    let rpc = "";
    if ("http" === subcommand) {
      rpc = args.shift() || "";
      if (!rpc) {
        showHelp();
        process.exit(1);
        return;
      }

      let [addr] = await mustGetAddr({ defaultAddr }, args);

      await initCrowdNode(insightBaseUrl);
      // ex: http <rpc>(<pub>, ...)
      args.unshift(addr);
      let hasRpc = rpc in CrowdNode.http;
      if (!hasRpc) {
        console.error(`Unrecognized rpc command ${rpc}`);
        console.error();
        showHelp();
        process.exit(1);
      }
      //@ts-ignore - TODO use `switch` or make Record Type
      let result = await CrowdNode.http[rpc].apply(null, args);
      console.info(``);
      console.info(`${rpc} ${addr}:`);
      if ("string" === typeof result) {
        console.info(result);
      } else {
        console.info(JSON.stringify(result, null, 2));
      }
      process.exit(0);
      return;
    }

    if ("load" === subcommand) {
      await loadAddr({ defaultAddr, insightBaseUrl }, args);
      process.exit(0);
      return;
    }

    // keeping rm for backwards compat
    if ("rm" === subcommand || "delete" === subcommand) {
      await initCrowdNode(insightBaseUrl);
      let [addr, filepath] = await mustGetAddr({ defaultAddr }, args);
      await removeKey({ addr, dashApi, filepath, insightBaseUrl });
      process.exit(0);
      return;
    }

    if ("balance" === subcommand) {
      if (args.length) {
        await getBalance({ dashApi, defaultAddr }, args);
        if (!isBrowser) {
          process.exit(0);
        }
        return;
      }

      await getAllBalances({ dashApi, defaultAddr }, args);
      process.exit(0);
      return;
    }

    if ("status" === subcommand) {
      await getStatus({ dashApi, defaultAddr, insightBaseUrl }, args);
      process.exit(0);
      return;
    }

    if ("signup" === subcommand) {
      await sendSignup({ dashApi, defaultAddr, insightBaseUrl }, args);
      process.exit(0);
      return;
    }

    if ("accept" === subcommand) {
      await acceptTerms({ dashApi, defaultAddr, insightBaseUrl }, args);
      process.exit(0);
      return;
    }

    if ("deposit" === subcommand) {
      await depositDash(
        { dashApi, defaultAddr, insightBaseUrl, noReserve },
        args,
      );
      process.exit(0);
      return;
    }

    if ("withdrawal" === subcommand) {
      await withdrawalDash({ dashApi, defaultAddr, insightBaseUrl }, args);
      process.exit(0);
      return;
    }

    console.error(`Unrecognized subcommand ${subcommand}`);
    console.error();
    showHelp();

    process.exit(1);
  }

  /**
   * @param {Object} opts
   * @param {any} opts.dashApi - TODO
   * @param {String} opts.defaultAddr
   * @param {Boolean} opts.forceGenerate
   * @param {String} opts.insightBaseUrl
   * @param {any} opts.insightApi
   * @param {Boolean} opts.noReserve
   * @param {Array<String>} args
   */
  async function stakeDash(
    {
      dashApi,
      defaultAddr,
      forceGenerate,
      insightApi,
      insightBaseUrl,
      noReserve,
    },
    args,
  ) {
    let err;
    if (!isBrowser) {
      err = await Fs.access(args[0]).catch(Object);
    }
    let addr;
    if (!err) {
      let keypath = args.shift() || "";
      addr = await importKey({ keypath });
    } else if (forceGenerate) {
      addr = await generateKey({ defaultKey: defaultAddr }, []);
    } else {
      addr = await initKeystore({ defaultAddr });
    }

    if (!addr) {
      let [_addr] = await mustGetAddr({ defaultAddr }, args);
      addr = _addr;
    }

    let extra = feeEstimate;
    console.info("Checking CrowdNode account... ");
    await CrowdNode.init({
      baseUrl: "https://app.crowdnode.io",
      insightBaseUrl,
    });
    let hotwallet = CrowdNode.main.hotwallet;
    let state = await getCrowdNodeStatus({ addr, hotwallet });

    if (!state.status?.accept) {
      if (!state.status?.signup) {
        let signUpDeposit = signupOnly + feeEstimate;
        console.info(
          `    ${TODO} SignUpForApi deposit is ${signupOnly} (+ tx fee)`,
        );
        extra += signUpDeposit;
      } else {
        console.info(`    ${DONE} SignUpForApi complete`);
      }
      let acceptDeposit = acceptOnly + feeEstimate;
      console.info(`    ${TODO} AcceptTerms deposit is ${acceptOnly} (+ tx fee)`);
      extra += acceptDeposit;
    }

    let desiredAmountDash = args.shift() || "0.5";
    let effectiveDuff = toDuff(desiredAmountDash);
    effectiveDuff += extra;

    let balanceInfo = await dashApi.getInstantBalance(addr);
    effectiveDuff -= balanceInfo.balanceSat;

    if (effectiveDuff > 0) {
      effectiveDuff = roundDuff(effectiveDuff, 3);
      let effectiveDash = toDash(effectiveDuff);
      await plainLoadAddr({
        addr,
        effectiveDash,
        effectiveDuff,
        insightBaseUrl,
      });
    }

    if (!state.status?.accept) {
      if (!state.status?.signup) {
        await sendSignup({ dashApi, defaultAddr: addr, insightBaseUrl }, [addr]);
      }
      await acceptTerms({ dashApi, defaultAddr: addr, insightBaseUrl }, [addr]);
    }

    await depositDash(
      { dashApi, defaultAddr: addr, insightBaseUrl, noReserve },
      [addr].concat(args),
    );
  }

  /**
   * @param {Object} opts
   * @param {String} opts.defaultAddr
   */
  async function initKeystore({ defaultAddr }) {
    // if we have no keys, make one
    let wifnames = await listManagedKeynames();
    if (!wifnames.length) {
      return await generateKey({ defaultKey: defaultAddr }, []);
    }
    // if we have no passphrase, ask about it
    await initPassphrase();
    return defaultAddr || wifnames[0];
  }

  /**
   * @param {String} insightBaseUrl
   */
  async function initCrowdNode(insightBaseUrl) {
    if (CrowdNode.main.hotwallet) {
      return;
    }
    process.stdout.write("Checking CrowdNode API... ");
    await CrowdNode.init({
      baseUrl: "https://app.crowdnode.io",
      insightBaseUrl,
    });
    console.info(`(hotwallet ${CrowdNode.main.hotwallet})`);
  }

  /**
   * @param {String} addr - Base58Check pubKeyHash address
   * @param {Number} duffs - 1/100000000 of a DASH
   */
  function showQr(addr, duffs = 0) {
    let dashAmount = toDash(duffs);
    let dashUri = `dash://${addr}`;
    if (duffs) {
      dashUri += `?amount=${dashAmount}`;
    }

    let dashQr = Qr.ascii(dashUri, { indent: 4, size: "mini" });
    let addrPad = Math.max(0, Math.ceil((qrWidth - dashUri.length) / 2));

    console.info(dashQr);
    console.info();
    console.info(" ".repeat(addrPad) + dashUri);
  }

  /**
   * @param {Array<any>} arr
   * @param {any} item
   */
  function removeItem(arr, item) {
    let index = arr.indexOf(item);
    if (index >= 0) {
      return arr.splice(index, 1)[0];
    }
    return null;
  }

  /**
   * @param {Object} opts
   * @param {String} opts.addr
   * @param {String} opts.hotwallet
   */
  async function getCrowdNodeStatus({ addr, hotwallet }) {
    let state = {
      signup: TODO,
      accept: TODO,
      deposit: TODO,
      status: {
        signup: 0,
        accept: 0,
        deposit: 0,
      },
    };

    //@ts-ignore - TODO why warnings?
    let status = await CrowdNode.status(addr, hotwallet);
    if (status) {
      state.status = status;
    }
    if (state.status?.signup) {
      state.signup = DONE;
    }
    if (state.status?.accept) {
      state.accept = DONE;
    }
    if (state.status?.deposit) {
      state.deposit = DONE;
    }
    return state;
  }

  /**
   * @param {Object} opts
   * @param {String} opts.addr
   * @param {any} opts.dashApi - TODO
   */
  async function checkBalance({ addr, dashApi }) {
    // deposit if balance is over 100,000 (0.00100000)
    console.info("Checking balance... ");
    let balanceInfo = await dashApi.getInstantBalance(addr);
    let balanceDASH = toDASH(balanceInfo.balanceSat);

    let crowdNodeBalance = await CrowdNode.http.GetBalance(addr);
    if (!crowdNodeBalance.TotalBalance) {
      crowdNodeBalance.TotalBalance = 0;
      crowdNodeBalance.TotalDividend = 0;
    }

    let crowdNodeDuffNum = toDuff(crowdNodeBalance.TotalBalance);
    let crowdNodeDASH = toDASH(crowdNodeDuffNum);

    let crowdNodeDivNum = toDuff(crowdNodeBalance.TotalDividend);
    let crowdNodeDASHDiv = toDASH(crowdNodeDivNum);

    console.info(`Key:       ${balanceDASH}`);
    console.info(`CrowdNode: ${crowdNodeDASH}`);
    console.info(`Dividends: ${crowdNodeDASHDiv}`);
    console.info();
    /*
    let balanceInfo = await insightApi.getBalance(pub);
    if (balanceInfo.unconfirmedBalanceSat || balanceInfo.unconfirmedAppearances) {
      if (!forceConfirm) {
        console.error(
          `Error: This address has pending transactions. Please try again in 1-2 minutes or use --unconfirmed.`,
        );
        console.error(balanceInfo);
        if ("status" !== subcommand) {
          if(!isBrowser) {
          process.exit(1);
          }
          return;
        }
      }
    }
    */
    return balanceInfo;
  }

  /**
   * @param {Object} opts
   * @param {String} opts.defaultAddr
   * @param {Array<String>} args
   * @returns {Promise<[String, String]>}
   */
  async function mustGetAddr({ defaultAddr }, args) {
    let name = args.shift() ?? "";
    if (34 === name.length) {
      // looks like addr already
      // TODO make function for addr-lookin' check
      return [name, name];
    }

    let addr = await maybeReadKeyPaths(name, { wif: false });
    if (addr) {
      if (34 === addr.length) {
        return [addr, name];
      }
      //let pk = new Dashcore.PrivateKey(wif);
      //let addr = pk.toAddress().toString();
      return [addr, name];
    }

    let isNum = !isNaN(parseFloat(name));
    if (isNum) {
      args.unshift(name);
      name = "";
    }

    if (name) {
      console.error();
      console.error(`could not read '${name}' in ./ or match in ${keysDirRel}/.`);
      console.error();
      process.exit(1);
      return ["", name];
    }

    addr = await mustGetDefaultWif(defaultAddr, { wif: false });

    // TODO we don't need defaultAddr, right? because it could be old?
    return [addr, addr];
  }

  /**
   * @param {Object} opts
   * @param {String} opts.defaultAddr
   * @param {Array<String>} args
   */
  async function mustGetWif({ defaultAddr }, args) {
    let name = args.shift() ?? "";

    let wif = await maybeReadKeyPaths(name, { wif: true });
    if (wif) {
      return wif;
    }

    let isNum = !isNaN(parseFloat(name));
    if (isNum) {
      args.unshift(name);
      name = "";
    }

    if (name) {
      console.error();
      console.error(
        `'${name}' does not match a staking key in ./ or ${keysDirRel}/`,
      );
      console.error();
      process.exit(1);
      return "";
    }

    wif = await mustGetDefaultWif(defaultAddr);

    return wif;
  }

  /**
   * @param {String} name
   * @param {Object} opts
   * @param {Boolean} opts.wif
   * @returns {Promise<String>} - wif
   */
  async function maybeReadKeyPaths(name, opts) {
    let privKey = "";

    // prefix match in .../keys/
    let wifname = await findWif(name);
    if (!wifname) {
      return "";
    }

    if (false === opts.wif) {
      return wifname.slice(0, -".wif".length);
    }

    let filepath = Path.join(keysDir, wifname);
    privKey = await maybeReadKeyFile(filepath);
    if (!privKey) {
      // local in ./
      privKey = await maybeReadKeyFile(name);
    }

    return privKey;
  }

  /**
   * @param {String} defaultAddr
   * @param {Object} [opts]
   * @param {Boolean} opts.wif
   */
  async function mustGetDefaultWif(defaultAddr, opts) {
    let defaultWif = "";
    if (defaultAddr) {
      let keyfile = Path.join(keysDir, `${defaultAddr}.wif`);
      let raw = await maybeReadKeyFileRaw(keyfile, opts);
      // misnomering wif here a bit
      defaultWif = raw?.wif || raw?.addr || "";
    }
    if (defaultWif && !shownDefault) {
      shownDefault = true;
      debug(`Selected default staking key ${defaultAddr}`);
      return defaultWif;
    }

    console.error();
    console.error(`Error: no default staking key selected.`);
    console.error();
    console.error(`Select a different address:`);
    console.error(`    crowdnode list`);
    console.error(`    crowdnode use <addr>`);
    console.error(``);
    console.error(`Or create a new staking key:`);
    console.error(`    crowdnode generate`);
    console.error();

    process.exit(1);

    return "";
  }

  // Subcommands

  /**
   * @param {Object} psuedoState
   * @param {String} psuedoState.defaultKey - addr name of default key
   * @param {Boolean} [psuedoState.plainText] - don't encrypt
   * @param {Array<String>} args
   */
  async function generateKey({ defaultKey, plainText }, args) {
    let name = args.shift();
    //@ts-ignore - TODO submit JSDoc PR for Dashcore
    let pk = new Dashcore.PrivateKey();

    let addr = pk.toAddress().toString();
    let plainWif = pk.toWIF();

    let wif = plainWif;
    if (!plainText) {
      wif = await maybeEncrypt(plainWif);
    }

    let filename = `~/${configdir}/keys/${addr}.wif`;
    let filepath = Path.join(`${keysDir}/${addr}.wif`);
    let note = "";
    if (name) {
      filename = name;
      filepath = name;
      note = `\n(for pubkey address ${addr})`;
      let err = await Fs.access(filepath).catch(Object);
      if (!err) {
        // TODO
        console.info(`'${filepath}' already exists (will not overwrite)`);
        if (!isBrowser) {
          process.exit(0);
        }
        return;
      }
    }

    await Fs.writeFile(filename, wif);
    if (!name && !defaultKey) {
      await Fs.writeFile(defaultWifPath, addr);
    }

    console.info(``);
    console.info(`Generated ${filename} ${note}`);
    console.info(``);
    return addr;
  }

  async function initPassphrase() {
    let needsInit = false;
    let shadow = await readFile(shadowPath);
    if (!shadow) {
      needsInit = true;
    }
    if (needsInit) {
      await cmds.getPassphrase({}, []);
    }
  }

  /**
   * @param {Object} state
   * @param {Boolean} [state._askPreviousPassphrase] - don't ask for passphrase again
   * @param {Array<String>} args
   */
  async function setPassphrase({ _askPreviousPassphrase }, args) {
    let result = {
      passphrase: "",
      changed: false,
    };
    let date = getFsDateString();

    // get the old passphrase
    if (false !== _askPreviousPassphrase) {
      // TODO should contain the shadow?
      await cmds.getPassphrase({ _rotatePassphrase: true }, []);
    }

    // get the new passphrase
    let newPassphrase = await promptPassphrase();
    let curShadow = await readFile(shadowPath);

    let newShadow = await Cipher.shadowPassphrase(newPassphrase);
    await Fs.writeFile(shadowPath, newShadow);

    let rawKeys = await readAllKeys();
    let encAddrs = rawKeys
      .map(function (raw) {
        if (raw.encrypted) {
          return raw.addr;
        }
      })
      .filter(Boolean);

    // backup all currently encrypted files
    //@ts-ignore
    if (encAddrs.length) {
      let filepath = Path.join(HOME, `${configdir}/keys.${date}.bak`);
      console.info(``);
      console.info(`Backing up previous (encrypted) keys:`);
      encAddrs.unshift(`SHADOW:${curShadow}`);
      await Fs.writeFile(filepath, encAddrs.join("\n") + "\n");
      console.info(`  ~/${configdir}/keys.${date}.bak`);
      console.info(``);
    }
    cmds._setPassphrase(newPassphrase);

    await encryptAll(rawKeys, { rotateKey: true });

    result.passphrase = newPassphrase;
    result.changed = true;
    return result;
  }

  async function promptPassphrase() {
    let newPassphrase;
    for (;;) {
      newPassphrase = await Prompt.prompt("Enter (new) passphrase: ", {
        mask: true,
      });
      newPassphrase = newPassphrase.trim();

      let _newPassphrase = await Prompt.prompt("Enter passphrase again: ", {
        mask: true,
      });
      _newPassphrase = _newPassphrase.trim();

      let match = Cipher.secureCompare(newPassphrase, _newPassphrase);
      if (match) {
        break;
      }

      console.error("passphrases do not match");
    }
    return newPassphrase;
  }

  /**
   * Import and Encrypt
   * @param {Object} opts
   * @param {String} opts.keypath
   */
  async function importKey({ keypath }) {
    let key = await maybeReadKeyFileRaw(keypath);
    if (!key?.wif) {
      console.error(`no key found for '${keypath}'`);

      process.exit(1);

      return;
    }

    let encWif = await maybeEncrypt(key.wif);
    let icon = "💾";
    if (encWif.includes(":")) {
      icon = "🔐";
    }
    let date = getFsDateString();

    await safeSave(
      Path.join(keysDir, `${key.addr}.wif`),
      encWif,
      Path.join(keysDir, `${key.addr}.${date}.bak`),
    );

    console.info(`${icon} Imported ${keysDirRel}/${key.addr}.wif`);
    console.info(``);

    return key.addr;
  }

  /**
   * @param {Object} opts
   * @param {Boolean} [opts._rotatePassphrase]
   * @param {Boolean} [opts._force]
   * @param {Array<String>} args
   */
  cmds.getPassphrase = async function ({ _rotatePassphrase, _force }, args) {
    let result = {
      passphrase: "",
      changed: false,
    };
    /*
    if (!_rotatePassphrase) {
      let cachedphrase = cmds._getPassphrase();
      if (cachedphrase) {
        return cachedphrase;
      }
    }
    */

    // Three possible states:
    //   1. no shadow file yet (ask to set one)
    //   2. empty shadow file (initialized, but not set - don't ask to set one)
    //   3. encrypted shadow file (initialized, requires passphrase)
    let needsInit = false;
    let shadow = await readFile(shadowPath);
    if (!shadow) {
      needsInit = true;
    } else if (NO_SHADOW === shadow && _force) {
      needsInit = true;
    }

    // State 1: not initialized, what does the user want?
    if (needsInit) {
      for (;;) {
        let no;
        if (!_force) {
          no = await Prompt.prompt(
            "Would you like to set an encryption passphrase? [Y/n]: ",
          );
        }

        // Set a passphrase and create shadow file
        if (!no || ["yes", "y"].includes(no.toLowerCase())) {
          result = await setPassphrase({ _askPreviousPassphrase: false });
          cmds._setPassphrase(result.passphrase);
          return result;
        }

        // ask user again
        if (!["no", "n"].includes(no.toLowerCase())) {
          continue;
        }

        // No passphrase, create a NONE shadow file
        await Fs.writeFile(shadowPath, NO_SHADOW);
        return result;
      }
    }

    // State 2: shadow already initialized to empty
    // (user doesn't want a passphrase)
    if (!shadow) {
      cmds._setPassphrase("");
      return result;
    }

    // State 3: passphrase & shadow already in use
    for (;;) {
      let prompt = `Enter passphrase: `;
      if (_rotatePassphrase) {
        prompt = `Enter (current) passphrase: `;
      }
      result.passphrase = await Prompt.prompt(prompt, {
        mask: true,
      });
      result.passphrase = result.passphrase.trim();
      if (!result.passphrase || "q" === result.passphrase) {
        console.error("cancel: no passphrase");
        process.exit(1);
        return result;
      }

      let match = await Cipher.checkPassphrase(result.passphrase, shadow);
      if (match) {
        cmds._setPassphrase(result.passphrase);
        console.info(``);
        return result;
      }

      console.error("incorrect passphrase");
    }

    throw new Error("SANITY FAIL: unreachable return");
  };

  cmds._getPassphrase = function () {
    return "";
  };

  /**
   * @param {String} passphrase
   */
  cmds._setPassphrase = function (passphrase) {
    // Look Ma! A private variable!
    cmds._getPassphrase = function () {
      return passphrase;
    };
  };

  /**
   * Encrypt ALL-the-things!
   * @param {Object} [opts]
   * @param {Boolean} opts.rotateKey
   * @param {Array<RawKey>?} rawKeys
   */
  async function encryptAll(rawKeys, opts) {
    if (!rawKeys) {
      rawKeys = await readAllKeys();
    }
    let date = getFsDateString();

    let passphrase = cmds._getPassphrase();
    if (!passphrase) {
      let result = await cmds.getPassphrase({ _force: true }, []);
      if (result.changed) {
        // encryptAll was already called on rotation
        return;
      }
      passphrase = result.passphrase;
    }

    console.info(`Encrypting...`);
    console.info(``);
    await rawKeys.reduce(async function (promise, key) {
      await promise;

      if (key.encrypted && !opts?.rotateKey) {
        console.info(`🙈 ${key.addr} [already encrypted]`);
        return;
      }
      let encWif = await maybeEncrypt(key.wif, { force: true });
      await safeSave(
        Path.join(keysDir, `${key.addr}.wif`),
        encWif,
        Path.join(keysDir, `${key.addr}.${date}.bak`),
      );
      console.info(`🔑 ${key.addr}`);
    }, Promise.resolve());
    console.info(``);
    console.info(`Done 🔐`);
    console.info(``);
  }

  /**
   * Decrypt ALL-the-things!
   * @param {Array<RawKey>?} rawKeys
   */
  async function decryptAll(rawKeys) {
    if (!rawKeys) {
      rawKeys = await readAllKeys();
    }
    let date = getFsDateString();

    console.info(``);
    console.info(`Decrypting...`);
    console.info(``);
    await rawKeys.reduce(async function (promise, key) {
      await promise;

      if (!key.encrypted) {
        console.info(`📖 ${key.addr} [already decrypted]`);
        return;
      }
      await safeSave(
        Path.join(keysDir, `${key.addr}.wif`),
        key.wif,
        Path.join(keysDir, `${key.addr}.${date}.bak`),
      );
      console.info(`🔓 ${key.addr}`);
    }, Promise.resolve());
    console.info(``);
    console.info(`Done ${DONE}`);
    console.info(``);
  }

  function getFsDateString() {
    // YYYY-MM-DD_hh-mm_ss
    let date = new Date()
      .toISOString()
      .replace(/:/g, ".")
      .replace(/T/, "_")
      .replace(/\.\d{3}.*/, "");
    return date;
  }

  /**
   * @param {String} filepath
   * @param {String} wif
   * @param {String} bakpath
   */
  async function safeSave(filepath, wif, bakpath) {
    let tmpPath = `${bakpath}.tmp`;
    await Fs.writeFile(tmpPath, wif);
    if (!isBrowser) {
      let err = await Fs.access(filepath).catch(Object);
      if (!err) {
        await Fs.rename(filepath, bakpath);
      }
      await Fs.rename(tmpPath, filepath);
      if (!err) {
        await Fs.unlink(bakpath);
      }
    }
  }

  /**
   * @typedef {Object} RawKey
   * @property {String} addr
   * @property {Boolean} encrypted
   * @property {String} wif
   */

  /**
   * @throws
   */
  async function readAllKeys() {
    let wifnames = await listManagedKeynames();

    /** @type Array<RawKey> */
    let keys = [];
    await wifnames.reduce(async function (promise, wifname) {
      await promise;

      let keypath = Path.join(keysDir, wifname);
      let key = await maybeReadKeyFileRaw(keypath);
      if (!key?.wif) {
        return;
      }

      if (`${key.addr}.wif` !== wifname) {
        throw new Error(
          `computed pubkey '${key.addr}' of WIF does not match filename '${keypath}'`,
        );
      }

      keys.push(key);
    }, Promise.resolve());

    return keys;
  }

  /**
   * @param {String} filepath
   * @param {Object} [opts]
   * @param {Boolean} opts.wif
   * @returns {Promise<String>}
   */
  async function maybeReadKeyFile(filepath, opts) {
    let key = await maybeReadKeyFileRaw(filepath, opts);
    if (false === opts?.wif) {
      return key?.addr || "";
    }
    return key?.wif || "";
  }

  /**
   * @param {String} filepath
   * @param {Object} [opts]
   * @param {Boolean} opts.wif
   * @returns {Promise<RawKey?>}
   */
  async function maybeReadKeyFileRaw(filepath, opts) {
    let privKey = await readFile(filepath);
    privKey = privKey.trim();
    if (!privKey) {
      return null;
    }

    let encrypted = false;
    if (privKey.includes(":")) {
      encrypted = true;
      try {
        if (false !== opts?.wif) {
          privKey = await decrypt(privKey);
        }
      } catch (err) {
        //@ts-ignore
        console.error(err.message);
        console.error(`passphrase does not match for key ${filepath}`);
        process.exit(1);
      }
    }
    if (false === opts?.wif) {
      return {
        addr: Path.basename(filepath, ".wif"),
        encrypted: encrypted,
        wif: "",
      };
    }

    let pk = new Dashcore.PrivateKey(privKey);
    let pub = pk.toAddress().toString();

    return {
      addr: pub,
      encrypted: encrypted,
      wif: privKey,
    };
  }

  /**
   * @param {String} encWif
   */
  async function decrypt(encWif) {
    let passphrase = cmds._getPassphrase();
    if (!passphrase) {
      let result = await cmds.getPassphrase({}, []);
      passphrase = result.passphrase;
      // we don't return just in case they're setting a passphrase to
      // decrypt a previously encrypted file (i.e. for recovery from elsewhere)
    }
    let key128 = await Cipher.deriveKey(passphrase);
    let cipher = Cipher.create(key128);

    return cipher.decrypt(encWif);
  }

  // tuple example {Promise<[String, Boolean]>}
  /**
   * @param {Object} [opts]
   * @param {Boolean} [opts.force]
   * @param {String} plainWif
   */
  async function maybeEncrypt(plainWif, opts) {
    let passphrase = cmds._getPassphrase();
    if (!passphrase) {
      let result = await cmds.getPassphrase({}, []);
      passphrase = result.passphrase;
    }
    if (!passphrase) {
      if (opts?.force) {
        throw new Error(`no passphrase with which to encrypt file`);
      }
      return plainWif;
    }

    let key128 = await Cipher.deriveKey(passphrase);
    let cipher = Cipher.create(key128);
    return cipher.encrypt(plainWif);
  }

  /**
   * @param {Null} _
   * @param {Array<String>} args
   */
  async function setDefault(_, args) {
    let addr = args.shift() || "";

    let keyname = await findWif(addr);
    if (!keyname) {
      console.error(`no key matches '${addr}'`);
      process.exit(1);
      return;
    }

    let filepath = Path.join(keysDir, keyname);
    let wif = await maybeReadKeyFile(filepath);
    let pk = new Dashcore.PrivateKey(wif);
    let pub = pk.toAddress().toString();

    console.info("set", defaultWifPath, pub);
    await Fs.writeFile(defaultWifPath, pub);
  }

  // TODO option to specify config dir

  /**
   * @param {Object} opts
   * @param {any} opts.dashApi - TODO
   * @param {String} opts.defaultAddr
   * @param {Array<String>} args
   */
  async function listKeys({ dashApi, defaultAddr }, args) {
    let wifnames = await listManagedKeynames();

    if (wifnames) {
      // to print 'default staking key' message
      await mustGetAddr({ defaultAddr }, args);
    }

    /**
     * @type Array<{ node: String, error: Error }>
     */
    let warns = [];
    // console.error because console.debug goes to stdout, not stderr
    debug(``);
    debug(`Staking keys: (in ${keysDirRel}/)`);
    debug(``);

    await wifnames.reduce(async function (promise, wifname) {
      await promise;

      let wifpath = Path.join(keysDir, wifname);
      let addr = await maybeReadKeyFile(wifpath, { wif: false }).catch(function (
        err,
      ) {
        warns.push({ node: wifname, error: err });
        return "";
      });
      if (!addr) {
        return;
      }

      console.info(`${addr}`);
    }, Promise.resolve());
    debug(``);

    if (warns.length) {
      console.warn(`Warnings:`);
      warns.forEach(function (warn) {
        console.warn(`${warn.node}: ${warn.error.message}`);
      });
      console.warn(``);
    }
  }

  /**
   * @param {Object} opts
   * @param {any} opts.dashApi - TODO
   * @param {String} opts.defaultAddr
   * @param {Array<String>} args
   */
  async function getAllBalances({ dashApi, defaultAddr }, args) {
    let wifnames = await listManagedKeynames();
    let totals = {
      key: 0,
      stake: 0,
      dividend: 0,
      keyDash: "",
      stakeDash: "",
      dividendDash: "",
    };

    if (wifnames.length) {
      // to print 'default staking key' message
      await mustGetAddr({ defaultAddr }, args);
    }

    /**
     * @type Array<{ node: String, error: Error }>
     */
    let warns = [];
    // console.error because console.debug goes to stdout, not stderr
    debug(``);
    debug(`Staking keys: (in ${keysDirRel}/)`);
    debug(``);
    console.info(
      `|                                    |   🔑 Holdings |   🪧  Stakings |   💸 Earnings |`,
    );
    console.info(
      `| ---------------------------------: | ------------: | ------------: | ------------: |`,
    );
    if (!wifnames.length) {
      console.info(`    (none)`);
    }
    await wifnames.reduce(async function (promise, wifname) {
      await promise;

      let wifpath = Path.join(keysDir, wifname);
      let addr = await maybeReadKeyFile(wifpath, { wif: false }).catch(function (
        err,
      ) {
        warns.push({ node: wifname, error: err });
        return "";
      });
      if (!addr) {
        return;
      }

      /*
      let pk = new Dashcore.PrivateKey(wif);
      let pub = pk.toAddress().toString();
      if (`${pub}.wif` !== wifname) {
        // sanity check
        warns.push({
          node: wifname,
          error: new Error(
            `computed pubkey '${pub}' of WIF does not match filename '${wifname}'`,
          ),
        });
        return;
      }
      */

      process.stdout.write(`| ${addr} |`);

      let balanceInfo = await dashApi.getInstantBalance(addr);
      let balanceDASH = toDASH(balanceInfo.balanceSat);

      let crowdNodeBalance = await CrowdNode.http.GetBalance(addr);
      if (!crowdNodeBalance.TotalBalance) {
        crowdNodeBalance.TotalBalance = 0;
        crowdNodeBalance.TotalDividend = 0;
      }
      let crowdNodeDuffNum = toDuff(crowdNodeBalance.TotalBalance);
      let crowdNodeDASH = toDASH(crowdNodeDuffNum);

      let crowdNodeDivNum = toDuff(crowdNodeBalance.TotalDividend);
      let crowdNodeDivDASH = toDASH(crowdNodeDivNum);
      process.stdout.write(
        ` ${balanceDASH} | ${crowdNodeDASH} | ${crowdNodeDivDASH} |`,
      );

      totals.key += balanceInfo.balanceSat;
      totals.dividend += crowdNodeBalance.TotalDividend;
      totals.stake += crowdNodeBalance.TotalBalance;

      console.info();
    }, Promise.resolve());
    console.info(
      `|                                    |               |               |               |`,
    );
    let total = `|                             Totals`;
    totals.keyDash = toDASH(toDuff(totals.key.toString()));
    totals.stakeDash = toDASH(toDuff(totals.stake.toString()));
    totals.dividendDash = toDASH(toDuff(totals.dividend.toString()));
    console.info(
      `${total} | ${totals.stakeDash} | ${totals.stakeDash} | ${totals.dividendDash} |`,
    );
    debug(``);

    if (warns.length) {
      console.warn(`Warnings:`);
      warns.forEach(function (warn) {
        console.warn(`${warn.node}: ${warn.error.message}`);
      });
      console.warn(``);
    }
  }

  /**
   * @param {String} name - ex: Xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.wif.enc
   */
  function isNamedLikeKey(name) {
    // TODO distinguish with .enc extension?
    let hasGoodLength = 34 + 4 === name.length || 34 + 4 + 4 === name.length;
    let knownExt = name.endsWith(".wif") || name.endsWith(".wif.enc");
    let isTmp = name.startsWith(".") || name.startsWith("_");
    return hasGoodLength && knownExt && !isTmp;
  }

  /**
   * @param {Object} opts
   * @param {any} opts.dashApi - TODO
   * @param {String} opts.addr
   * @param {String} opts.filepath
   * @param {String} opts.insightBaseUrl
   * @param {Array<String>} args
   */
  async function removeKey({ addr, dashApi, filepath, insightBaseUrl }, args) {
    let balanceInfo = await dashApi.getInstantBalance(addr);

    let balanceDash = toDash(balanceInfo.balanceSat);
    if (balanceInfo.balanceSat) {
      console.error(``);
      console.error(`Error: ${addr}`);
      console.error(
        `    still has a balance of ${balanceInfo.balanceSat} (Đ${balanceDash})`,
      );
      console.error(`    (transfer to another address before deleting)`);
      console.error(``);
      process.exit(1);
      return;
    }

    await initCrowdNode(insightBaseUrl);
    let crowdNodeBalance = await CrowdNode.http.GetBalance(addr);
    if (!crowdNodeBalance) {
      // may be janky if not registered
      crowdNodeBalance = {};
    }
    if (!crowdNodeBalance.TotalBalance) {
      crowdNodeBalance.TotalBalance = 0;
    }
    let crowdNodeDash = toDash(crowdNodeBalance.TotalBalance);
    if (crowdNodeBalance.TotalBalance) {
      console.error(``);
      console.error(`Error: ${addr}`);
      console.error(
        `    still staking ${crowdNodeBalance.TotalBalance} (Đ${crowdNodeDash}) on CrowdNode`,
      );
      console.error(
        `    (withdrawal 100.0 and transfer to another address before deleting)`,
      );
      console.error(``);
      process.exit(1);
      return;
    }

    let wifname = await findWif(addr);
    let fullpath = Path.join(keysDir, wifname);
    let wif = await maybeReadKeyPaths(filepath, { wif: true });
    if (!isBrowser) {
      await Fs.unlink(fullpath).catch(function (err) {
        console.error(`could not remove ${filepath}: ${err.message}`);
        process.exit(1);
      });
    }

    let wifnames = await listManagedKeynames();
    console.info(``);
    console.info(`No balances found. Removing ${filepath}.`);
    console.info(``);
    console.info(`Backup (just in case):`);
    console.info(`    ${wif}`);
    console.info(``);
    if (!wifnames.length) {
      console.info(`No keys left.`);
      console.info(``);
    } else {
      let newAddr = wifnames[0];
      debug(`Selected ${newAddr} as new default staking key.`);
      await Fs.writeFile(defaultWifPath, addr.replace(".wif", ""));
      console.info(``);
    }
  }

  /**
   * @param {String} pre
   */
  async function findWif(pre) {
    if (!pre) {
      return "";
    }

    let names = await listManagedKeynames();
    names = names.filter(function (name) {
      return name.startsWith(pre);
    });

    if (!names.length) {
      return "";
    }

    if (names.length > 1) {
      console.error(`'${pre}' is ambiguous:`, names.join(", "));

      process.exit(1);

      return "";
    }

    return names[0];
  }

  async function listManagedKeynames() {
    if (!isBrowser) {
      let nodes = await Fs.readdir(keysDir);

      return nodes.filter(isNamedLikeKey);
    }
    return Promise.resolve([""]);
  }

  /**
   * @param {Object} opts
   * @param {String} opts.defaultAddr
   * @param {String} opts.insightBaseUrl
   * @param {Array<String>} args
   */
  async function loadAddr({ defaultAddr, insightBaseUrl }, args) {
    let [addr] = await mustGetAddr({ defaultAddr }, args);

    let desiredAmountDash = parseFloat(args.shift() || "0");
    let desiredAmountDuff = Math.round(desiredAmountDash * DUFFS);

    let effectiveDuff = desiredAmountDuff;
    let effectiveDash = "";
    if (!effectiveDuff) {
      effectiveDuff = CrowdNode.stakeMinimum + signupTotal + feeEstimate;
      effectiveDuff = roundDuff(effectiveDuff, 3);
      effectiveDash = toDash(effectiveDuff);
    }

    await plainLoadAddr({ addr, effectiveDash, effectiveDuff, insightBaseUrl });

    return;
  }

  /**
   * 1000 to Round to the nearest mDash
   * ex: 0.50238108 => 0.50300000
   * @param {Number} effectiveDuff
   * @param {Number} numDigits
   */
  function roundDuff(effectiveDuff, numDigits) {
    let n = Math.pow(10, numDigits);
    let effectiveDash = toDash(effectiveDuff);
    effectiveDuff = toDuff(
      (Math.ceil(parseFloat(effectiveDash) * n) / n).toString(),
    );
    return effectiveDuff;
  }

  /**
   * @param {Object} opts
   * @param {String} opts.addr
   * @param {String} opts.effectiveDash
   * @param {Number} opts.effectiveDuff
   * @param {String} opts.insightBaseUrl
   */
  async function plainLoadAddr({
    addr,
    effectiveDash,
    effectiveDuff,
    insightBaseUrl,
  }) {
    console.info(``);
    showQr(addr, effectiveDuff);
    console.info(``);
    console.info(
      `Use the QR Code above to load ${effectiveDuff} (Đ${effectiveDash}) onto your staking key.`,
    );
    console.info(``);
    console.info(`(waiting...)`);
    console.info(``);
    let payment = await Ws.waitForVout(insightBaseUrl, addr, 0);
    console.info(`Received ${payment.satoshis}`);
  }

  /**
   * @param {Object} opts
   * @param {String} opts.defaultAddr
   * @param {any} opts.dashApi - TODO
   * @param {Array<String>} args
   */
  async function getBalance({ dashApi, defaultAddr }, args) {
    let [addr] = await mustGetAddr({ defaultAddr }, args);
    await checkBalance({ addr, dashApi });
    //let balanceInfo = await checkBalance({ addr, dashApi });
    //console.info(balanceInfo);
    return;
  }

  /**
   * @param {Object} opts
   * @param {any} opts.dashApi - TODO
   * @param {String} opts.defaultAddr
   * @param {Boolean} opts.forceConfirm
   * @param {String} opts.insightBaseUrl
   * @param {any} opts.insightApi
   * @param {Array<String>} args
   */
  // ex: node ./bin/crowdnode.js transfer ./priv.wif 'pub' 0.01
  async function transferBalance(
    { dashApi, defaultAddr, forceConfirm, insightBaseUrl, insightApi },
    args,
  ) {
    let wif = await mustGetWif({ defaultAddr }, args);

    let keyname = args.shift() || "";
    let newAddr = await wifFileToAddr(keyname);
    let dashAmount = parseFloat(args.shift() || "0");
    let duffAmount = Math.round(dashAmount * DUFFS);
    let tx;
    if (duffAmount) {
      tx = await dashApi.createPayment(wif, newAddr, duffAmount);
    } else {
      tx = await dashApi.createBalanceTransfer(wif, newAddr);
    }
    if (duffAmount) {
      let dashAmountStr = toDash(duffAmount);
      console.info(
        `Transferring ${duffAmount} (Đ${dashAmountStr}) to ${newAddr}...`,
      );
    } else {
      console.info(`Transferring balance to ${newAddr}...`);
    }
    await insightApi.instantSend(tx);
    console.info(`Queued...`);
    setTimeout(function () {
      // TODO take a cleaner approach
      // (waitForVout needs a reasonable timeout)
      console.error(`Error: Transfer did not complete.`);
      if (forceConfirm) {
        console.error(`(using --unconfirmed may lead to rejected double spends)`);
      }

      process.exit(1);
    }, 30 * 1000);
    await Ws.waitForVout(insightBaseUrl, newAddr, 0);
    console.info(`Accepted!`);
    return;
  }

  /**
   * @param {Object} opts
   * @param {any} opts.dashApi - TODO
   * @param {String} opts.defaultAddr
   * @param {String} opts.insightBaseUrl
   * @param {Array<String>} args
   */
  async function getStatus({ dashApi, defaultAddr, insightBaseUrl }, args) {
    let [addr] = await mustGetAddr({ defaultAddr }, args);
    await initCrowdNode(insightBaseUrl);
    let hotwallet = CrowdNode.main.hotwallet;
    let state = await getCrowdNodeStatus({ addr, hotwallet });

    console.info();
    console.info(`API Actions Complete for ${addr}:`);
    console.info(`    ${state.signup} SignUpForApi`);
    console.info(`    ${state.accept} AcceptTerms`);
    console.info(`    ${state.deposit} DepositReceived`);
    console.info();
    let crowdNodeBalance = await CrowdNode.http.GetBalance(addr);
    // may be unregistered / undefined
    /*
     * {
     *   '@odata.context': 'https://app.crowdnode.io/odata/$metadata#Edm.String',
     *   value: 'Address not found.'
     * }
     */
    if (!crowdNodeBalance.TotalBalance) {
      crowdNodeBalance.TotalBalance = 0;
    }
    let crowdNodeDuff = toDuff(crowdNodeBalance.TotalBalance);
    console.info(
      `CrowdNode Stake: ${crowdNodeDuff} (Đ${crowdNodeBalance.TotalBalance})`,
    );
    console.info();
    return;
  }

  /**
   * @param {Object} opts
   * @param {any} opts.dashApi - TODO
   * @param {String} opts.defaultAddr
   * @param {String} opts.insightBaseUrl
   * @param {Array<String>} args
   */
  async function sendSignup({ dashApi, defaultAddr, insightBaseUrl }, args) {
    let [addr, name] = await mustGetAddr({ defaultAddr }, args);
    await initCrowdNode(insightBaseUrl);
    let hotwallet = CrowdNode.main.hotwallet;
    let state = await getCrowdNodeStatus({ addr, hotwallet });
    let balanceInfo = await checkBalance({ addr, dashApi });

    if (state.status?.signup) {
      console.info(`${addr} is already signed up. Here's the account status:`);
      console.info(`    ${state.signup} SignUpForApi`);
      console.info(`    ${state.accept} AcceptTerms`);
      console.info(`    ${state.deposit} DepositReceived`);
      return;
    }

    let hasEnough = balanceInfo.balanceSat > signupOnly + feeEstimate;
    if (!hasEnough) {
      await collectSignupFees(insightBaseUrl, addr);
    }

    let wif = await maybeReadKeyPaths(name, { wif: true });

    console.info("Requesting account...");
    await CrowdNode.signup(wif, hotwallet);
    state.signup = DONE;
    console.info(`    ${state.signup} SignUpForApi`);
    return;
  }

  /**
   * @param {Object} opts
   * @param {any} opts.dashApi - TODO
   * @param {String} opts.defaultAddr
   * @param {String} opts.insightBaseUrl
   * @param {Array<String>} args
   */
  async function acceptTerms({ dashApi, defaultAddr, insightBaseUrl }, args) {
    let [addr, name] = await mustGetAddr({ defaultAddr }, args);

    await initCrowdNode(insightBaseUrl);
    let hotwallet = CrowdNode.main.hotwallet;
    let state = await getCrowdNodeStatus({ addr, hotwallet });
    let balanceInfo = await dashApi.getInstantBalance(addr);

    if (!state.status?.signup) {
      console.info(`${addr} is not signed up yet. Here's the account status:`);
      console.info(`    ${state.signup} SignUpForApi`);
      console.info(`    ${state.accept} AcceptTerms`);
      process.exit(1);
      return;
    }

    if (state.status?.accept) {
      console.info(`${addr} is already signed up. Here's the account status:`);
      console.info(`    ${state.signup} SignUpForApi`);
      console.info(`    ${state.accept} AcceptTerms`);
      console.info(`    ${state.deposit} DepositReceived`);
      return;
    }
    let hasEnough = balanceInfo.balanceSat > acceptOnly + feeEstimate;
    if (!hasEnough) {
      await collectSignupFees(insightBaseUrl, addr);
    }

    let wif = await maybeReadKeyPaths(name, { wif: true });

    console.info("Accepting terms...");
    await CrowdNode.accept(wif, hotwallet);
    state.accept = DONE;
    console.info(`    ${state.accept} AcceptTerms`);
    return;
  }

  /**
   * @param {Object} opts
   * @param {any} opts.dashApi - TODO
   * @param {String} opts.defaultAddr
   * @param {String} opts.insightBaseUrl
   * @param {Boolean} opts.noReserve
   * @param {Array<String>} args
   */
  async function depositDash(
    { dashApi, defaultAddr, insightBaseUrl, noReserve },
    args,
  ) {
    let [addr, name] = await mustGetAddr({ defaultAddr }, args);
    await initCrowdNode(insightBaseUrl);
    let hotwallet = CrowdNode.main.hotwallet;
    let state = await getCrowdNodeStatus({ addr, hotwallet });
    let balanceInfo = await dashApi.getInstantBalance(addr);

    if (!state.status?.accept) {
      console.error(`no account for address ${addr}`);
      process.exit(1);
      return;
    }

    // this would allow for at least 2 withdrawals costing (21000 + 1000)
    let reserve = 50000;
    let reserveDash = toDash(reserve);
    if (!noReserve) {
      console.info(
        `reserving ${reserve} (Đ${reserveDash}) for withdrawals (--no-reserve to disable)`,
      );
    } else {
      reserve = 0;
    }

    // TODO if unconfirmed, check utxos instead

    // deposit what the user asks, or all that we have,
    // or all that the user deposits - but at least 2x the reserve
    let desiredAmountDash = parseFloat(args.shift() || "0");
    let desiredAmountDuff = Math.round(desiredAmountDash * DUFFS);
    let effectiveAmount = desiredAmountDuff;
    if (!effectiveAmount) {
      effectiveAmount = balanceInfo.balanceSat - reserve;
    }
    let needed = Math.max(reserve * 2, effectiveAmount + reserve);

    if (balanceInfo.balanceSat < needed) {
      let ask = 0;
      if (desiredAmountDuff) {
        ask = desiredAmountDuff + reserve + -balanceInfo.balanceSat;
      }
      await collectDeposit(insightBaseUrl, addr, ask);
      balanceInfo = await dashApi.getInstantBalance(addr);
      if (balanceInfo.balanceSat < needed) {
        let balanceDash = toDash(balanceInfo.balanceSat);
        console.error(
          `Balance is still too small: ${balanceInfo.balanceSat} (Đ${balanceDash})`,
        );
        process.exit(1);
        return;
      }
    }
    if (!desiredAmountDuff) {
      effectiveAmount = balanceInfo.balanceSat - reserve;
    }

    let effectiveDash = toDash(effectiveAmount);
    console.info(
      `Initiating deposit of ${effectiveAmount} (Đ${effectiveDash})...`,
    );

    let wif = await maybeReadKeyPaths(name, { wif: true });

    await CrowdNode.deposit(wif, hotwallet, effectiveAmount);
    state.deposit = DONE;
    console.info(`    ${state.deposit} DepositReceived`);
    return;
  }

  /**
   * @param {Object} opts
   * @param {any} opts.dashApi - TODO
   * @param {String} opts.defaultAddr
   * @param {String} opts.insightBaseUrl
   * @param {Array<String>} args
   */
  async function withdrawalDash({ dashApi, defaultAddr, insightBaseUrl }, args) {
    let [addr] = await mustGetAddr({ defaultAddr }, args);
    await initCrowdNode(insightBaseUrl);
    let hotwallet = CrowdNode.main.hotwallet;
    let state = await getCrowdNodeStatus({ addr, hotwallet });

    if (!state.status?.accept) {
      console.error(`no account for address ${addr}`);
      process.exit(1);
      return;
    }

    let percentStr = args.shift() || "100.0";
    // pass: .1 0.1, 1, 1.0, 10, 10.0, 100, 100.0
    // fail: 1000, 10.00
    if (!/^1?\d?\d?(\.\d)?$/.test(percentStr)) {
      console.error("Error: withdrawal percent must be between 0.1 and 100.0");
      process.exit(1);
    }
    let percent = parseFloat(percentStr);

    let permil = Math.round(percent * 10);
    if (permil <= 0 || permil > 1000) {
      console.error("Error: withdrawal percent must be between 0.1 and 100.0");
      process.exit(1);
    }

    let realPercentStr = (permil / 10).toFixed(1);
    console.info(`Initiating withdrawal of ${realPercentStr}%...`);

    let wifname = await findWif(addr);
    let filepath = Path.join(keysDir, wifname);
    let wif = await maybeReadKeyFile(filepath);
    let paid = await CrowdNode.withdrawal(wif, hotwallet, permil);
    //let paidFloat = (paid.satoshis / DUFFS).toFixed(8);
    //let paidInt = paid.satoshis.toString().padStart(9, "0");
    console.info(`API Response: ${paid.api}`);
    return;
  }

  // Helpers

  /**
   * Convert prefix, addr, keyname, or filepath to pub addr
   * @param {String} name
   * @throws
   */
  async function wifFileToAddr(name) {
    if (34 === name.length) {
      // actually payment addr
      return name;
    }

    let privKey = "";

    let wifname = await findWif(name);
    if (wifname) {
      let filepath = Path.join(keysDir, wifname);
      privKey = await maybeReadKeyFile(filepath);
    }
    if (!privKey) {
      privKey = await maybeReadKeyFile(name);
    }
    if (!privKey) {
      throw new Error("bad file path or address");
    }

    let pk = new Dashcore.PrivateKey(privKey);
    let pub = pk.toPublicKey().toAddress().toString();
    return pub;
  }

  /**
   * @param {String} insightBaseUrl
   * @param {String} addr
   */
  async function collectSignupFees(insightBaseUrl, addr) {
    console.info(``);
    showQr(addr);

    let signupTotalDash = toDash(signupTotal);
    let signupMsg = `Please send >= ${signupTotal} (Đ${signupTotalDash}) to Sign Up to CrowdNode`;
    let msgPad = Math.ceil((qrWidth - signupMsg.length) / 2);
    let subMsg = "(plus whatever you'd like to deposit)";
    let subMsgPad = Math.ceil((qrWidth - subMsg.length) / 2);

    console.info();
    console.info(" ".repeat(msgPad) + signupMsg);
    console.info(" ".repeat(subMsgPad) + subMsg);
    console.info();

    console.info("");
    console.info("(waiting...)");
    console.info("");
    let payment = await Ws.waitForVout(insightBaseUrl, addr, 0);
    console.info(`Received ${payment.satoshis}`);
  }

  /**
   * @param {String} insightBaseUrl
   * @param {String} addr
   * @param {Number} duffAmount
   */
  async function collectDeposit(insightBaseUrl, addr, duffAmount) {
    console.info(``);
    showQr(addr, duffAmount);

    let depositMsg = `Please send what you wish to deposit to ${addr}`;
    if (duffAmount) {
      let dashAmount = toDash(duffAmount);
      depositMsg = `Please deposit ${duffAmount} (Đ${dashAmount}) to ${addr}`;
    }

    let msgPad = Math.ceil((qrWidth - depositMsg.length) / 2);
    msgPad = Math.max(0, msgPad);

    console.info();
    console.info(" ".repeat(msgPad) + depositMsg);
    console.info();

    console.info("");
    console.info("(waiting...)");
    console.info("");
    let payment = await Ws.waitForVout(insightBaseUrl, addr, 0);
    console.info(`Received ${payment.satoshis}`);
  }

  /**
   * @param {Error & { code: String }} err
   * @throws
   */
  function emptyStringOnErrEnoent(err) {
    if ("ENOENT" !== err.code) {
      throw err;
    }
    return "";
  }

  /**
   * @param {Number} duffs - ex: 00000000
   */
  function toDash(duffs) {
    return (duffs / DUFFS).toFixed(8);
  }

  /**
   * @param {Number} duffs - ex: 00000000
   */
  function toDASH(duffs) {
    let dash = (duffs / DUFFS).toFixed(8);
    return `Đ` + dash.padStart(12, " ");
  }

  /**
   * @param {String} dash - ex: 0.00000000
   */
  function toDuff(dash) {
    return Math.round(parseFloat(dash) * DUFFS);
  }

  // Run

  main().catch(function (err) {
    console.error("Fail:");
    console.error(err.stack || err);

    process.exit(1);
  });

  return crowdnode$1;

})(require$$0$5, require$$0$4, require$$2$1, require$$0, require$$1, require$$0$1, require$$0$2, require$$1$1, require$$2, require$$0$3, require$$1$2);
