import Cookie from "tough-cookie";
import { ICookies } from "../types/cookies";

let Cookies = <ICookies>{};

//@ts-ignore TODO
//let FileCookieStore = require("@root/file-cookie-store");
//let cookies_store = new FileCookieStore("./cookie.txt", { auto_sync: false });
let jar = new Cookie.CookieJar(/*cookies_store*/);
jar.setCookieAsync = require("util").promisify(jar.setCookie);
jar.getCookiesAsync = require("util").promisify(jar.getCookies);
//cookies_store.saveAsync = require("util").promisify(cookies_store.save);

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

Cookies.get = async function _getCookie(url) {
  return (await jar.getCookiesAsync(url)).toString();
};
