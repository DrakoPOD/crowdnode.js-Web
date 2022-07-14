import commonjs from "@rollup/plugin-commonjs";
import json from "@rollup/plugin-json";
import typescript from "@rollup/plugin-typescript";

export default {
  input: "bin/crowdnode.js",
  output: {
    file: "dist/bundle.js",
    format: "iife",
    globals: {
      fs: "",
      path: "",
      dotenv: "",
      crypto: "",
      "@root/request": "",
      "@dashevo/dashcore-lib ": "",
      "tough-cookie": "",
      util: "",
      ws: "",
      readline: "",
      "qrcode-svg": "",
    },
  },
  plugins: [
    typescript(),
    json({ compact: true, namedExports: false }),
    commonjs(),
  ],
};
