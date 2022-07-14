export const fs = {
  mkdir: function (path: string, options: any) {
    return Promise.resolve();
  },
  readFile: function (path: string, encode: string) {
    return Promise.resolve("");
  },
  writeFile: function (path: string, data: string, encode: string) {
    return Promise.resolve();
  },
  access: function (path: string) {
    return Promise.resolve(true);
  },
  readdir: function (keysDir: string) {
    return Promise.resolve([]);
  },
  unlink: function (path: string) {
    return Promise.resolve();
  },
};
