"use strict";

fetch(
  `https://insight.dash.org/socket.io/?EIO=3&transport=polling&t=${Date.now()}`,
  {
    method: "GET",
    credentials: "include",
    headers: {
      // userAgent: "crowdnode/1.6.0",
      //"Access-Control-Allow-Credentials": true,
    },
  },
)
  .then(function (response) {
    console.log(...response.headers);
  })
  .catch(function (error) {
    console.log(error);
  })
  .finally(function (response) {
    console.log(document.cookie);
  });

/* axios
  .get(
    `https://insight.dash.org/socket.io/?EIO=3&transport=polling&t=${Date.now()}`,
  )
  .then(function (response) {
    console.log(response.headers);
  })
  .catch(function (error) {
    console.log(error);
  })
  .finally(function (response) {
    console.log(document.cookie);
    document.cookie = "unaCookie=true";
  });
 */
var button = document.getElementById("button");

button.addEventListener("click", function () {
  console.log(document.cookie);
});
