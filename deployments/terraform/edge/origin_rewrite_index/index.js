exports.handler = async (event) => {
  const req = event.Records?.[0]?.cf?.request || event.request || event.cf?.request;
  if (!req) return event;

  // Only rewrite exactly the naked root
  if (req.uri === "/") {
    req.uri = "/index.html";
  // Or the /users path to the users index
  } else if (req.uri === "/users" || req.uri === "/users/") {
    req.uri = "/users/index.html";
  }

  return req;
};