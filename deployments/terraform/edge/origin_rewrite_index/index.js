exports.handler = async (event) => {
  const req = event.Records?.[0]?.cf?.request || event.request || event.cf?.request;
  if (!req) return event;

  // Only rewrite exactly the naked root
  if (req.uri === "/") {
    req.uri = "/index.html";
  }
  return req;
};