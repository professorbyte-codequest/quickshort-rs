function handler(event) {
  var req = event.request;
  var res = event.response;

  // Only touch the default path (avoid /v1/*) and only 404s
  if (res.status == 404 && !req.uri.startsWith('/v1/')) {
    var slug = req.uri.replace(/^\\/, '');
    return {
      statusCode: 302,
      statusDescription: 'Found',
      headers: {
        'location': { value: 'https://codequesthub.io/links/not-found?slug=' + encodeURIComponent(slug) }
      }
    };
  }
  return res;
}
