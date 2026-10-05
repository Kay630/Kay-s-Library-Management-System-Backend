'use strict';
// Parses a multipart/form-data body that is already fully in memory.
// Returns { fields: {name: string}, files: {name: {filename, type, data: Buffer}} }.
// Throws an Error with .status = 400 if the body is malformed.

function bad() {
  const err = new Error('Invalid upload.');
  err.status = 400;
  return err;
}

function parseMultipart(buf, contentType) {
  const m = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(contentType || '');
  if (!m) throw bad();
  const token = m[1] || m[2];
  const boundary = Buffer.from('--' + token);
  const delimiter = Buffer.from('\r\n--' + token);
  const fields = Object.create(null);
  const files = Object.create(null);

  let pos = buf.indexOf(boundary);
  if (pos === -1) throw bad();

  for (let parts = 0; parts < 50; parts++) {
    pos += boundary.length;
    if (buf[pos] === 0x2d && buf[pos + 1] === 0x2d) return { fields, files }; // closing "--"
    if (buf[pos] !== 0x0d || buf[pos + 1] !== 0x0a) throw bad();
    pos += 2;

    const headEnd = buf.indexOf('\r\n\r\n', pos);
    if (headEnd === -1) throw bad();
    const head = buf.toString('utf8', pos, headEnd);
    const bodyStart = headEnd + 4;
    const next = buf.indexOf(delimiter, bodyStart);
    if (next === -1) throw bad();
    const body = buf.subarray(bodyStart, next);

    let name = null, filename = null, type = '';
    for (const line of head.split('\r\n')) {
      const i = line.indexOf(':');
      if (i < 0) continue;
      const key = line.slice(0, i).trim().toLowerCase();
      const val = line.slice(i + 1).trim();
      if (key === 'content-disposition') {
        const n = /(?:^|;)\s*name="((?:[^"\\]|\\.)*)"/i.exec(val);
        const f = /;\s*filename="((?:[^"\\]|\\.)*)"/i.exec(val);
        name = n ? n[1] : null;
        filename = f ? f[1] : null;
      } else if (key === 'content-type') {
        type = val.toLowerCase();
      }
    }
    if (!name) throw bad();

    if (filename !== null) {
      // An empty file input is sent as filename="" with no bytes: treat it as "no file".
      if (!(filename === '' && body.length === 0)) files[name] = { filename, type, data: body };
    } else {
      fields[name] = body.toString('utf8');
    }
    pos = next + 2; // now at the start of the next boundary
  }
  throw bad();
}

module.exports = { parseMultipart };
