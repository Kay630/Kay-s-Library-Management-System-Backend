'use strict';

// Keeps PDFs and cover images in Supabase Storage (online) instead of on this computer.
// PDFs live in a private bucket. Covers live in a public bucket so the browser can show them.
const PDF_BUCKET = 'book-pdfs';
const COVER_BUCKET = 'book-covers';

function makeStorage(baseUrl, key) {
  const root = baseUrl.replace(/\/+$/, '') + '/storage/v1';
  const headers = extra => ({ apikey: key, ...extra });

  async function call(method, url, options = {}) {
    const res = await fetch(root + url, { method, ...options });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error('Storage ' + method + ' ' + url + ' failed (' + res.status + '): ' + text.slice(0, 200));
    }
    return res;
  }

  return {
    // Creates the two buckets if they are not there yet.
    async setup() {
      for (const [name, isPublic] of [[PDF_BUCKET, false], [COVER_BUCKET, true]]) {
        const res = await fetch(root + '/bucket', {
          method: 'POST',
          headers: headers({ 'Content-Type': 'application/json' }),
          body: JSON.stringify({ id: name, name, public: isPublic })
        });
        if (!res.ok && !/exist|duplicate/i.test(await res.text())) {
          throw new Error('Could not create storage bucket "' + name + '" (' + res.status + '). Check SUPABASE_URL and SUPABASE_SECRET_KEY.');
        }
      }
    },

    savePdf: (name, data) => call('POST', '/object/' + PDF_BUCKET + '/' + name, {
      headers: headers({ 'Content-Type': 'application/pdf' }), body: data
    }),
    saveCover: (name, data, type) => call('POST', '/object/' + COVER_BUCKET + '/' + name, {
      headers: headers({ 'Content-Type': type, 'Cache-Control': 'max-age=31536000' }), body: data
    }),

    // Returns the PDF as a web Response so the server can stream it to the logged-in user.
    getPdf: name => call('GET', '/object/' + PDF_BUCKET + '/' + name, { headers: headers() }),

    removePdf: name => name ? call('DELETE', '/object/' + PDF_BUCKET + '/' + name, { headers: headers() }).catch(() => {}) : Promise.resolve(),
    removeCover: name => name ? call('DELETE', '/object/' + COVER_BUCKET + '/' + name, { headers: headers() }).catch(() => {}) : Promise.resolve(),

    coverUrl: name => root + '/object/public/' + COVER_BUCKET + '/' + name
  };
}

module.exports = { makeStorage };
