const https = require('https');

const API_KEY = 'moltbook_sk_cPLm2OaAIXhS7pUznlnGVd_VSaRnigg6';
const UA = 'Mozilla/5.0 (compatible; TelegraphBot/1.0)';

function req(method, path, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const options = {
      hostname: 'www.moltbook.com',
      path,
      method,
      headers: {
        'Authorization': `Bearer ${API_KEY}`,
        'User-Agent': UA,
        'Content-Type': 'application/json',
      },
    };
    if (data) options.headers['Content-Length'] = Buffer.byteLength(data);
    const r = https.request(options, (res) => {
      let chunks = '';
      res.on('data', (d) => (chunks += d));
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(chunks) });
        } catch (e) {
          resolve({ status: res.statusCode, body: chunks });
        }
      });
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

async function main() {
  const [, , cmd, ...rest] = process.argv;
  if (cmd === 'post') {
    const [postId, parentId, b64content] = rest;
    const content = Buffer.from(b64content, 'base64').toString('utf8');
    const body = { content };
    if (parentId && parentId !== 'null') body.parent_id = parentId;
    const res = await req('POST', `/api/v1/posts/${postId}/comments`, body);
    console.log(JSON.stringify(res, null, 2));
  } else if (cmd === 'verify') {
    const [code, answer] = rest;
    const res = await req('POST', '/api/v1/verify', { verification_code: code, answer });
    console.log(JSON.stringify(res, null, 2));
  } else {
    console.error('usage: node moltbook_comment.js post <postId> <parentIdOrNull> <base64content>');
    console.error('       node moltbook_comment.js verify <code> <answer>');
    process.exit(1);
  }
}

main();
