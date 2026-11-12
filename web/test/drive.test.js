// Client Google Drive testé contre un faux fetch : forme des requêtes et gestion des réponses.
const test = require('node:test');
const assert = require('node:assert/strict');
const Drive = require('../js/drive.js');

function fakeDrive(files = []) {
  const calls = [];
  const fetch = async (url, options = {}) => {
    calls.push({ url, ...options });
    const json = (body, status = 200) => ({ ok: status < 400, status, json: async () => body, text: async () => JSON.stringify(body) });
    if (url.startsWith('https://www.googleapis.com/drive/v3/files?')) return json({ files });
    if (url.includes('?alt=media')) return { ok: true, status: 200, text: async () => '{"v":1}' };
    if (options.method === 'POST') return json({ id: 'new-id', modifiedTime: '2026-10-30T20:00:00Z' });
    if (options.method === 'PATCH') return json({ id: files[0].id, modifiedTime: '2026-10-30T21:00:00Z' });
    return json({}, 404);
  };
  return { fetch, calls };
}

const getToken = async () => 'jeton-test';

test('find : recherche dans appDataFolder avec le jeton', async () => {
  const { fetch, calls } = fakeDrive([{ id: 'f1', modifiedTime: 't' }]);
  const found = await Drive.createClient({ fetch, getToken }).find();
  assert.deepEqual(found, { id: 'f1', modifiedTime: 't' });
  const url = new URL(calls[0].url);
  assert.equal(url.searchParams.get('spaces'), 'appDataFolder');
  // Nom, taille et dates : affichés dans la carte de sauvegarde.
  assert.equal(url.searchParams.get('fields'), 'files(id,name,size,createdTime,modifiedTime,headRevisionId)');
  assert.match(url.searchParams.get('q'), /name = 'mymfa-vault\.json'/);
  assert.equal(calls[0].headers.Authorization, 'Bearer jeton-test');
});

test('upload : création multipart dans appDataFolder si aucun fichier', async () => {
  const { fetch, calls } = fakeDrive([]);
  const res = await Drive.createClient({ fetch, getToken }).upload('{"v":1,"data":"chiffré"}');
  assert.equal(res.id, 'new-id');
  const post = calls.find((c) => c.method === 'POST');
  assert.match(post.url, /uploadType=multipart/);
  assert.match(post.headers['Content-Type'], /^multipart\/related; boundary=/);
  assert.match(post.body, /"parents":\["appDataFolder"\]/);
  assert.match(post.body, /"data":"chiffré"/);
});

test('upload : mise à jour (PATCH) du fichier existant', async () => {
  const { fetch, calls } = fakeDrive([{ id: 'f1', modifiedTime: 't' }]);
  await Drive.createClient({ fetch, getToken }).upload('{"v":1}');
  const patch = calls.find((c) => c.method === 'PATCH');
  assert.match(patch.url, /\/upload\/drive\/v3\/files\/f1\?uploadType=media/);
  assert.equal(patch.body, '{"v":1}');
});

test('download : contenu et date ; aucune sauvegarde → driveEmpty', async () => {
  const full = fakeDrive([{ id: 'f1', modifiedTime: '2026-10-30T20:00:00Z' }]);
  assert.deepEqual(await Drive.createClient({ fetch: full.fetch, getToken }).download(), {
    content: '{"v":1}',
    modifiedTime: '2026-10-30T20:00:00Z',
    file: { id: 'f1', modifiedTime: '2026-10-30T20:00:00Z' },
  });
  const empty = fakeDrive([]);
  await assert.rejects(Drive.createClient({ fetch: empty.fetch, getToken }).download(), { code: 'driveEmpty' });
});

test('erreurs HTTP : 401 → driveAuth, 500 → driveHttp', async () => {
  const fetch401 = async () => ({ ok: false, status: 401 });
  await assert.rejects(Drive.createClient({ fetch: fetch401, getToken }).find(), { code: 'driveAuth' });
  const fetch500 = async () => ({ ok: false, status: 500 });
  await assert.rejects(Drive.createClient({ fetch: fetch500, getToken }).find(), { code: 'driveHttp', params: { status: 500 } });
});
