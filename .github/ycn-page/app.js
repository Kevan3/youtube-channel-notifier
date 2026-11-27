'use strict';

// Decrypted data lives only in memory. Two things are kept in this browser's
// localStorage:
// - the thumbnail on/off preference (not sensitive), and
// - the list of videos you removed, encrypted with a key derived from your
//   passphrase. Every github.io page of the same account shares this storage,
//   so it must never hold anything readable.

const PAGE_SIZE = 150;
const IDLE_LOCK_MS = 30 * 60 * 1000;
const UNDO_MS = 6000;
const PBKDF2_ITERATIONS = 600000;
const REMOVED_KEY = 'ycn.removed.v1';
const VIDEO_ID = /^[A-Za-z0-9_-]{11}$/;
const CHANNEL_ID = /^UC[A-Za-z0-9_-]{22}$/;

const $ = (id) => document.getElementById(id);

let data = null;
let channelsById = new Map();
let shown = PAGE_SIZE;

// Removed videos: video ID -> time removed (ms).
let removed = new Map();
let removedKey = null;
let removedSalt = null;
let storageWorks = true;
let undoTimer = null;
let lastRemoval = [];

// ---------- small helpers ----------

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat()) {
    if (child !== null && child !== undefined && child !== false) {
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
  }
  return node;
}

function b64(value) {
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}

function toB64(bytes) {
  let binary = '';
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function storageGet(key) {
  try { return localStorage.getItem(key); } catch { return null; }
}

function storageSet(key, value) {
  try {
    localStorage.setItem(key, value);
    return true;
  } catch {
    return false;
  }
}

function getPref(key, fallback) {
  const value = storageGet(key);
  return value === null ? fallback : value === 'true';
}

function setPref(key, value) {
  storageSet(key, String(value));
}

const relative = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

function timeAgo(date) {
  const seconds = Math.round((date - Date.now()) / 1000);
  const units = [['year', 31536000], ['month', 2592000], ['week', 604800], ['day', 86400], ['hour', 3600], ['minute', 60]];
  for (const [unit, size] of units) {
    if (Math.abs(seconds) >= size) return relative.format(Math.round(seconds / size), unit);
  }
  return 'just now';
}

const dayFormat = new Intl.DateTimeFormat(undefined, { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
const timeFormat = new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit' });
const fullFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

function dayKey(date) {
  return `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`;
}

function dayLabel(date) {
  const today = new Date();
  const yesterday = new Date(today);
  yesterday.setDate(today.getDate() - 1);
  if (dayKey(date) === dayKey(today)) return 'Today';
  if (dayKey(date) === dayKey(yesterday)) return 'Yesterday';
  return dayFormat.format(date);
}

// ---------- crypto ----------

async function deriveKey(passphrase, salt, iterations) {
  const baseKey = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function decrypt(passphrase) {
  const response = await fetch('data.json', { cache: 'no-store' });
  if (!response.ok) throw new Error('The encrypted data file could not be loaded.');
  const envelope = await response.json();
  if (envelope.v !== 1) throw new Error('Unsupported data format.');

  const key = await deriveKey(passphrase, b64(envelope.salt), envelope.iterations);

  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(envelope.iv) }, key, b64(envelope.data));
  } catch {
    throw new Error('Wrong passphrase.');
  }
  return JSON.parse(new TextDecoder().decode(plaintext));
}

// ---------- removed videos (encrypted in localStorage) ----------

function readRemovedRecord() {
  try {
    const record = JSON.parse(storageGet(REMOVED_KEY) ?? 'null');
    return record && record.v === 1 ? record : null;
  } catch {
    return null;
  }
}

// Derives the storage key from the passphrase. Its salt is random per browser
// and kept beside the ciphertext; it is not secret.
async function openRemoved(passphrase) {
  const record = readRemovedRecord();
  removedSalt = record ? b64(record.salt) : crypto.getRandomValues(new Uint8Array(16));
  removedKey = await deriveKey(passphrase, removedSalt, PBKDF2_ITERATIONS);

  if (!record) return { map: new Map(), unreadable: false };

  try {
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(record.iv) }, removedKey, b64(record.data));
    const entries = JSON.parse(new TextDecoder().decode(plaintext));
    return { map: new Map(entries), unreadable: false };
  } catch {
    // Saved under a different passphrase. Start a new list with a new salt;
    // the old one is replaced on the next save.
    removedSalt = crypto.getRandomValues(new Uint8Array(16));
    removedKey = await deriveKey(passphrase, removedSalt, PBKDF2_ITERATIONS);
    return { map: new Map(), unreadable: true };
  }
}

// Saves run one after another so a slow save can't overwrite a newer one.
let saveQueue = Promise.resolve();

function saveRemoved() {
  saveQueue = saveQueue.then(writeRemoved, writeRemoved);
  return saveQueue;
}

async function writeRemoved() {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify([...removed]));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, removedKey, plaintext);
  const ok = storageSet(REMOVED_KEY, JSON.stringify({
    v: 1, salt: toB64(removedSalt), iv: toB64(iv), data: toB64(ciphertext),
  }));
  if (!ok && storageWorks) {
    storageWorks = false;
    showNotice('This browser is not letting the page save, so removed videos will come back after you lock or reload.');
  }
}

function showNotice(text) {
  $('storage-notice').textContent = text;
  $('storage-notice').hidden = false;
}

function removeVideos(ids) {
  const fresh = ids.filter((id) => !removed.has(id));
  if (fresh.length === 0) return;
  const now = Date.now();
  for (const id of fresh) removed.set(id, now);
  lastRemoval = fresh;
  saveRemoved();
  rerender();
  showToast(fresh.length === 1 ? 'Video removed' : `${fresh.length} videos removed`);
}

function restoreVideos(ids) {
  for (const id of ids) removed.delete(id);
  saveRemoved();
  rerender();
}

function showToast(text) {
  $('toast-text').textContent = text;
  $('toast').hidden = false;
  clearTimeout(undoTimer);
  undoTimer = setTimeout(hideToast, UNDO_MS);
}

function hideToast() {
  $('toast').hidden = true;
  lastRemoval = [];
}

// ---------- rendering ----------

function videoMatches(video, query, channelId, hideMuted, showRemoved) {
  const channel = channelsById.get(video.c);
  if (!showRemoved && removed.has(video.id)) return false;
  if (channelId && String(video.c) !== channelId) return false;
  if (hideMuted && channel?.muted) return false;
  if (query && !video.t.toLowerCase().includes(query)) return false;
  return true;
}

function renderVideos() {
  const query = $('search').value.trim().toLowerCase();
  const channelId = $('channel-filter').value;
  const hideMuted = $('hide-muted').checked;
  const showRemoved = $('show-removed').checked;
  const thumbs = $('thumbs').checked;

  const matches = data.videos.filter((v) => videoMatches(v, query, channelId, hideMuted, showRemoved));
  const visible = matches.slice(0, shown);
  const remaining = data.videos.filter((v) => !removed.has(v.id)).length;
  const removedCount = data.videos.length - remaining;

  const filtered = query || channelId || hideMuted;
  let summary = filtered
    ? `${matches.length.toLocaleString()} matching videos`
    : `${matches.length.toLocaleString()} videos`;
  if (removedCount > 0) summary += ` · ${removedCount.toLocaleString()} removed${showRemoved ? ' (shown faded)' : ''}`;
  $('video-summary').textContent = summary;
  $('count-videos').textContent = remaining.toLocaleString();

  const list = $('video-list');
  list.replaceChildren();

  if (visible.length === 0) {
    const text = data.videos.length === 0 ? 'No videos yet.'
      : filtered ? 'No videos match.'
        : 'Nothing left to watch. Removed videos are under “Show removed”.';
    list.append(el('p', { class: 'empty', text }));
  }

  // Group the visible videos by day.
  const groups = [];
  for (const video of visible) {
    const published = new Date(video.p);
    const key = dayKey(published);
    if (groups.length === 0 || groups[groups.length - 1].key !== key) {
      groups.push({ key, date: published, videos: [] });
    }
    groups[groups.length - 1].videos.push(video);
  }

  for (const group of groups) {
    const toRemove = group.videos.filter((v) => !removed.has(v.id)).map((v) => v.id);
    const rows = el('div', { class: 'video-list' }, group.videos.map((video) => renderVideo(video, thumbs)));
    list.append(el('section', { class: 'day' },
      el('div', { class: 'day-head' },
        el('h2', { text: dayLabel(group.date) }),
        toRemove.length > 1
          ? el('button', { type: 'button', text: `Remove all ${toRemove.length}`, onclick: () => removeVideos(toRemove) })
          : null,
      ),
      rows,
    ));
  }

  $('show-more').hidden = matches.length <= shown;
}

function renderVideo(video, thumbs) {
  const published = new Date(video.p);
  const channel = channelsById.get(video.c);
  const validId = VIDEO_ID.test(video.id);
  const href = validId ? `https://www.youtube.com/watch?v=${video.id}` : undefined;
  const isRemoved = removed.has(video.id);

  return el('div', { class: isRemoved ? 'video removed' : 'video' },
    el('a', { class: 'video-link', href, target: '_blank', rel: 'noopener noreferrer' },
      thumbs && validId
        ? el('img', { src: `https://i.ytimg.com/vi/${video.id}/mqdefault.jpg`, alt: '', loading: 'lazy', referrerpolicy: 'no-referrer' })
        : null,
      el('div', { class: 'video-text' },
        el('div', { class: 'video-title', text: video.t }),
        el('div', { class: 'video-meta' },
          `${channel?.name ?? 'Unknown channel'} · ${timeFormat.format(published)}`,
          channel?.muted ? el('span', { class: 'badge', text: 'muted' }) : null,
          isRemoved ? el('span', { class: 'badge', text: 'removed' }) : null,
        ),
      ),
    ),
    isRemoved
      ? el('button', { type: 'button', class: 'video-action', text: 'Restore', 'aria-label': `Restore ${video.t}`, onclick: () => restoreVideos([video.id]) })
      : el('button', { type: 'button', class: 'video-action', text: 'Remove', 'aria-label': `Remove ${video.t}`, title: 'Remove from the list (e.g. already watched)', onclick: () => removeVideos([video.id]) }),
  );
}

function renderChannels() {
  const latest = new Map();
  const left = new Map();
  for (const video of data.videos) {
    if (!latest.has(video.c)) latest.set(video.c, new Date(video.p));
    if (!removed.has(video.id)) left.set(video.c, (left.get(video.c) ?? 0) + 1);
  }

  const grid = $('channel-list');
  grid.replaceChildren();

  if (data.channels.length === 0) {
    grid.append(el('p', { class: 'empty', text: 'No channels yet.' }));
  }

  for (const channel of data.channels) {
    const last = latest.get(channel.id);
    const unwatched = left.get(channel.id) ?? 0;
    grid.append(el('div', { class: 'channel' },
      el('div', { class: 'channel-name' }, channel.name, channel.muted ? el('span', { class: 'badge', text: 'muted' }) : null),
      el('div', { class: 'muted small', text: `${unwatched.toLocaleString()} of ${channel.videoCount.toLocaleString()} videos left${last ? ` · latest ${timeAgo(last)}` : ''}` }),
      channel.note ? el('div', { class: 'channel-note muted', text: channel.note }) : null,
      el('div', { class: 'channel-links' },
        el('button', { type: 'button', text: 'Show videos', onclick: () => showChannel(channel.id) }),
        CHANNEL_ID.test(channel.channelId)
          ? el('a', { href: `https://www.youtube.com/channel/${channel.channelId}`, target: '_blank', rel: 'noopener noreferrer', text: 'YouTube' })
          : null,
      ),
    ));
  }

  $('excluded-words').textContent = data.excludedWords.length ? data.excludedWords.join(', ') : 'None.';
}

function renderActivity() {
  const list = $('activity-list');
  list.replaceChildren();
  const runs = [...data.logs].reverse();

  if (runs.length === 0) {
    list.append(el('p', { class: 'empty', text: 'No runs recorded yet.' }));
  }

  for (const run of runs) {
    const at = new Date(run.at);
    list.append(el('details', { class: 'run' },
      el('summary', {},
        el('span', { class: `dot ${run.ok ? 'ok' : 'bad'}`, title: run.ok ? 'Succeeded' : 'Failed' }),
        el('strong', { text: run.command }),
        el('span', { class: 'muted small', text: `${run.trigger === 'schedule' ? 'scheduled' : 'manual'} · ${fullFormat.format(at)} (${timeAgo(at)})` }),
      ),
      el('pre', { text: run.output?.trim() || '(no output)' }),
    ));
  }

  const latest = runs[0];
  $('activity-status').replaceChildren(latest ? el('span', { class: `dot ${latest.ok ? 'ok' : 'bad'}` }) : '');
}

function rerender() {
  renderVideos();
  renderChannels();
}

function showChannel(id) {
  $('channel-filter').value = String(id);
  shown = PAGE_SIZE;
  selectTab('videos');
  renderVideos();
  window.scrollTo(0, 0);
}

function selectTab(name) {
  for (const button of document.querySelectorAll('[data-tab]')) {
    const active = button.dataset.tab === name;
    button.setAttribute('aria-selected', String(active));
    $(`tab-${button.dataset.tab}`).hidden = !active;
  }
}

function start(decrypted, removedState) {
  data = decrypted;
  removed = removedState.map;
  channelsById = new Map(data.channels.map((c) => [c.id, c]));

  if (removedState.unreadable) {
    showNotice('Your removed-videos list in this browser was saved with a different passphrase and can’t be read, so it has been reset.');
  }

  const select = $('channel-filter');
  for (const channel of data.channels) {
    select.append(el('option', { value: String(channel.id), text: channel.name }));
  }

  $('count-channels').textContent = data.channels.length.toLocaleString();
  $('updated').textContent = `Updated ${timeAgo(new Date(data.generatedAt))}`;
  $('updated').title = fullFormat.format(new Date(data.generatedAt));

  rerender();
  renderActivity();

  $('lock').hidden = true;
  $('app').hidden = false;
}

// Reloading drops every decrypted value and key from memory.
function lock() {
  data = null;
  removedKey = null;
  window.location.reload();
}

// ---------- wiring ----------

document.addEventListener('DOMContentLoaded', () => {
  $('thumbs').checked = getPref('ycn.thumbnails', false);

  $('unlock-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const input = $('passphrase');
    const button = $('unlock-button');
    const error = $('unlock-error');

    error.hidden = true;
    button.disabled = true;
    button.textContent = 'Decrypting…';
    try {
      const passphrase = input.value;
      const decrypted = await decrypt(passphrase);
      const removedState = await openRemoved(passphrase);
      input.value = '';
      start(decrypted, removedState);
    } catch (e) {
      error.textContent = e instanceof Error ? e.message : 'Could not unlock.';
      error.hidden = false;
      input.select();
    } finally {
      button.disabled = false;
      button.textContent = 'Unlock';
    }
  });

  $('lock-button').addEventListener('click', lock);

  $('thumbs').addEventListener('change', (event) => {
    setPref('ycn.thumbnails', event.target.checked);
    if (data) renderVideos();
  });

  for (const id of ['search', 'channel-filter', 'hide-muted', 'show-removed']) {
    $(id).addEventListener('input', () => {
      shown = PAGE_SIZE;
      renderVideos();
    });
  }

  $('show-more').addEventListener('click', () => {
    shown += PAGE_SIZE;
    renderVideos();
  });

  $('toast-undo').addEventListener('click', () => {
    const ids = lastRemoval;
    hideToast();
    restoreVideos(ids);
  });

  for (const button of document.querySelectorAll('[data-tab]')) {
    button.addEventListener('click', () => selectTab(button.dataset.tab));
  }

  // Lock after 30 minutes without interaction.
  let idleTimer;
  const resetIdle = () => {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => { if (data) lock(); }, IDLE_LOCK_MS);
  };
  for (const type of ['pointerdown', 'keydown', 'scroll']) {
    window.addEventListener(type, resetIdle, { passive: true });
  }
  resetIdle();
});
