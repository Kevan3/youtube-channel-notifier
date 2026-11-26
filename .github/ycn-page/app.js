'use strict';

// Decrypted data lives only in memory. Nothing from it is written to
// storage; the only thing remembered is the thumbnail on/off preference.

const PAGE_SIZE = 150;
const IDLE_LOCK_MS = 30 * 60 * 1000;
const VIDEO_ID = /^[A-Za-z0-9_-]{11}$/;
const CHANNEL_ID = /^UC[A-Za-z0-9_-]{22}$/;

const $ = (id) => document.getElementById(id);

let data = null;
let channelsById = new Map();
let shown = PAGE_SIZE;

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

function getPref(key, fallback) {
  try {
    const value = localStorage.getItem(key);
    return value === null ? fallback : value === 'true';
  } catch {
    return fallback;
  }
}

function setPref(key, value) {
  try { localStorage.setItem(key, String(value)); } catch { /* storage unavailable */ }
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

// ---------- decryption ----------

async function decrypt(passphrase) {
  const response = await fetch('data.json', { cache: 'no-store' });
  if (!response.ok) throw new Error('The encrypted data file could not be loaded.');
  const envelope = await response.json();
  if (envelope.v !== 1) throw new Error('Unsupported data format.');

  const baseKey = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey'],
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: b64(envelope.salt), iterations: envelope.iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );

  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(envelope.iv) }, key, b64(envelope.data));
  } catch {
    throw new Error('Wrong passphrase.');
  }
  return JSON.parse(new TextDecoder().decode(plaintext));
}

// ---------- rendering ----------

function videoMatches(video, query, channelId, hideMuted) {
  const channel = channelsById.get(video.c);
  if (channelId && String(video.c) !== channelId) return false;
  if (hideMuted && channel?.muted) return false;
  if (query && !video.t.toLowerCase().includes(query)) return false;
  return true;
}

function renderVideos() {
  const query = $('search').value.trim().toLowerCase();
  const channelId = $('channel-filter').value;
  const hideMuted = $('hide-muted').checked;
  const thumbs = $('thumbs').checked;

  const matches = data.videos.filter((v) => videoMatches(v, query, channelId, hideMuted));
  const visible = matches.slice(0, shown);

  $('video-summary').textContent = matches.length === data.videos.length
    ? `${matches.length.toLocaleString()} videos`
    : `${matches.length.toLocaleString()} of ${data.videos.length.toLocaleString()} videos`;

  const list = $('video-list');
  list.replaceChildren();

  if (visible.length === 0) {
    list.append(el('p', { class: 'empty', text: data.videos.length ? 'No videos match.' : 'No videos yet.' }));
  }

  let group = null;
  let groupKey = null;
  for (const video of visible) {
    const published = new Date(video.p);
    const key = dayKey(published);
    if (key !== groupKey) {
      groupKey = key;
      group = el('div', { class: 'video-list' });
      list.append(el('section', { class: 'day' }, el('h2', { text: dayLabel(published) }), group));
    }

    const channel = channelsById.get(video.c);
    const validId = VIDEO_ID.test(video.id);
    const href = validId ? `https://www.youtube.com/watch?v=${video.id}` : undefined;

    group.append(el('a', { class: 'video', href, target: '_blank', rel: 'noopener noreferrer' },
      thumbs && validId
        ? el('img', { src: `https://i.ytimg.com/vi/${video.id}/mqdefault.jpg`, alt: '', loading: 'lazy', referrerpolicy: 'no-referrer' })
        : null,
      el('div', { class: 'video-text' },
        el('div', { class: 'video-title', text: video.t }),
        el('div', { class: 'video-meta' },
          `${channel?.name ?? 'Unknown channel'} · ${timeFormat.format(published)}`,
          channel?.muted ? el('span', { class: 'badge', text: 'muted' }) : null,
        ),
      ),
    ));
  }

  $('show-more').hidden = matches.length <= shown;
}

function renderChannels() {
  const latest = new Map();
  for (const video of data.videos) {
    if (!latest.has(video.c)) latest.set(video.c, new Date(video.p));
  }

  const grid = $('channel-list');
  grid.replaceChildren();

  if (data.channels.length === 0) {
    grid.append(el('p', { class: 'empty', text: 'No channels yet.' }));
  }

  for (const channel of data.channels) {
    const last = latest.get(channel.id);
    grid.append(el('div', { class: 'channel' },
      el('div', { class: 'channel-name' }, channel.name, channel.muted ? el('span', { class: 'badge', text: 'muted' }) : null),
      el('div', { class: 'muted small', text: `${channel.videoCount.toLocaleString()} videos${last ? ` · latest ${timeAgo(last)}` : ''}` }),
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

function start(decrypted) {
  data = decrypted;
  channelsById = new Map(data.channels.map((c) => [c.id, c]));

  const select = $('channel-filter');
  for (const channel of data.channels) {
    select.append(el('option', { value: String(channel.id), text: channel.name }));
  }

  $('count-videos').textContent = data.videos.length.toLocaleString();
  $('count-channels').textContent = data.channels.length.toLocaleString();
  $('updated').textContent = `Updated ${timeAgo(new Date(data.generatedAt))}`;
  $('updated').title = fullFormat.format(new Date(data.generatedAt));

  renderVideos();
  renderChannels();
  renderActivity();

  $('lock').hidden = true;
  $('app').hidden = false;
}

// Reloading drops every decrypted value from memory.
function lock() {
  data = null;
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
      const decrypted = await decrypt(input.value);
      input.value = '';
      start(decrypted);
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

  for (const id of ['search', 'channel-filter', 'hide-muted']) {
    $(id).addEventListener('input', () => {
      shown = PAGE_SIZE;
      renderVideos();
    });
  }

  $('show-more').addEventListener('click', () => {
    shown += PAGE_SIZE;
    renderVideos();
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
