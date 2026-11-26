<?php

declare(strict_types=1);

/*
 * Builds the encrypted data file for the private GitHub Pages video list.
 *
 * Usage: php .github/ycn-page/export.php <logs.json> <output.json>
 * Passphrase: YCN_PAGE_PASSPHRASE environment variable.
 *
 * The page decrypts this in the browser with the Web Crypto API:
 * PBKDF2-SHA256 (600,000 iterations) -> AES-256-GCM. The plaintext is
 * padded to a multiple of 64 KiB so the file size only hints at how much
 * data there is.
 */

use App\Models\Channel;
use App\Models\ExcludedWord;
use App\Models\Video;
use Illuminate\Contracts\Console\Kernel;

const PBKDF2_ITERATIONS = 600_000;
const PAD_TO_BYTES = 65_536;

$root = dirname(__DIR__, 2);

require $root.'/vendor/autoload.php';

$app = require $root.'/bootstrap/app.php';
$app->make(Kernel::class)->bootstrap();

$logsPath = $argv[1] ?? null;
$outputPath = $argv[2] ?? null;

if ($logsPath === null || $outputPath === null) {
    fwrite(STDERR, "Usage: php export.php <logs.json> <output.json>\n");
    exit(1);
}

$passphrase = (string) getenv('YCN_PAGE_PASSPHRASE');

if (strlen($passphrase) < 20) {
    fwrite(STDERR, "YCN_PAGE_PASSPHRASE must be at least 20 characters.\n");
    exit(1);
}

$channels = Channel::query()
    ->withCount('videos')
    ->orderBy('name')
    ->get()
    ->map(fn (Channel $channel): array => [
        'id' => $channel->id,
        'name' => $channel->name,
        'channelId' => $channel->channel_id,
        'muted' => $channel->isMuted(),
        'note' => $channel->note,
        'videoCount' => $channel->videos_count,
        'lastCheckedAt' => $channel->last_checked_at?->toIso8601String(),
    ])
    ->values()
    ->all();

$videos = Video::query()
    ->orderByDesc('published_at')
    ->get(['channel_id', 'video_id', 'title', 'published_at'])
    ->map(fn (Video $video): array => [
        'c' => $video->channel_id,
        'id' => $video->video_id,
        't' => $video->title,
        'p' => $video->published_at->toIso8601String(),
    ])
    ->values()
    ->all();

$logs = is_file($logsPath) ? json_decode((string) file_get_contents($logsPath), true) : [];

$json = json_encode([
    'generatedAt' => now()->toIso8601String(),
    'channels' => $channels,
    'videos' => $videos,
    'excludedWords' => ExcludedWord::query()->orderBy('word')->pluck('word')->all(),
    'logs' => is_array($logs) ? $logs : [],
], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

$padding = (PAD_TO_BYTES - strlen($json) % PAD_TO_BYTES) % PAD_TO_BYTES;
$plaintext = $json.str_repeat(' ', $padding);

$salt = random_bytes(16);
$iv = random_bytes(12);
$key = hash_pbkdf2('sha256', $passphrase, $salt, PBKDF2_ITERATIONS, 32, true);
$tag = '';

$ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);

if ($ciphertext === false) {
    fwrite(STDERR, "Encryption failed.\n");
    exit(1);
}

file_put_contents($outputPath, json_encode([
    'v' => 1,
    'iterations' => PBKDF2_ITERATIONS,
    'salt' => base64_encode($salt),
    'iv' => base64_encode($iv),
    // Web Crypto expects the GCM tag appended to the ciphertext.
    'data' => base64_encode($ciphertext.$tag),
], JSON_THROW_ON_ERROR));

echo "Encrypted page data written.\n";
