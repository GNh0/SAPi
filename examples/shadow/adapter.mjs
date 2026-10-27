// Example only: no deployment, transport, logging, or durable storage is configured.
export function createShadowBuffer({ samplePercent = 10, capacity = 64 } = {}) {
  if (!Number.isInteger(samplePercent) || samplePercent < 1 || samplePercent > 100 ||
      !Number.isInteger(capacity) || capacity < 1 || capacity > 64) throw new Error('invalid bounded settings');
  let queue = [];
  let counters = { seen: 0, sampled_out: 0, queue_dropped: 0, observer_error: 0, emitted: 0 };
  let overflow = false;
  function pathClass(path) {
    if (path === '/.env') return 'dotenv';
    if (path === '/config.bak') return 'config_backup';
    if (path === '/wp-admin/' || path.startsWith('/wp-admin/')) return 'wordpress';
    if (path === '/') return 'root';
    if (path === '/api') return 'api';
    if (path === '/soap') return 'soap';
    if (path === '/xml') return 'xml';
    if (path === '/sapi') return 'sapi';
    return 'other';
  }
  function mediaClass(value) {
    if (!value) return 'none';
    if (value.length > 128) return 'other';
    const media = value.split(';', 1)[0].trim().toLowerCase();
    if (media === 'application/xml' || media === 'text/xml') return 'xml';
    if (media === 'application/sapi+jwe') return 'sapi';
    if (media === 'application/json') return 'json';
    return 'other';
  }
  function sizeBucket(value) {
    if (value === null || !/^[0-9]{1,12}$/.test(value)) return 'unknown';
    const size = Number(value);
    if (size === 0) return 'zero';
    if (size <= 1024) return 'small';
    if (size <= 65536) return 'medium';
    return 'large';
  }
  function observe(request, response) {
    // Saturation is made visible; after saturation no completeness claim is possible.
    if (counters.seen >= 1000000) { overflow = true; return; }
    counters.seen++;
    try {
      const random = new Uint32Array(1); crypto.getRandomValues(random);
      if (random[0] / 4294967296 * 100 >= samplePercent) { counters.sampled_out++; return; }
      if (queue.length >= capacity) { counters.queue_dropped++; return; }
      const method = request.method === 'GET' || request.method === 'POST' ? request.method : 'OTHER';
      const event = {
        request_id: crypto.randomUUID(), observed_utc: new Date().toISOString(),
        path_class: request.url.length <= 2048 ? pathClass(new URL(request.url).pathname) : 'other', method,
        media_class: mediaClass(request.headers.get('content-type')),
        size_bucket: sizeBucket(request.headers.get('content-length')),
        original_status: response.status,
      };
      queue.push(event); counters.emitted++;
    } catch (_) { counters.observer_error++; }
  }
  return {
    observe,
    // An external, separately authorized consumer can drain; this example sends nothing.
    drain() {
      const snapshot = { batch_id: crypto.randomUUID(), sample_percent: samplePercent, overflow, counters, events: queue };
      queue = []; counters = { seen: 0, sampled_out: 0, queue_dropped: 0, observer_error: 0, emitted: 0 }; overflow = false;
      return snapshot;
    },
  };
}

export async function handleWithShadow(request, handler, buffer) {
  const response = await handler(request); // Original response is authoritative.
  try { buffer.observe(request, response); } catch (_) { /* Shadow must not affect response. */ }
  return response;
}
