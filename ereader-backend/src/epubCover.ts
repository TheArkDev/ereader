import { unzipSync } from 'fflate';

const CONTENT_TYPES: Record<string, string> = {
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  png: 'image/png',
  gif: 'image/gif',
  webp: 'image/webp',
  svg: 'image/svg+xml',
};

function contentTypeFor(path: string): string {
  const ext = path.split('.').pop()?.toLowerCase() ?? '';
  return CONTENT_TYPES[ext] ?? 'image/jpeg';
}

/** Joins an OPF-relative href against the OPF file's own directory. */
function resolvePath(opfDir: string, href: string): string {
  const decoded = decodeURIComponent(href);
  if (!opfDir) return decoded;
  const combined = `${opfDir}/${decoded}`;
  // Collapse "./" and "../" segments — real-world EPUBs rarely nest deeper
  // than this, so a simple pass is enough.
  const parts: string[] = [];
  for (const segment of combined.split('/')) {
    if (segment === '.' || segment === '') continue;
    if (segment === '..') parts.pop();
    else parts.push(segment);
  }
  return parts.join('/');
}

/**
 * Extracts the embedded cover image from an EPUB's own metadata, matching
 * how EPUB3 (`properties="cover-image"`) and EPUB2 (`<meta name="cover">`)
 * both declare it. Returns null if the EPUB doesn't declare one, or if
 * anything about its structure doesn't match what we expect — callers
 * should treat a null return as "no cover available", not an error.
 */
export function extractEpubCover(bytes: Uint8Array): { bytes: Uint8Array; contentType: string } | null {
  try {
    const files = unzipSync(bytes);
    const decoder = new TextDecoder();

    // 1. container.xml points at the real .opf package file.
    const containerXml = files['META-INF/container.xml'];
    if (!containerXml) return null;
    const containerText = decoder.decode(containerXml);
    const rootfileMatch = containerText.match(/<rootfile[^>]*full-path="([^"]+)"/i);
    const opfPath = rootfileMatch?.[1];
    if (!opfPath || !files[opfPath]) return null;

    const opfText = decoder.decode(files[opfPath]);
    const opfDir = opfPath.includes('/') ? opfPath.slice(0, opfPath.lastIndexOf('/')) : '';

    // 2. Find every <item .../> in the manifest, capturing id/href/properties.
    const items: { id?: string; href?: string; properties?: string }[] = [];
    const itemRegex = /<item\b[^>]*\/?>/gi;
    for (const tag of opfText.match(itemRegex) ?? []) {
      const id = tag.match(/\bid="([^"]+)"/i)?.[1];
      const href = tag.match(/\bhref="([^"]+)"/i)?.[1];
      const properties = tag.match(/\bproperties="([^"]+)"/i)?.[1];
      items.push({ id, href, properties });
    }

    // 3a. EPUB3: an item explicitly marked as the cover image.
    let coverHref = items.find((i) => i.properties?.split(/\s+/).includes('cover-image'))?.href;

    // 3b. EPUB2 fallback: <meta name="cover" content="some-manifest-id"/>
    if (!coverHref) {
      const metaMatch = opfText.match(/<meta[^>]*name="cover"[^>]*content="([^"]+)"/i);
      const coverId = metaMatch?.[1];
      if (coverId) coverHref = items.find((i) => i.id === coverId)?.href;
    }

    // 3c. Last resort: an item whose id/href looks cover-ish and is an image.
    if (!coverHref) {
      coverHref = items.find(
        (i) => i.href && /\.(jpe?g|png|gif|webp)$/i.test(i.href) && /cover/i.test(i.id ?? i.href ?? '')
      )?.href;
    }

    if (!coverHref) return null;

    const fullPath = resolvePath(opfDir, coverHref);
    const imageBytes = files[fullPath];
    if (!imageBytes) return null;

    return { bytes: imageBytes, contentType: contentTypeFor(fullPath) };
  } catch {
    // Any parsing hiccup on a real-world malformed EPUB just means "no
    // auto-cover" — never let this break the upload itself.
    return null;
  }
}
