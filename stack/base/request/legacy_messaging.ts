// RUIN src/platform/ClientVersionAdvertisement.x: advertise the pre-premium
// messaging client per request. Keep the session's device family and OS intact.
const LEGACY_APP_VERSION = "15.16.1";
const LEGACY_BUILD_VERSION = "2025.926.1805";

export function legacyMessagingHeaders(
  headers: Record<string, string>,
  requestUrl: string,
): Record<string, string> {
  const url = new URL(requestUrl);
  if (
    url.protocol !== "https:" || url.username || url.password ||
    (url.port && url.port !== "443") ||
    ![".line.naver.jp", ".line.me", ".line-apps.com"].some((host) => url.hostname.endsWith(host))
  ) return {};

  const fields = new Map<string, [string, string]>();
  for (const [key, value] of Object.entries(headers)) {
    const name = key.toLowerCase();
    if (!["x-line-application", "x-line-application-version", "user-agent"].includes(name)) continue;
    if (fields.has(name) || /[\r\n]/.test(value)) return {};
    fields.set(name, [key, value]);
  }
  const application = fields.get("x-line-application");
  const parts = application?.[1].split("\t");
  if (
    !application || parts?.length !== 4 ||
    !["IOS", "IPAD", "IOSIPAD"].includes(parts[0]!) ||
    !/^\d+\.\d+\.\d+$/.test(parts[1]!) || !parts[2] ||
    !/^\d+\.\d+(?:\.\d+)?$/.test(parts[3]!)
  ) return {};

  // Vyline's current iOS version is independent of RUIN's pinned binary build.
  // Android/Desktop versions have no verified mapping and stay native.
  const applicationVersion = fields.get("x-line-application-version");
  if (applicationVersion && !/^\d+\.\d+\.\d+$/.test(applicationVersion[1])) return {};
  parts[1] = LEGACY_APP_VERSION;
  const overrides: Record<string, string> = { [application[0]]: parts.join("\t") };
  if (applicationVersion) overrides[applicationVersion[0]] = LEGACY_APP_VERSION;

  const userAgent = fields.get("user-agent");
  if (userAgent && /^(?:iphoneapp\.line|Line)\/\d+\.\d+\.\d+(?![\w.])/i.test(userAgent[1])) {
    overrides[userAgent[0]] = userAgent[1]
      .replace(/^(iphoneapp\.line|Line)\/\d+\.\d+\.\d+/i, `$1/${LEGACY_APP_VERSION}`)
      .replace(/(BuildVersion:\s*)\d+\.\d+\.\d+(?![\w.])/i, (_, prefix) => `${prefix}${LEGACY_BUILD_VERSION}`);
  }
  return overrides;
}
