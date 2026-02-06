export function isDevBypassEnabled() {
  return (
    String(import.meta.env.VITE_DEV_AUTH_BYPASS).toLowerCase() === "true" ||
    Boolean(import.meta.env.VITE_DEV_BEARER_TOKEN)
  );
}
