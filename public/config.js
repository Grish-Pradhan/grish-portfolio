(() => {
  const projectUrl = "https://kqdrhwdidjrdbmwteuom.supabase.co";
  const publishableKey = "sb_publishable_Nmyw4pDaqtHNTfuYCmoA3A_aFgn8tZ3";
  const functionUrl = new URL("/functions/v1/portfolio-api", projectUrl);
  const isLocal = ["localhost", "127.0.0.1"].includes(window.location.hostname) || window.location.port === "5173";

  window.portfolioApi = (path, options = {}) => {
    if (isLocal) return fetch(path, options);

    const url = new URL(functionUrl);
    url.searchParams.set("path", path);
    const headers = new Headers(options.headers || {});
    headers.set("apikey", publishableKey);
    return fetch(url, { ...options, headers });
  };
})();