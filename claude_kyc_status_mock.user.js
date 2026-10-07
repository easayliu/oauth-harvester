// ==UserScript==
// @name         Claude KYC Status Mock (verified)
// @namespace    local.claude.kyc
// @version      1.0.0
// @description  mock /api/organizations/{org}/kyc_status → 成功(verified)
// @match        *://claude.ai/*
// @match        *://*.claude.ai/*
// @run-at       document-start
// @grant        none
// @sandbox      raw
// ==/UserScript==

(function () {
  "use strict";

  const TARGET_HOST = "claude.ai";
  const TARGET_PATH = /^\/api\/organizations\/[^/]+\/kyc_status\/?$/;

  // ⬇️ 成功返回体；字段名按真实接口调，不确定就多塞几个常见命名
  const MOCK_DATA = {
    status: "verified",
    kyc_status: "verified",
    kyc_required: false,
    verified: true,
    completed: true,
    has_completed_kyc: true,
  };

  const MOCK_BODY = JSON.stringify(MOCK_DATA);
  const MOCK_LENGTH = new TextEncoder().encode(MOCK_BODY).byteLength;

  function getTargetUrl(input, method) {
    try {
      let rawUrl;
      if (typeof input === "string" || input instanceof URL) {
        rawUrl = String(input);
      } else if (input && typeof input.url === "string") {
        rawUrl = input.url;
      } else {
        return null;
      }
      const url = new URL(rawUrl, location.href);
      if (String(method || "GET").toUpperCase() !== "GET") return null;
      if (!(url.hostname === TARGET_HOST ||
            url.hostname.endsWith("." + TARGET_HOST))) return null;
      if (!TARGET_PATH.test(url.pathname)) return null;
      return url;
    } catch (e) {
      console.error("[KYC Mock] URL 解析失败：", e);
      return null;
    }
  }

  function createMockResponse(originalResponse) {
    const headers = new Headers(originalResponse.headers);
    headers.delete("content-length");
    headers.delete("content-encoding");
    headers.delete("etag");
    headers.delete("content-md5");
    headers.set("content-type", "application/json; charset=utf-8");
    headers.set("content-length", String(MOCK_LENGTH));
    headers.set("cache-control", "no-store");
    return new Response(MOCK_BODY, {
      status: 200,
      statusText: "OK",
      headers,
    });
  }

  // ---- fetch 拦截 ----
  const _fetch = window.fetch;
  window.fetch = function (input, init) {
    const url = getTargetUrl(input, init && init.method);
    if (!url) return _fetch.apply(this, arguments);
    console.log("[KYC Mock] 拦截 fetch:", url.href);
    return _fetch.call(this, url.href, init).then(createMockResponse);
  };

  // ---- XHR 拦截 ----
  const _open = XMLHttpRequest.prototype.open;
  const _send = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url) {
    this._ky_method = method;
    this._ky_url = url;
    return _open.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function (body) {
    const target = getTargetUrl(this._ky_url, this._ky_method);
    if (!target) return _send.apply(this, arguments);
    console.log("[KYC Mock] 拦截 XHR:", target.href);
    Object.defineProperty(this, "readyState", { value: 4, writable: true, configurable: true });
    Object.defineProperty(this, "status",     { value: 200, writable: true, configurable: true });
    Object.defineProperty(this, "statusText", { value: "OK", writable: true, configurable: true });
    Object.defineProperty(this, "responseText", { value: MOCK_BODY, writable: true, configurable: true });
    Object.defineProperty(this, "response",     { value: MOCK_BODY, writable: true, configurable: true });
    const self = this;
    setTimeout(function () {
      self.dispatchEvent(new Event("readystatechange"));
      self.dispatchEvent(new Event("load"));
      self.dispatchEvent(new Event("loadend"));
    }, 0);
  };
})();
