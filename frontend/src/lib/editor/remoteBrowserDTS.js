// Type declarations the browser.js editor feeds Monaco for autocomplete on remote
// browser automation. It mirrors the API Phishing Club's remote browser exposes:
// newSession() returns a Session, with the victim connection available through
// request(). baitbox also injects page, rb and emitEvent, declared at the end.

export const remoteBrowserDTS = `
interface SessionOptions {
  /** DevTools WebSocket URL, connects to an existing Chrome instead of launching one */
  remote?: string;
  /** SOCKS5 or HTTP proxy, e.g. "socks5://127.0.0.1:1080" */
  proxy?: string;
  /** Run Chrome headless (default: from config) */
  headless?: boolean;
  /** Close the session after this many ms of no browser activity */
  idleTimeout?: number;
  /** Log every action to the test runner */
  debug?: boolean;
  /** Stream Chrome process stdout/stderr into the event log (noisy; for crash diagnostics only) */
  chromeDebug?: boolean;
  /** Max ms for read only CDP calls (getText, evaluate, ...); 0 = no limit */
  queryTimeout?: number;
  /** Override the User-Agent header sent by Chrome */
  userAgent?: string;
  /**
   * BCP 47 locale for Chrome's language setting, e.g. "en-US" or "en-GB".
   * Sets navigator.language, navigator.languages, and the Accept-Language header
   * at the process level, consistent across the main frame AND Web Workers.
   * Local mode only; ignored when connecting to a remote browser.
   */
  lang?: string;
  /**
   * Additional Chrome CLI flags passed at launch. Each entry must start with "--".
   * Local mode only. Example: ["--use-gl=egl"]
   */
  extraFlags?: string[];
}

interface CaptureOptions {
  /** Filter cookies to these domains, e.g. ["google.com"] */
  domains?: string[];
  /** Only keep cookies with these names */
  cookieNames?: string[];
  /** Include localStorage (default true unless domains is set) */
  localStorage?: boolean;
  /** Include sessionStorage (default true unless domains is set) */
  sessionStorage?: boolean;
}

interface CaptureResult {
  cookies?: Array<{ name: string; value: string; domain: string; path: string; [key: string]: any }>;
  localStorage?: Record<string, string>;
  sessionStorage?: Record<string, string>;
}

interface WaitOptions {
  /** Set to false to search only the main page document (skip iframes). Default: true. */
  frames?: boolean;
  /** CSS selector for a specific iframe element to scope the search to. */
  frame?: string;
}

interface RaceCondition {
  /** Element is visible (nonzero bounding box) */
  visible?: string;
  /** Element is visible and not disabled */
  ready?: string;
  /** Element exists in DOM */
  present?: string;
  /** Element is not disabled */
  enabled?: string;
  /** Element is not visible */
  notVisible?: string;
  /** Element is absent from DOM */
  notPresent?: string;
  /** Page URL contains this substring */
  urlContains?: string;
  /** Page URL matches this regex */
  urlMatch?: RegExp;
  /** Victim sends this event */
  event?: string;
  /** Fire after this many milliseconds regardless of other conditions. */
  after?: number;
}

/** Controls the loop started by run(). Passed to each action. */
interface RunLoop {
  /** Name of the state currently being handled */
  state: string;
  /** End the loop after the current action finishes. Works from any callback. */
  stop(): void;
}

interface RunOptions {
  /** Milliseconds to wait each cycle for the state to change (default 10000) */
  detectTimeout?: number;
  /** Overall budget in milliseconds for the whole loop (0 = no limit) */
  timeout?: number;
}

/** A state machine built by s.states(rules). Add before()/after() hooks, then run(). */
interface StateMachine {
  before(fn: (state: string) => void): StateMachine;
  after(fn: (state: string) => void): StateMachine;
  run(actions: { [state: string]: (loop: RunLoop) => any }, options?: RunOptions): string;
}

interface Session {
  // Navigation
  /** Navigate to a URL and wait for the page to load */
  navigate(url: string): void;
  navigateBack(): void;
  navigateForward(): void;
  reload(): void;
  stop(): void;
  location(): string;
  title(): string;
  waitURLContains(substring: string): string;
  waitURLMatch(pattern: RegExp): string;

  // Waiting
  waitVisible(...selectorsAndOpts: Array<string | WaitOptions>): string;
  waitReady(...selectorsAndOpts: Array<string | WaitOptions>): string;
  waitEnabled(...selectorsAndOpts: Array<string | WaitOptions>): string;
  waitSelected(...selectorsAndOpts: Array<string | WaitOptions>): string;
  waitNotVisible(...selectorsAndOpts: Array<string | WaitOptions>): string;
  waitNotPresent(...selectorsAndOpts: Array<string | WaitOptions>): string;

  // Mouse
  click(selector: string): void;
  doubleClick(selector: string): void;
  rightClick(selector: string): void;
  rightClickXY(x: number, y: number): void;
  selectText(selector: string): void;
  /** Move along a curved Bezier path with micro jitter before clicking. */
  clickXY(x: number, y: number): void;
  moveMouse(x: number, y: number, opts?: { duration?: number; jitter?: number }): void;
  scrollIntoView(selector: string): void;
  humanScroll(deltaY: number, options?: { duration?: number }): void;
  humanIdle(ms: number): void;

  // Keyboard
  sendKeys(selector: string, text: string): void;
  keyEvent(key: string): void;

  // Form
  clear(selector: string): void;
  focus(selector: string): void;
  blur(selector: string): void;
  submit(selector: string): void;
  setValue(selector: string, value: string): void;
  getValue(selector: string): string;

  // DOM reading
  getText(selector: string): string;
  getTextContent(selector: string): string;
  getInnerHTML(selector: string): string;
  getOuterHTML(selector: string): string;
  getAttribute(selector: string, attr: string): string | null;
  getAttributes(selector: string): Record<string, string>;
  setAttribute(selector: string, attr: string, value: string): void;
  removeAttribute(selector: string, attr: string): void;
  getJSAttribute(selector: string, prop: string): any;
  setJSAttribute(selector: string, prop: string, value: string): void;
  getNodeCount(selector: string): number;
  present(selector: string): boolean;
  visible(selector: string): boolean;
  query(name: string): string | null;

  // JavaScript evaluation
  evaluate(expression: string): any;

  // Screenshots (test/debug only)
  screenshot(name: string): void;
  screenshotElement(selector: string, name: string): void;
  domDump(name: string): void;

  // Viewport & emulation
  setViewport(width: number, height: number): void;
  setViewportMobile(width: number, height: number): void;
  resetViewport(): void;
  setUserAgent(ua: string): void;
  setAcceptLanguage(lang: string): void;

  // Header rewriting
  setRequestHeader(name: string, value: string, targets?: string | string[]): void;
  removeRequestHeader(name: string, targets?: string | string[]): void;
  setResponseHeader(name: string, value: string, targets?: string | string[]): void;
  removeResponseHeader(name: string, targets?: string | string[]): void;

  // Capture
  /** Capture cookies and storage; saves to campaign timeline automatically */
  capture(options?: CaptureOptions): CaptureResult;

  // Utility
  wait(ms: number): void;
  /** Make passkey logins fail fast so the page offers another sign in method. */
  failFido(): void;
  /** @deprecated use failFido() */
  disableFidoUI(): void;
  /** Register a JS snippet that runs before any page scripts on every navigation. */
  injectScript(js: string): void;
  /** Park the script and signal that the browser is ready for admin live takeover */
  keepAlive(): void;
  /** Run fn with a scoped timeout; returns true if fn completed before the deadline. */
  withTimeout(ms: number, fn: (s: Session) => void): boolean;
  close(): void;

  // State machine
  states(rules: { [state: string]: () => boolean }): StateMachine;
  waitForState(rules: { [state: string]: () => boolean }, timeoutMs?: number): string;

  // Event driven API
  on(event: string, handler: (data: any) => void): void;
  listen(): void;
  done(): void;

  // Race
  race(conditions: Record<string, RaceCondition>): { key: string; value: any };

  // Streaming
  stream(selector: string, name: string, options?: { maxFps?: number; quality?: number }): { stop(): void };

  // Frame sub sessions
  frame(selector: string): FrameSession | null;
}

interface FrameSession {
  navigate(url: string): void;
  navigateBack(): void;
  navigateForward(): void;
  reload(): void;
  stop(): void;
  location(): string;
  title(): string;
  waitURLContains(substring: string): string;
  waitURLMatch(pattern: RegExp): string;
  waitVisible(...selectorsAndOpts: Array<string | WaitOptions>): string;
  waitReady(...selectorsAndOpts: Array<string | WaitOptions>): string;
  waitEnabled(...selectorsAndOpts: Array<string | WaitOptions>): string;
  waitSelected(...selectorsAndOpts: Array<string | WaitOptions>): string;
  waitNotVisible(...selectorsAndOpts: Array<string | WaitOptions>): string;
  waitNotPresent(...selectorsAndOpts: Array<string | WaitOptions>): string;
  click(selector: string): void;
  doubleClick(selector: string): void;
  rightClick(selector: string): void;
  clickXY(x: number, y: number): void;
  moveMouse(x: number, y: number, opts?: { duration?: number; jitter?: number }): void;
  scrollIntoView(selector: string): void;
  humanScroll(deltaY: number, options?: { duration?: number }): void;
  sendKeys(selector: string, text: string): void;
  keyEvent(key: string): void;
  clear(selector: string): void;
  focus(selector: string): void;
  blur(selector: string): void;
  submit(selector: string): void;
  setValue(selector: string, value: string): void;
  getValue(selector: string): string;
  getText(selector: string): string;
  getAttribute(selector: string, attr: string): string | null;
  getNodeCount(selector: string): number;
  evaluate(expression: string): any;
  wait(ms: number): void;
  withTimeout(ms: number, fn: (s: FrameSession) => void): boolean;
  frame(selector: string): FrameSession | null;
}

/** Open a new browser session */
declare function newSession(options?: SessionOptions): Session;

interface RequestASN { number: number; name: string; }
interface RequestInfo {
  /** The victim's request IP (trusted proxy aware). */
  ip: string;
  /** ISO country code from the GeoIP database, e.g. "DE". Empty if unknown. */
  country: string;
  /** Autonomous systems the IP belongs to. Empty unless the ASN package is downloaded. */
  asns: RequestASN[];
  /** JA4 TLS fingerprint of the connection. Empty if not captured. */
  ja4: string;
  userAgent: string;
  acceptLanguage: string;
  headers: { [name: string]: string };
}
/** The victim connection that started this session. Available before newSession(). */
declare function request(): RequestInfo;
/** Run a saved Script by name, passing data as its input, and return the result object. */
declare function runScript(name: string, data?: object): any;
/** Send an event to the victim page (visible to the victim's JS) */
declare function emit(key: string, value?: any): void;
/** Log a message to the test runner */
declare function log(message: string, data?: any): void;
/** Record an info note to the campaign timeline */
declare function info(message: string): void;
/** Submit arbitrary captured data (e.g. credentials) to the campaign timeline */
declare function submitData(data: any): void;
/** Block until an incoming victim event with the given name arrives; returns its data */
declare function waitForEvent(event: string): any;
/** Block until any of the listed victim events arrive; returns { event, data } */
declare function waitForAny(events: string[]): { event: string; data: any };
declare function waitForAny(...events: string[]): { event: string; data: any };
/** Stop the script immediately with no error. */
declare function stop(): never;

interface RetryContext { attempt: number; max: number; isFirst: boolean; isLast: boolean; }
/** Calls fn up to max times. Return truthy from fn to stop; returns that value, or null. */
declare function retry(max: number, fn: (ctx: RetryContext) => any): any;
declare function retry(options: { max: number; wait?: number }, fn: (ctx: RetryContext) => any): any;

// baitbox injects these globals into browser.js so the authored script can drive the
// current session directly: page is the active Session, rb sends/receives victim events,
// emitEvent records a campaign event.
/** The active browser Session for this run. */
declare const page: Session;
declare const rb: {
  /** Send an event to the victim page. */
  emit(key: string, value?: any): void;
  /** Register a handler for a victim page event. */
  on(event: string, handler: (data: any) => void): void;
};
/** Record a campaign event for data this script authored. */
declare function emitEvent(name: string, data?: Record<string, any>): void;

// A compact slice of the ECMAScript builtins available in the goja runtime (ES2015+).
// No DOM and no Node.js, so dot completion stays focused on the script API.
interface String {
  readonly length: number;
  charAt(index: number): string;
  charCodeAt(index: number): number;
  indexOf(searchValue: string, fromIndex?: number): number;
  lastIndexOf(searchValue: string, fromIndex?: number): number;
  includes(searchValue: string, fromIndex?: number): boolean;
  startsWith(searchValue: string, fromIndex?: number): boolean;
  endsWith(searchValue: string, endPosition?: number): boolean;
  slice(start?: number, end?: number): string;
  substring(start: number, end?: number): string;
  toLowerCase(): string;
  toUpperCase(): string;
  trim(): string;
  padStart(targetLength: number, padString?: string): string;
  padEnd(targetLength: number, padString?: string): string;
  repeat(count: number): string;
  split(separator: string | RegExp, limit?: number): string[];
  replace(searchValue: string | RegExp, replaceValue: string): string;
  replaceAll(searchValue: string | RegExp, replaceValue: string): string;
  match(regexp: string | RegExp): string[] | null;
  concat(...strings: string[]): string;
  [index: number]: string;
}
interface Number { toFixed(digits?: number): string; toString(radix?: number): string; valueOf(): number; }
interface Boolean { valueOf(): boolean; toString(): string; }
interface Array<T> {
  readonly length: number;
  push(...items: T[]): number;
  pop(): T | undefined;
  shift(): T | undefined;
  unshift(...items: T[]): number;
  slice(start?: number, end?: number): T[];
  indexOf(searchElement: T, fromIndex?: number): number;
  includes(searchElement: T, fromIndex?: number): boolean;
  join(separator?: string): string;
  concat(...items: T[][]): T[];
  reverse(): T[];
  map<U>(fn: (value: T, index: number) => U): U[];
  filter(fn: (value: T, index: number) => boolean): T[];
  forEach(fn: (value: T, index: number) => void): void;
  find(fn: (value: T, index: number) => boolean): T | undefined;
  some(fn: (value: T, index: number) => boolean): boolean;
  every(fn: (value: T, index: number) => boolean): boolean;
  reduce<U>(fn: (acc: U, value: T, index: number) => U, initial: U): U;
  sort(compareFn?: (a: T, b: T) => number): T[];
  [index: number]: T;
}
declare var JSON: {
  parse(text: string): any;
  stringify(value: any, replacer?: any, space?: string | number): string;
};
declare var Math: {
  readonly PI: number;
  readonly E: number;
  abs(x: number): number;
  ceil(x: number): number;
  floor(x: number): number;
  max(...values: number[]): number;
  min(...values: number[]): number;
  random(): number;
  round(x: number): number;
  pow(x: number, y: number): number;
  sqrt(x: number): number;
  trunc(x: number): number;
  sign(x: number): number;
};
declare var Object: {
  keys(o: object): string[];
  values(o: object): any[];
  entries(o: object): [string, any][];
  assign<T>(target: T, ...sources: any[]): T;
  fromEntries(entries: Iterable<[string, any]>): object;
  freeze<T>(o: T): Readonly<T>;
};
`;
