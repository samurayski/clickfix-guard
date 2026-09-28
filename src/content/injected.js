// Runs in the page's MAIN world (declared via manifest "world": "MAIN") at
// document_start, before any page script, so it can hook the clipboard APIs
// before a lure page has a chance to hide or replace them.
//
// Threat model for this file: a lure page that knows about the extension
// shares this JS world and can replace any builtin it likes after we start —
// RegExp.prototype.test, Array.prototype.push, window.postMessage,
// MessageEvent.prototype.data, Promise.prototype.then... So:
//
//  - Every builtin used after start-up is captured here, before page scripts
//    run, and invoked through the captured Reflect.apply.
//  - Hooks sit on the prototypes (Clipboard.prototype.writeText, ...), not on
//    the navigator.clipboard instance; otherwise
//    `Clipboard.prototype.writeText.call(navigator.clipboard, x)` skips them.
//  - Arguments are converted ONCE and that same value is what reaches the
//    real API, so an object whose toString() answers differently on its
//    second call can't show us one string and write another.
//  - Copy-event hijacking ("pastejacking" — a copy/cut handler that swaps the
//    data via event.clipboardData.setData / .items.add) is hooked too.
//  - Same-origin iframes are separate JS realms with their own, unhooked
//    Clipboard.prototype; they're patched the moment the page reaches into
//    them via contentWindow/contentDocument.
//  - This file does NO analysis. It ships the raw text over a private
//    MessagePort to content.js (isolated world), where the page can't touch
//    the regexes. The port is handed over in a handshake the page can't
//    intercept or block (see onOffer).
//
// Residual: a page that reaches a fresh same-origin iframe through
// window.frames[i] / window[i] (not contentWindow) before Chrome injects this
// script into that frame can still grab an unhooked Clipboard.prototype.
(function () {
  const win = window;
  const apply = Reflect.apply;
  const getOwnDesc = Object.getOwnPropertyDescriptor;
  const defineProp = Object.defineProperty;
  const S = String;
  const ITER = Symbol.iterator;
  const arrayFrom = Array.from;
  const ArrayCtor = Array;
  const toLower = String.prototype.toLowerCase;
  const strSlice = String.prototype.slice;
  const wsHas = WeakSet.prototype.has;
  const wsAdd = WeakSet.prototype.add;
  const promiseThen = Promise.prototype.then;
  const portPost = MessagePort.prototype.postMessage;
  const addListener = EventTarget.prototype.addEventListener;
  const winPostMessage = window.postMessage;
  const stopImmediate = Event.prototype.stopImmediatePropagation;

  function getterOf(proto, name) {
    const d = proto && getOwnDesc(proto, name);
    return d && d.get;
  }
  const msgData = getterOf(MessageEvent.prototype, "data");
  const msgSource = getterOf(MessageEvent.prototype, "source");
  const msgPorts = getterOf(MessageEvent.prototype, "ports");

  function noop() {}

  // ---- private channel to content.js -------------------------------------
  //
  // content.js offers a MessagePort by posting it to this window. Neither
  // script can assume the other is already listening — Chrome may run the
  // isolated-world and MAIN-world document_start scripts in separate turns of
  // the event loop — so the handshake works in either order:
  //  - content.js posts an offer when it starts, and again whenever it hears
  //    this script's "ready" (it posts at most a few);
  //  - this script listens for offers from the start and posts "ready".
  // Whichever side comes second completes it. Both listeners are capturing
  // listeners on window registered at document_start, i.e. before any page
  // script, so they run first and stop propagation: the page can't swallow
  // the handshake. A page that forges an offer only gets a copy of reports
  // about its own clipboard writes; one that forges "ready" only makes
  // content.js open another port. Neither silences anything.

  const ports = [];
  const MAX_PORTS = 4;
  const queue = [];
  const MAX_QUEUE = 200;

  function send(method, text) {
    const msg = { method: method, text: text };
    if (ports.length === 0) {
      if (queue.length < MAX_QUEUE) queue[queue.length] = msg;
      return;
    }
    for (let i = 0; i < ports.length; i++) apply(portPost, ports[i], [msg]);
  }

  function onOffer(ev) {
    let data, source, offered;
    try {
      data = apply(msgData, ev, []);
      source = apply(msgSource, ev, []);
      offered = apply(msgPorts, ev, []);
    } catch (e) {
      return;
    }
    if (source !== win || !data || typeof data !== "object") return;
    const flag = getOwnDesc(data, "__clickfixGuardHandshake");
    if (!flag || flag.value !== true || !offered || offered.length !== 1) return;
    apply(stopImmediate, ev, []);
    if (ports.length >= MAX_PORTS) return;
    const port = offered[0];
    ports[ports.length] = port;
    if (ports.length === 1) {
      for (let i = 0; i < queue.length; i++) apply(portPost, port, [queue[i]]);
      queue.length = 0;
    }
  }
  apply(addListener, win, ["message", onOffer, true]);
  apply(winPostMessage, win, [{ __clickfixGuardMainReady: true }, "*"]);

  // ---- hooking helpers -----------------------------------------------------

  function wrapMethod(proto, name, makeWrapper) {
    const d = proto && getOwnDesc(proto, name);
    if (!d || typeof d.value !== "function") return;
    defineProp(proto, name, {
      value: makeWrapper(d.value),
      writable: d.writable,
      enumerable: d.enumerable,
      configurable: d.configurable,
    });
  }

  function wrapGetter(proto, name, makeGetter) {
    const d = proto && getOwnDesc(proto, name);
    if (!d || typeof d.get !== "function") return;
    defineProp(proto, name, {
      get: makeGetter(d.get),
      set: d.set,
      enumerable: d.enumerable,
      configurable: d.configurable,
    });
  }

  function has(set, v) {
    try {
      return apply(wsHas, set, [v]);
    } catch (e) {
      return false;
    }
  }

  function isTextType(t) {
    const l = apply(toLower, t, []);
    return l === "text/plain" || l === "text";
  }

  // Materializes a page-supplied sequence once and gives the copy its own
  // iterator, so the browser's WebIDL conversion walks exactly the items we
  // inspected even if the page has replaced Array.prototype[Symbol.iterator].
  function snapshot(seq) {
    const arr = apply(arrayFrom, ArrayCtor, [seq]);
    defineProp(arr, ITER, {
      value: function () {
        let i = 0;
        return {
          next: function () {
            return i < arr.length ? { value: arr[i++], done: false } : { value: undefined, done: true };
          },
        };
      },
    });
    return arr;
  }

  // DataTransfer objects / item lists handed out by a ClipboardEvent, shared
  // across realms (an event from one realm can be read with another realm's
  // getter).
  const clipboardTransfers = new WeakSet();
  const clipboardItemLists = new WeakSet();
  const patchedRealms = new WeakSet();

  // ---- the hooks, applied to a realm ---------------------------------------

  function patchRealm(w) {
    let realmKey;
    try {
      realmKey = w.EventTarget; // throws for a cross-origin frame — that frame runs its own copy of this script
    } catch (e) {
      return;
    }
    if (typeof realmKey !== "function" || has(patchedRealms, realmKey)) return;
    apply(wsAdd, patchedRealms, [realmKey]);

    const docActiveElement = getterOf(w.Document && w.Document.prototype, "activeElement");
    const docGetSelection = w.Document && w.Document.prototype.getSelection;
    const docDefaultView = getterOf(w.Document && w.Document.prototype, "defaultView");
    const selToString = w.Selection && w.Selection.prototype.toString;
    const itemTypes = getterOf(w.ClipboardItem && w.ClipboardItem.prototype, "types");
    const itemGetType = w.ClipboardItem && w.ClipboardItem.prototype.getType;
    const blobText = w.Blob && w.Blob.prototype.text;
    // Index loops, not for...of: patchRealm also runs after page scripts
    // (for iframes), when Array.prototype[Symbol.iterator] may be poisoned.
    const CONTROLS = [];
    const controlCtors = [w.HTMLTextAreaElement, w.HTMLInputElement];
    for (let k = 0; k < controlCtors.length; k++) {
      const C = controlCtors[k];
      if (!C) continue;
      CONTROLS[CONTROLS.length] = {
        value: getterOf(C.prototype, "value"),
        start: getterOf(C.prototype, "selectionStart"),
        end: getterOf(C.prototype, "selectionEnd"),
      };
    }

    // Legacy copy trick: a hidden <textarea>/<input> holds the payload and is
    // focused + selected right before execCommand('copy'). Selection#toString
    // doesn't see text inside form controls, so read the control directly
    // (the value getter's brand check tells us which kind it is).
    function controlText(el) {
      for (let i = 0; i < CONTROLS.length; i++) {
        const c = CONTROLS[i];
        let value;
        try {
          value = apply(c.value, el, []);
        } catch (e) {
          continue;
        }
        try {
          const start = apply(c.start, el, []);
          const end = apply(c.end, el, []);
          if (typeof start === "number" && typeof end === "number" && end > start) {
            return apply(strSlice, value, [start, end]);
          }
        } catch (e) {}
        return value;
      }
      return null;
    }

    function selectionText(doc) {
      try {
        const active = apply(docActiveElement, doc, []);
        if (active) {
          const t = controlText(active);
          if (t !== null) return t;
        }
      } catch (e) {}
      try {
        return S(apply(selToString, apply(docGetSelection, doc, []), []));
      } catch (e) {
        return "";
      }
    }

    function inspectItems(items, method) {
      for (let i = 0; i < items.length; i++) {
        try {
          const item = items[i];
          const types = apply(itemTypes, item, []);
          let hasText = false;
          for (let j = 0; j < types.length; j++) if (types[j] === "text/plain") hasText = true;
          if (!hasText) continue;
          const p = apply(itemGetType, item, ["text/plain"]);
          apply(promiseThen, p, [
            function (blob) {
              apply(promiseThen, apply(blobText, blob, []), [
                function (t) {
                  send(method, t);
                },
                noop,
              ]);
            },
            noop,
          ]);
        } catch (e) {}
      }
    }

    try {
      wrapMethod(w.Clipboard && w.Clipboard.prototype, "writeText", function (orig) {
        return {
          writeText(...args) {
            if (args.length === 0) return apply(orig, this, args);
            args[0] = S(args[0]);
            send("clipboard.writeText", args[0]);
            return apply(orig, this, args);
          },
        }.writeText;
      });
    } catch (e) {}

    try {
      wrapMethod(w.Clipboard && w.Clipboard.prototype, "write", function (orig) {
        return {
          write(...args) {
            if (args.length === 0 || args[0] === null || typeof args[0] !== "object") return apply(orig, this, args);
            args[0] = snapshot(args[0]);
            inspectItems(args[0], "clipboard.write");
            return apply(orig, this, args);
          },
        }.write;
      });
    } catch (e) {}

    try {
      wrapMethod(w.Document && w.Document.prototype, "execCommand", function (orig) {
        return {
          execCommand(...args) {
            if (args.length > 0) {
              args[0] = S(args[0]);
              const cmd = apply(toLower, args[0], []);
              if (cmd === "copy" || cmd === "cut") send("execCommand." + cmd, selectionText(this));
            }
            return apply(orig, this, args);
          },
        }.execCommand;
      });
    } catch (e) {}

    try {
      wrapGetter(w.ClipboardEvent && w.ClipboardEvent.prototype, "clipboardData", function (orig) {
        return getOwnDesc(
          {
            get clipboardData() {
              const dt = apply(orig, this, []);
              if (dt) apply(wsAdd, clipboardTransfers, [dt]);
              return dt;
            },
          },
          "clipboardData"
        ).get;
      });
    } catch (e) {}

    try {
      wrapGetter(w.DataTransfer && w.DataTransfer.prototype, "items", function (orig) {
        return getOwnDesc(
          {
            get items() {
              const list = apply(orig, this, []);
              if (list && has(clipboardTransfers, this)) apply(wsAdd, clipboardItemLists, [list]);
              return list;
            },
          },
          "items"
        ).get;
      });
    } catch (e) {}

    try {
      wrapMethod(w.DataTransfer && w.DataTransfer.prototype, "setData", function (orig) {
        return {
          setData(...args) {
            if (args.length >= 2 && has(clipboardTransfers, this)) {
              args[0] = S(args[0]);
              args[1] = S(args[1]);
              if (isTextType(args[0])) send("clipboardData.setData", args[1]);
            }
            return apply(orig, this, args);
          },
        }.setData;
      });
    } catch (e) {}

    try {
      wrapMethod(w.DataTransferItemList && w.DataTransferItemList.prototype, "add", function (orig) {
        return {
          add(...args) {
            // add(data, type) is the string overload; add(file) has one argument.
            if (args.length >= 2 && has(clipboardItemLists, this)) {
              args[0] = S(args[0]);
              args[1] = S(args[1]);
              if (isTextType(args[1])) send("clipboardData.items.add", args[0]);
            }
            return apply(orig, this, args);
          },
        }.add;
      });
    } catch (e) {}

    const frameCtors = [w.HTMLIFrameElement, w.HTMLFrameElement, w.HTMLObjectElement];
    for (let k = 0; k < frameCtors.length; k++) {
      const Frame = frameCtors[k];
      if (!Frame) continue;
      try {
        wrapGetter(Frame.prototype, "contentWindow", function (orig) {
          return getOwnDesc(
            {
              get contentWindow() {
                const cw = apply(orig, this, []);
                if (cw) patchRealm(cw);
                return cw;
              },
            },
            "contentWindow"
          ).get;
        });
      } catch (e) {}
      try {
        wrapGetter(Frame.prototype, "contentDocument", function (orig) {
          return getOwnDesc(
            {
              get contentDocument() {
                const cd = apply(orig, this, []);
                if (cd && docDefaultView) {
                  try {
                    const v = apply(docDefaultView, cd, []);
                    if (v) patchRealm(v);
                  } catch (e) {}
                }
                return cd;
              },
            },
            "contentDocument"
          ).get;
        });
      } catch (e) {}
    }
  }

  try {
    patchRealm(win);
  } catch (e) {
    // Fail open (no detection from this layer) rather than break the page.
  }
})();
