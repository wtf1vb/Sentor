// Sentor compatibility shim: emulates the Wails v2 JS runtime on top of Tauri 2 IPC.
// Used by the COPIED frontend; the original net-gui frontend is left untouched.
// Method/argument tables mirror the Go App API map (see port notes).
(function () {
  'use strict';
  var T = window.__TAURI__;
  if (!T || !T.core || typeof T.core.invoke !== 'function') {
    console.warn('[sentor-shim] window.__TAURI__ not available — shim disabled (static preview mode)');
    return;
  }
  var invoke = T.core.invoke;

  // Go PascalCase -> Tauri snake_case command name
  function cmdName(name) {
    return name
      .replace(/([A-Z]+)([A-Z][a-z0-9])/g, '$1_$2')
      .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
      .toLowerCase();
  }

  // map: Go method -> ordered list of argument keys (camelCase; Tauri matches them to Rust params)
  var API = {
    GetStatus: [], GetTraffic: [], CheckUpdates: [], OpenToolsFolder: [],
    // VerifyInstall долгое время отсутствовал здесь: команда была зарегистрирована
    // в Rust, но window.go.main.App.VerifyInstall === undefined — кнопки «🩺 Проверить»
    // падали с TypeError
    VerifyInstall: ['which'],
    InstallZapret: [], UpdateZapret: [], InstallTgProxy: [], UpdateTgProxy: [],
    StartStrategy: ['name'], StopZapret: [], StartTgProxy: [], StopTgProxy: [], AddToTelegram: ['direct'],
    GetLogs: [], SaveLogsFile: [], ClearLogs: [],
    CheckerStart: ['autoSelect'], CheckerStop: [], CheckerState: [], CheckerSelect: ['name'], OpenChecker: [],
    ToolSources: [],
    PwdttConnect: ['id'], PwdttDisconnect: [], PwdttImportLink: ['link'], PwdttLog: [],
    PwdttRemoveServer: ['id'], PwdttSaveServer: ['s'], PwdttSendCaptcha: ['token'],
    PwdttServers: [], PwdttStatus: [],
    CqsttConnect: ['id'], CqsttDisconnect: [], CqsttImportLink: ['link'], CqsttLog: [],
    CqsttRemoveServer: ['id'], CqsttSaveServer: ['s'], CqsttSendCaptcha: ['token'],
    CqsttServers: [], CqsttStatus: [],
    VpnAddLink: ['link', 'subId'], VpnAddSubscription: ['name', 'link'], VpnAddWarpConfig: ['name', 'conf'],
    VpnCheckIp: [], VpnConnect: ['id', 'force'], VpnDisconnect: [], VpnExportWarpConf: ['id'],
    VpnFlags: [], VpnGeo: [], VpnGenerateWarpConf: ['endpoint'], VpnGetSettings: [], VpnImportWarpConf: [],
    VpnInstallCore: ['core'], VpnList: [], VpnListSubscriptions: [], VpnPing: ['id'], VpnPingThrough: ['id'],
    VpnRefreshAllSubscriptions: [], VpnRefreshSubscription: ['id'], VpnRemove: ['id'],
    VpnRemoveSubscription: ['id'], VpnServersGeo: [], VpnServices: [], VpnSetSettings: ['s'],
    VpnStartServiceChecks: [], VpnStatus: [], VpnTraffic: []
  };

  var App = {};
  Object.keys(API).forEach(function (name) {
    var keys = API[name];
    App[name] = function () {
      var args = Array.prototype.slice.call(arguments);
      var payload = {};
      for (var i = 0; i < keys.length; i++) payload[keys[i]] = args[i];
      return invoke(cmdName(name), payload);
    };
  });
  window.go = { main: { App: App } };

  // Wails fires multi-arg events as positional callback args; the Rust port emits a JSON array.
  function fire(cb, payload) {
    if (Array.isArray(payload) && payload.length > 1) cb.apply(null, payload);
    else cb(payload);
  }

  var listeners = {};
  window.runtime = {
    EventsOn: function (event, cb) {
      var arr = (listeners[event] = listeners[event] || []);
      var unlisten = null;
      var unsubscribed = false;
      T.event.listen(event, function (e) { fire(cb, e.payload); }).then(function (u) {
        // отписка могла прийти раньше resolve listen: раньше слушатель
        // утекал навсегда (unlisten был ещё null)
        if (unsubscribed) { u(); return; }
        unlisten = u;
        arr.push(u);
      });
      return function () {
        unsubscribed = true;
        if (unlisten) {
          unlisten();
          var i = arr.indexOf(unlisten);
          if (i >= 0) arr.splice(i, 1);
        }
      };
    },
    EventsOff: function (event) {
      var arr = listeners[event];
      if (arr) {
        arr.forEach(function (u) { u(); });
        delete listeners[event];
      }
    },
    BrowserOpenURL: function (url) {
      return invoke('open_url', { url: url });
    }
  };

  console.log('[sentor-shim] ready: ' + Object.keys(API).length + ' methods bridged to Tauri IPC');
})();
