const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("subnetNative", {
  batchPing: async (payload) => {
    return await ipcRenderer.invoke("batch-ping", payload || {});
  },
  tcpPortScan: async (payload) => {
    return await ipcRenderer.invoke("tcp-port-scan", payload || {});
  },
  getLocalNetworkInfo: async () => {
    return await ipcRenderer.invoke("local-network-info");
  },
  showNativeMessageBox: async (payload) => {
    return await ipcRenderer.invoke("show-native-message-box", payload || {});
  },
  showTaskNotification: async (payload) => {
    return await ipcRenderer.invoke("show-task-notification", payload || {});
  },
  traceRoute: async (payload) => {
    return await ipcRenderer.invoke("trace-route", payload || {});
  },
  traceRouteAbort: async () => {
    return await ipcRenderer.invoke("trace-route-abort");
  },
  traceRoutePauseToggle: async () => {
    return await ipcRenderer.invoke("trace-route-pause-toggle");
  },
  onNavigateTab: (callback) => {
    const fn = (_e, tabId) => {
      try {
        callback(tabId);
      } catch {
        // ignore
      }
    };
    ipcRenderer.on("app-navigate-tab", fn);
    return () => ipcRenderer.removeListener("app-navigate-tab", fn);
  },
});

