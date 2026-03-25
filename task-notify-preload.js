const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("taskNotifyView", {
  onPayload: (fn) => {
    ipcRenderer.on("notify-payload", (_e, p) => fn(p));
  },
  activate: () => ipcRenderer.send("task-notify-activate"),
  dismiss: () => ipcRenderer.send("task-notify-dismiss"),
});
