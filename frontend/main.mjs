import { app, BrowserWindow } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';

// Convert the file URL to a file path
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let mainWindow;

function createWindow() {
  // Create the browser window
  mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      // preload: path.join(__dirname, 'preload.js'), // Correct preload script
      nodeIntegration: false, // Disable nodeIntegration for security
      contextIsolation: true, // Enable context isolation for security
    },
  });

  // Ignore certificate errors (for development only)
  mainWindow.webContents.session.setCertificateVerifyProc(
    (request, callback) => {
      callback(0); // Bypass certificate validation
    }
  );

  // Load the index.html file
  mainWindow.loadFile(path.join(__dirname, 'index.html')); // Correct path to index.html

  // Open the DevTools (optional)
  mainWindow.webContents.openDevTools();

  // Emitted when the window is closed
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Electron is ready to create the window
app.whenReady().then(() => {
  createWindow();

  // Handle macOS activate event
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// Quit when all windows are closed
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
