import React from "react";
import ReactDOM from "react-dom/client";
import "@fontsource/barlow/400.css";
import "@fontsource/barlow/500.css";
import "@fontsource/barlow/600.css";
import "@fontsource/barlow-condensed/500.css";
import "@fontsource/barlow-condensed/600.css";
import "@fontsource/barlow-condensed/700.css";
import "@fontsource/jetbrains-mono/400.css";
import "./index.css";
import App from "./App";
import { LiveProvider } from "./live";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <LiveProvider>
      <App />
    </LiveProvider>
  </React.StrictMode>,
);
