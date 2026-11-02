import { mount } from "svelte";
import { getCurrentWindow } from "@tauri-apps/api/window";
import "./app.css";
import App from "./App.svelte";
import CardView from "./lib/CardView.svelte";
import MiniView from "./lib/MiniView.svelte";

// The card (connections wanting an answer) and the mini viewer load the same
// page; the window's label says which view.
const label = getCurrentWindow().label;
if (label === "mini") document.documentElement.classList.add("mini");
if (label === "card") document.documentElement.classList.add("card-window");
const view = label === "card" ? CardView : label === "mini" ? MiniView : App;
const app = mount(view, { target: document.getElementById("app")! });

export default app;
